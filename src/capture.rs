//! Container decoding. Packet bytes borrow the bounded input buffer.
use anyhow::{Context, Result, bail, ensure};
use pcap_parser::{parse_pcap_frame, parse_pcap_frame_be, parse_pcap_header};

#[derive(Debug, serde::Serialize)]
pub struct EmbeddedMetadata {
    pub section: u64,
    pub data: serde_json::Value,
}

pub(crate) struct Packet<'a> {
    pub index: u64,
    pub stream: u64,
    pub time_ns: Option<i128>,
    pub linktype: u32,
    pub fcs_bytes: Option<usize>,
    pub truncated: bool,
    pub data: &'a [u8],
}

#[derive(Clone, Copy)]
struct Endian(bool);
impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.0 {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a: [u8; 4] = b[..4].try_into().expect("checked container range");
        if self.0 {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
    fn i64(self, b: &[u8]) -> i64 {
        let a: [u8; 8] = b[..8].try_into().expect("checked container range");
        if self.0 {
            i64::from_be_bytes(a)
        } else {
            i64::from_le_bytes(a)
        }
    }
}
#[derive(Clone, Copy)]
struct Interface {
    linktype: u32,
    snaplen: u32,
    ticks_per_sec: u64,
    offset: i64,
    fcs: Option<usize>,
}

pub(crate) fn decode<'a>(
    input: &'a [u8],
    mut visit: impl FnMut(Packet<'a>) -> Result<()>,
    metadata: &mut Vec<EmbeddedMetadata>,
) -> Result<&'static str> {
    if input.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        decode_ng(input, &mut visit, metadata)?;
        Ok("pcapng")
    } else {
        decode_pcap(input, &mut visit)?;
        Ok("pcap")
    }
}

fn decode_pcap<'a>(
    input: &'a [u8],
    visit: &mut impl FnMut(Packet<'a>) -> Result<()>,
) -> Result<()> {
    let (mut rest, header) = parse_pcap_header(input)
        .map_err(|_| anyhow::anyhow!("Invalid or incomplete PCAP header"))?;
    ensure!(
        header.version_major == 2 && header.version_minor == 4,
        "Only PCAP 2.4 is supported"
    );
    ensure!(!header.is_modified_format(), "Modified PCAP is unsupported");
    ensure!(header.snaplen > 0, "PCAP snaplen is zero");
    let network = header.network.0 as u32;
    ensure!(
        network <= u16::MAX.into(),
        "PCAP linktype extension/FCS metadata is unsupported"
    );
    let scale = if header.is_nanosecond_precision() {
        1
    } else {
        1000
    };
    let max_fraction = 1_000_000_000 / scale;
    let mut index = 0;
    while !rest.is_empty() {
        index += 1;
        let parsed = if header.is_bigendian() {
            parse_pcap_frame_be(rest)
        } else {
            parse_pcap_frame(rest)
        };
        let (next, frame) =
            parsed.map_err(|_| anyhow::anyhow!("Invalid or incomplete PCAP record {index}"))?;
        ensure!(
            frame.caplen <= frame.origlen && frame.caplen <= header.snaplen,
            "Invalid lengths in PCAP record {index}"
        );
        ensure!(
            frame.ts_usec < max_fraction,
            "Invalid timestamp in PCAP record {index}"
        );
        visit(Packet {
            index,
            stream: 0,
            time_ns: Some(
                i128::from(frame.ts_sec) * 1_000_000_000
                    + i128::from(frame.ts_usec) * i128::from(scale),
            ),
            linktype: network,
            fcs_bytes: None,
            truncated: frame.caplen != frame.origlen,
            data: frame.data,
        })?;
        rest = next;
    }
    Ok(())
}

// Iterate over bounded input slices instead of allocating one entry per option.
// A file full of empty unknown options must not amplify memory use.
fn options<'a>(
    mut data: &'a [u8],
    endian: Endian,
) -> impl Iterator<Item = Result<(u16, &'a [u8])>> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let next = (|| -> Result<Option<(u16, &'a [u8])>> {
            ensure!(data.len() >= 4, "Truncated PCAPNG option");
            let code = endian.u16(data);
            let size = usize::from(endian.u16(&data[2..]));
            data = &data[4..];
            if code == 0 {
                ensure!(
                    size == 0 && data.is_empty(),
                    "Invalid PCAPNG end-of-options"
                );
                return Ok(None);
            }
            let padded = (size + 3) & !3;
            ensure!(padded <= data.len(), "Truncated PCAPNG option value");
            let value = &data[..size];
            data = &data[padded..];
            Ok(Some((code, value)))
        })();
        match next {
            Ok(Some(value)) => Some(Ok(value)),
            Ok(None) => None,
            Err(error) => {
                data = &[];
                Some(Err(error))
            }
        }
    })
}

fn decode_ng<'a>(
    input: &'a [u8],
    visit: &mut impl FnMut(Packet<'a>) -> Result<()>,
    metadata: &mut Vec<EmbeddedMetadata>,
) -> Result<()> {
    let mut rest = input;
    let mut endian = Endian(false);
    let mut section: u64 = 0;
    let mut section_end: Option<usize> = None;
    let mut section_records = 0u64;
    let mut source_bytes = 24u64;
    let mut have_metadata = false;
    let mut interfaces = Vec::<Interface>::new();
    let mut index = 0;
    while !rest.is_empty() {
        let pos = input.len() - rest.len();
        ensure!(rest.len() >= 12, "Truncated PCAPNG block at byte {pos}");
        let shb = rest[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if let Some(end) = section_end {
            ensure!(
                pos <= end && (shb == (pos == end)),
                "PCAPNG section length mismatch at byte {pos}"
            );
        }
        if shb {
            endian = match &rest[8..12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian(false),
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian(true),
                _ => bail!("Invalid PCAPNG byte-order magic"),
            };
        }
        let kind = endian.u32(rest);
        let size = endian.u32(&rest[4..]) as usize;
        ensure!(
            size >= 12 && size.is_multiple_of(4) && size <= rest.len(),
            "Invalid PCAPNG block length at byte {pos}"
        );
        if !shb {
            if let Some(end) = section_end {
                ensure!(pos + size <= end, "PCAPNG block exceeds section length");
            }
        }
        let block = &rest[..size];
        ensure!(
            endian.u32(&block[size - 4..]) as usize == size,
            "PCAPNG block length trailer mismatch at byte {pos}"
        );
        let body = &block[8..size - 4];
        match kind {
            0x0a0d0d0a => {
                ensure!(body.len() >= 16, "Short PCAPNG section header");
                ensure!(
                    endian.u16(&body[4..]) == 1 && endian.u16(&body[6..]) == 0,
                    "Only PCAPNG 1.0 is supported"
                );
                let declared = endian.i64(&body[8..]);
                ensure!(declared >= -1, "Invalid PCAPNG section length");
                section_end = if declared < 0 {
                    None
                } else {
                    let length = usize::try_from(declared).context("PCAPNG section too large")?;
                    Some(
                        (pos + size)
                            .checked_add(length)
                            .context("PCAPNG section length overflow")?,
                    )
                };
                for option in options(&body[16..], endian) {
                    option?;
                }
                section += 1;
                interfaces.clear();
                section_records = 0;
                source_bytes = 24;
                have_metadata = false;
            }
            1 => {
                ensure!(
                    section > 0 && body.len() >= 8,
                    "Invalid PCAPNG interface block"
                );
                ensure!(
                    interfaces.len() < 4096,
                    "PCAPNG interface limit exceeded (4096)"
                );
                ensure!(
                    endian.u16(&body[2..]) == 0,
                    "Nonzero PCAPNG interface reserved field"
                );
                let mut interface = Interface {
                    linktype: u32::from(endian.u16(body)),
                    snaplen: endian.u32(&body[4..]),
                    ticks_per_sec: 1_000_000,
                    offset: 0,
                    fcs: None,
                };
                let mut seen = [false; 3];
                for option in options(&body[8..], endian) {
                    let (code, value) = option?;
                    match code {
                        9 => {
                            ensure!(
                                !seen[0] && value.len() == 1,
                                "Invalid/duplicate PCAPNG timestamp resolution"
                            );
                            seen[0] = true;
                            let (base, power) = if value[0] & 0x80 == 0 {
                                (10u64, value[0])
                            } else {
                                (2u64, value[0] & 0x7f)
                            };
                            interface.ticks_per_sec = base
                                .checked_pow(power.into())
                                .context("Unsupported PCAPNG timestamp resolution")?;
                        }
                        14 => {
                            ensure!(
                                !seen[1] && value.len() == 8,
                                "Invalid/duplicate PCAPNG timestamp offset"
                            );
                            seen[1] = true;
                            interface.offset = endian.i64(value);
                        }
                        13 => {
                            ensure!(
                                !seen[2] && value.len() == 1,
                                "Invalid/duplicate PCAPNG FCS option"
                            );
                            seen[2] = true;
                            ensure!(
                                value[0] == 0 || value[0] == 32,
                                "Only zero or 32-bit PCAPNG FCS is supported"
                            );
                            interface.fcs = Some(usize::from(value[0] / 8));
                        }
                        _ => {}
                    }
                }
                interfaces.push(interface);
            }
            5 => {
                ensure!(body.len() >= 12, "Short PCAPNG interface statistics");
                let id = endian.u32(body) as usize;
                ensure!(
                    id < interfaces.len(),
                    "Statistics references unknown interface"
                );
                for option in options(&body[12..], endian) {
                    let (code, value) = option?;
                    if code != 1 || !value.starts_with(b"FZWIFI_META_V1\n") {
                        continue;
                    }
                    ensure!(
                        !have_metadata && metadata.len() < 64,
                        "Duplicate/excessive embedded metadata"
                    );
                    ensure!(value.len() <= 16384, "Embedded metadata exceeds 16 KiB");
                    ensure!(
                        id == 0 && interfaces.len() == 1 && interfaces[0].linktype == 127,
                        "System metadata requires one Radiotap interface"
                    );
                    let data: serde_json::Value =
                        serde_json::from_slice(&value[b"FZWIFI_META_V1\n".len()..])
                            .context("Invalid embedded metadata JSON")?;
                    ensure!(
                        data["schema"] == "fz-wifi.capture"
                            && data["version"] == 1
                            && data["source_format"] == "pcap-radiotap"
                            && data["capture"].is_object(),
                        "Unsupported embedded metadata schema"
                    );
                    ensure!(
                        data["source_records"].as_u64() == Some(section_records)
                            && data["source_bytes"].as_u64() == Some(source_bytes),
                        "Embedded metadata packet/byte count mismatch"
                    );
                    metadata.push(EmbeddedMetadata { section, data });
                    have_metadata = true;
                }
            }
            6 => {
                ensure!(!have_metadata, "Packets follow final capture metadata");
                ensure!(body.len() >= 20, "Short PCAPNG enhanced packet");
                let id = endian.u32(body) as usize;
                let interface = interfaces
                    .get(id)
                    .context("PCAPNG packet references unknown interface")?;
                let caplen = endian.u32(&body[12..]) as usize;
                let origlen = endian.u32(&body[16..]) as usize;
                let padded = caplen
                    .checked_add(3)
                    .context("PCAPNG packet size overflow")?
                    & !3;
                ensure!(
                    padded <= body.len() - 20 && caplen <= origlen,
                    "Invalid PCAPNG packet lengths"
                );
                ensure!(
                    interface.snaplen == 0 || caplen <= interface.snaplen as usize,
                    "PCAPNG caplen exceeds snaplen"
                );
                let mut fcs = interface.fcs;
                let mut packet_bad = false;
                let mut seen_flags = false;
                for option in options(&body[20 + padded..], endian) {
                    let (code, value) = option?;
                    if code == 2 {
                        ensure!(
                            !seen_flags && value.len() == 4,
                            "Invalid/duplicate PCAPNG packet flags"
                        );
                        seen_flags = true;
                        let flags = endian.u32(value);
                        let length = ((flags >> 5) & 0x0f) as usize;
                        if length != 0 {
                            ensure!(length == 4, "Unsupported PCAPNG packet FCS length");
                            fcs = Some(length);
                        }
                        packet_bad = flags & 0xff00_0000 != 0;
                    }
                }
                section_records += 1;
                source_bytes += 16 + caplen as u64;
                let ticks =
                    (u64::from(endian.u32(&body[4..])) << 32) | u64::from(endian.u32(&body[8..]));
                index += 1;
                visit(Packet {
                    index,
                    stream: (section << 32) | id as u64,
                    time_ns: Some(
                        i128::from(ticks) * 1_000_000_000 / i128::from(interface.ticks_per_sec)
                            + i128::from(interface.offset) * 1_000_000_000,
                    ),
                    linktype: interface.linktype,
                    fcs_bytes: fcs,
                    truncated: caplen != origlen || packet_bad,
                    data: &body[20..20 + caplen],
                })?;
            }
            3 => {
                ensure!(!have_metadata, "Packets follow final capture metadata");
                section_records += 1;
                ensure!(body.len() >= 4, "Short PCAPNG simple packet");
                let interface = interfaces
                    .first()
                    .context("PCAPNG simple packet has no interface")?;
                let origlen = endian.u32(body) as usize;
                let caplen = if interface.snaplen == 0 {
                    origlen
                } else {
                    origlen.min(interface.snaplen as usize)
                };
                ensure!(
                    (caplen + 3) & !3 == body.len() - 4,
                    "Invalid PCAPNG simple packet length"
                );
                source_bytes += 16 + caplen as u64;
                index += 1;
                visit(Packet {
                    index,
                    stream: section << 32,
                    time_ns: None,
                    linktype: interface.linktype,
                    fcs_bytes: interface.fcs,
                    truncated: caplen != origlen,
                    data: &body[4..4 + caplen],
                })?;
            }
            2 => bail!(
                "Obsolete PCAPNG Packet Blocks are unsupported; resave as Enhanced Packet Blocks"
            ),
            _ => {}
        }
        rest = &rest[size..];
    }
    ensure!(section > 0, "Missing PCAPNG section");
    if let Some(end) = section_end {
        ensure!(end == input.len(), "PCAPNG section length exceeds input");
    }
    Ok(())
}
