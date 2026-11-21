//! Checked decoding of RSN-PSK captures; the selected M2 profile is authoritative.
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Cipher {
    #[serde(rename = "TKIP")]
    Tkip,
    #[serde(rename = "CCMP-128")]
    Ccmp128,
    #[serde(rename = "GCMP-128")]
    Gcmp128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SecurityProfile {
    pub protocol: &'static str,
    pub group_cipher: Cipher,
    pub pairwise_cipher: Cipher,
    pub akm: &'static str,
    pub descriptor_type: u8,
    pub descriptor_version: u8,
    /// Client RSN capabilities, not proof that PMF was negotiated with the AP.
    pub client_pmf: &'static str,
    pub group_management_cipher: Option<[u8; 4]>,
}

fn cipher(suite: &[u8], reason: &'static str) -> ParseResult<Cipher> {
    need(suite[..3] == [0, 15, 172], reason)?;
    match suite[3] {
        2 => Ok(Cipher::Tkip),
        4 => Ok(Cipher::Ccmp128),
        8 => Ok(Cipher::Gcmp128),
        _ => Err(reason),
    }
}
use crate::capture::Packet;

pub type Mac = [u8; 6];
type ParseResult<T> = Result<T, &'static str>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Group {
    pub stream: u64,
    pub ap: Mac,
    pub station: Mac,
}

#[derive(Clone, Debug)]
pub(crate) struct KeyFrame {
    pub group: Group,
    pub index: u64,
    pub time_ns: i128,
    pub message: u8,
    pub replay: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],
    pub eapol: Vec<u8>,
    pub descriptor_type: u8,
    pub descriptor_version: u8,
    pub profile: Option<SecurityProfile>,
}

pub(crate) enum Event {
    Ssid { ap: Mac, name: Vec<u8> },
    Key(KeyFrame),
}

fn need(condition: bool, reason: &'static str) -> ParseResult<()> {
    if condition { Ok(()) } else { Err(reason) }
}
fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn mac(b: &[u8]) -> Mac {
    b[..6].try_into().expect("checked MAC range")
}
fn unicast(a: Mac) -> bool {
    a[0] & 1 == 0 && a != [0; 6]
}

fn elements(mut b: &[u8]) -> ParseResult<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        need(b.len() >= 2, "malformed_information_elements")?;
        let size = usize::from(b[1]);
        need(size <= b.len() - 2, "malformed_information_elements")?;
        out.push((b[0], &b[2..2 + size]));
        b = &b[2 + size..];
    }
    Ok(out)
}

// Check the client's selected RSN AKM, rather than the AP's advertised list.
fn wpa2_psk(data: &[u8], version: u8) -> ParseResult<SecurityProfile> {
    let ies = elements(data)?;
    let rsns: Vec<_> = ies.iter().filter(|(id, _)| *id == 48).collect();
    need(rsns.len() == 1, "missing_or_multiple_client_rsn")?;
    let b = rsns[0].1;
    need(b.len() >= 8 && le16(b) == 1, "malformed_rsn")?;
    let group = cipher(&b[2..6], "unsupported_group_cipher")?;
    let pairs = usize::from(le16(&b[6..]));
    need(pairs > 0 && pairs <= (b.len() - 8) / 4, "malformed_rsn")?;
    need(pairs == 1, "unsupported_pairwise_cipher")?;
    let pairwise = cipher(&b[8..12], "unsupported_pairwise_cipher")?;
    let mut pos = 8 + pairs * 4;
    need(b.len() - pos >= 2, "malformed_rsn")?;
    let akms = usize::from(le16(&b[pos..]));
    pos += 2;
    need(akms > 0 && akms <= (b.len() - pos) / 4, "malformed_rsn")?;
    need(
        akms == 1 && b[pos..pos + 4] == [0, 0x0f, 0xac, 2],
        "unsupported_akm",
    )?;
    pos += akms * 4;
    need(
        version == if pairwise == Cipher::Tkip { 1 } else { 2 },
        "cipher_descriptor_mismatch",
    )?;
    need(
        matches!(
            (pairwise, group),
            (Cipher::Tkip, Cipher::Tkip)
                | (Cipher::Ccmp128, Cipher::Tkip | Cipher::Ccmp128)
                | (
                    Cipher::Gcmp128,
                    Cipher::Tkip | Cipher::Ccmp128 | Cipher::Gcmp128
                )
        ),
        "unsupported_cipher_combination",
    )?;
    let mut profile = SecurityProfile {
        protocol: "RSN",
        group_cipher: group,
        pairwise_cipher: pairwise,
        akm: "PSK",
        descriptor_type: 2,
        descriptor_version: version,
        client_pmf: "disabled",
        group_management_cipher: None,
    };
    if pos == b.len() {
        return Ok(profile);
    }
    need(b.len() - pos >= 2, "malformed_rsn")?;
    let caps = le16(&b[pos..]);
    need(caps & 0xc0 != 0x40, "malformed_rsn")?;
    profile.client_pmf = if caps & 0x40 != 0 {
        "required"
    } else if caps & 0x80 != 0 {
        "capable"
    } else {
        "disabled"
    };
    pos += 2;
    if pos == b.len() {
        return Ok(profile);
    }
    need(b.len() - pos >= 2, "malformed_rsn")?;
    let pmkids = usize::from(le16(&b[pos..]));
    pos += 2;
    need(pmkids <= (b.len() - pos) / 16, "malformed_rsn")?;
    pos += pmkids * 16;
    need(pos == b.len() || b.len() - pos == 4, "malformed_rsn")?;
    if pos != b.len() {
        profile.group_management_cipher = Some(b[pos..].try_into().expect("checked suite"));
    }
    Ok(profile)
}

fn radiotap(b: &[u8]) -> ParseResult<(&[u8], Option<u8>)> {
    need(b.len() >= 8 && b[0] == 0, "malformed_radiotap")?;
    let len = usize::from(le16(&b[2..]));
    need(len >= 8 && len <= b.len(), "malformed_radiotap")?;
    let first = u32::from_le_bytes(b[4..8].try_into().expect("checked bitmap"));
    let mut present = first;
    let mut pos = 8;
    let mut words = 1;
    while present & 0x8000_0000 != 0 {
        need(words < 16 && pos + 4 <= len, "malformed_radiotap")?;
        present = u32::from_le_bytes(b[pos..pos + 4].try_into().expect("checked bitmap"));
        pos += 4;
        words += 1;
    }
    if first & 1 != 0 {
        pos = (pos + 7) & !7;
        pos += 8;
        need(pos <= len, "malformed_radiotap")?;
    }
    let flags = if first & 2 != 0 {
        need(pos < len, "malformed_radiotap")?;
        Some(b[pos])
    } else {
        None
    };
    Ok((&b[len..], flags))
}

pub(crate) fn parse(packet: &Packet<'_>) -> ParseResult<Option<Event>> {
    need(!packet.truncated, "truncated_or_bad_packet")?;
    let (mut b, flags) = match packet.linktype {
        105 => (packet.data, None),
        127 => radiotap(packet.data)?,
        _ => return Err("unsupported_linktype"),
    };
    let rt_fcs = flags.map(|f| if f & 0x10 != 0 { 4 } else { 0 });
    if let (Some(a), Some(b)) = (rt_fcs, packet.fcs_bytes) {
        need(a == b, "conflicting_fcs_metadata")?;
    }
    let fcs = rt_fcs.or(packet.fcs_bytes).unwrap_or(0);
    let datapad = flags.is_some_and(|f| f & 0x20 != 0);
    need(flags.is_none_or(|f| f & 0x40 == 0), "bad_fcs")?;
    need(b.len() >= 2, "short_80211_header")?;
    let fc = le16(b);
    need(fc & 3 == 0, "unsupported_80211_version")?;
    let kind = (fc >> 2) & 3;
    if kind != 0 && kind != 2 {
        return Ok(None);
    }
    need(b.len() >= 24 + fcs, "short_80211_header")?;
    need(fc & 0x4000 == 0, "protected_frame")?;
    need(
        fc & 0x0400 == 0 && le16(&b[22..]) & 0xf == 0,
        "fragmented_frame",
    )?;
    let subtype = (fc >> 4) & 0xf;
    let direction = (fc >> 8) & 3;
    let qos = kind == 2 && subtype & 8 != 0;
    need(direction != 3, "unsupported_wds")?;
    let mut header_len = 24;
    if qos {
        header_len += 2;
        need(b.len() >= header_len + fcs, "short_80211_header")?;
        need(b[24] & 0x80 == 0, "unsupported_amsdu")?;
        if fc & 0x8000 != 0 {
            header_len += 4;
        }
    }
    need(b.len() >= header_len + fcs, "short_80211_header")?;
    let payload = if datapad {
        (header_len + 3) & !3
    } else {
        header_len
    };
    need(b.len() >= payload + fcs, "short_80211_header")?;
    if fcs == 4 {
        let end = b.len() - 4;
        let expected = u32::from_le_bytes(b[end..].try_into().expect("checked FCS"));
        let mut crc = crc32fast::Hasher::new();
        crc.update(&b[..header_len]);
        crc.update(&b[payload..end]);
        need(crc.finalize() == expected, "bad_fcs")?;
        b = &b[..end];
    }
    let a1 = mac(&b[4..]);
    let a2 = mac(&b[10..]);
    let a3 = mac(&b[16..]);
    if kind == 0 {
        need(direction == 0, "invalid_management_direction")?;
        let offset = match subtype {
            8 | 5 => {
                need(a2 == a3, "invalid_management_addresses")?;
                36
            }
            0 => {
                need(a1 == a3, "invalid_management_addresses")?;
                28
            }
            2 => {
                need(a1 == a3, "invalid_management_addresses")?;
                34
            }
            _ => return Ok(None),
        };
        need(unicast(a3) && b.len() >= offset, "malformed_management")?;
        let ies = elements(&b[offset..])?;
        let names: Vec<_> = ies.iter().filter(|(id, _)| *id == 0).collect();
        need(names.len() <= 1, "multiple_ssid_elements")?;
        if let Some((_, name)) = names.first() {
            need(name.len() <= 32, "invalid_ssid_length")?;
            if !name.is_empty() && name.iter().any(|v| *v != 0) {
                return Ok(Some(Event::Ssid {
                    ap: a3,
                    name: name.to_vec(),
                }));
            }
        }
        return Ok(None);
    }
    if subtype & 4 != 0 {
        return Ok(None);
    } // Null-data variants.
    need(
        direction == 1 || direction == 2,
        "unsupported_data_direction",
    )?;
    if b.len() < payload + 8 || b[payload..payload + 8] != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e] {
        return Ok(None);
    }
    let (ap, station) = if direction == 1 { (a1, a2) } else { (a2, a1) };
    need(
        unicast(ap) && unicast(station) && ap != station,
        "invalid_eapol_addresses",
    )?;
    let e = &b[payload + 8..];
    need(e.len() >= 4, "short_eapol")?;
    if e[1] != 3 {
        return Ok(None);
    }
    need((1..=3).contains(&e[0]), "unsupported_eapol_version")?;
    let body_len = usize::from(be16(&e[2..]));
    need(
        body_len >= 95 && body_len + 4 <= e.len(),
        "invalid_eapol_length",
    )?;
    let e = &e[..body_len + 4];
    need(e[4] == 2, "unsupported_key_descriptor")?;
    need(
        usize::from(be16(&e[97..])) == body_len - 95,
        "invalid_key_data_length",
    )?;
    let info = be16(&e[5..]);
    let descriptor_version = (info & 7) as u8;
    need(
        matches!(descriptor_version, 1 | 2),
        "unsupported_descriptor_version",
    )?;
    // Some captures use zero (unspecified); a nonzero length must fit the profile.
    let key_length = be16(&e[7..]);
    need(
        key_length == 0 || key_length == if descriptor_version == 1 { 32 } else { 16 },
        "cipher_key_length_mismatch",
    )?;
    need(info & 8 != 0, "group_key_exchange")?;
    need(info & 0xec30 == 0, "unsupported_key_flags")?;
    let ack = info & 0x80 != 0;
    let mic_present = info & 0x100 != 0;
    let secure = info & 0x200 != 0;
    let message = match (ack, mic_present, secure) {
        (true, false, false) => 1,
        (false, true, false) => 2,
        (true, true, true) => 3,
        (false, true, true) => 4,
        _ => return Err("unsupported_key_message"),
    };
    need(
        (message == 1 || message == 3) == (direction == 2),
        "invalid_eapol_direction",
    )?;
    need(message != 2 || info & 0x1040 == 0, "unsupported_key_flags")?;
    let nonce: [u8; 32] = e[17..49].try_into().expect("checked nonce");
    let mic: [u8; 16] = e[81..97].try_into().expect("checked MIC");
    need(message == 4 || nonce != [0; 32], "zero_nonce")?;
    need(!mic_present || mic != [0; 16], "zero_mic")?;
    let profile = if message == 2 {
        need(e.len() <= 256, "eapol_too_large_for_hashcat")?;
        Some(wpa2_psk(&e[99..], descriptor_version)?)
    } else {
        None
    };
    let time_ns = packet.time_ns.ok_or("missing_timestamp")?;
    Ok(Some(Event::Key(KeyFrame {
        group: Group {
            stream: packet.stream,
            ap,
            station,
        },
        index: packet.index,
        time_ns,
        message,
        descriptor_type: e[4],
        descriptor_version,
        profile,
        replay: u64::from_be_bytes(e[9..17].try_into().expect("checked replay")),
        nonce,
        mic,
        eapol: if message == 2 { e.to_vec() } else { Vec::new() },
    })))
}
