mod common;
use common::*;
use serde_json::{Value, json};
use wifi_cap2hashcat::{Config, convert};

fn metadata(records: usize, bytes: usize) -> Value {
    json!({"schema":"fz-wifi.capture","version":1,"source_format":"pcap-radiotap",
        "source_records":records,"source_bytes":bytes,"capture":{"epoch":0}})
}
fn summary(value: &Value, e: E, terminated: bool) -> Vec<u8> {
    let mut body = vec![0; 12];
    let mut text = b"FZWIFI_META_V1\n".to_vec();
    text.extend(serde_json::to_vec(value).unwrap());
    body.extend(option(1, &text, e));
    if terminated {
        body.extend([0; 4]);
    }
    block(5, &body, e)
}
fn without_end(bytes: &[u8], e: E) -> Vec<u8> {
    let kind = if e.0 {
        u32::from_be_bytes(bytes[..4].try_into().unwrap())
    } else {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    };
    block(kind, &bytes[8..bytes.len() - 8], e)
}
fn complete(e: E) -> (Vec<u8>, Value) {
    let mut bytes = section(e);
    bytes.extend(interface(127, 6, 0, None, e));
    let mut source_bytes = 24;
    for (time, frame) in exchange() {
        let packet = radio(&frame, 0, false);
        source_bytes += 16 + packet.len();
        bytes.extend(epb(0, u64::from(time), &packet, e));
    }
    (bytes, metadata(5, source_bytes))
}

#[test]
fn implicit_option_termination_works_in_both_byte_orders() {
    for e in [E(false), E(true)] {
        let shb = section(e);
        let mut body = shb[8..shb.len() - 4].to_vec();
        body.extend(option(1, b"section comment", e));
        let mut capture = block(0x0a0d0d0a, &body, e);
        capture.extend(without_end(&interface(127, 6, 0, None, e), e));
        let mut source_bytes = 24;
        for (time, frame) in exchange() {
            let packet = radio(&frame, 0, false);
            source_bytes += 16 + packet.len();
            let ep = epb(0, time.into(), &packet, e);
            let mut body = ep[8..ep.len() - 4].to_vec();
            body.extend(option(1, b"packet comment", e));
            capture.extend(block(6, &body, e));
        }
        capture.extend(summary(&metadata(5, source_bytes), e, false));
        let result = convert(&capture, &Config::default()).unwrap();
        assert_eq!(
            result.hashes,
            convert(&complete(e).0, &Config::default()).unwrap().hashes
        );
        assert_eq!(result.report.embedded_metadata.len(), 1);
    }
}

#[test]
fn simple_packet_source_bytes_are_accounted() {
    for e in [E(false), E(true)] {
        let mut capture = section(e);
        capture.extend(interface(127, 6, 0, None, e));
        let packet = radio(&beacon(SSID), 0, false);
        let mut body = e.u32(packet.len() as u32).to_vec();
        body.extend(&packet);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        capture.extend(block(3, &body, e));
        let base = capture.clone();
        capture.extend(summary(&metadata(1, 24 + 16 + packet.len()), e, true));
        assert!(convert(&capture, &Config::default()).is_ok());
        let mut invalid = base;
        invalid.extend(summary(&metadata(1, 24), e, true));
        assert!(convert(&invalid, &Config::default()).is_err());
    }
}

#[test]
fn independent_sections_allow_metadata_in_both_byte_orders() {
    let (mut first, value1) = complete(E(false));
    first.extend(summary(&value1, E(false), true));
    let one = convert(&first, &Config::default()).unwrap();
    let (mut second, value2) = complete(E(true));
    second.extend(summary(&value2, E(true), true));
    first.extend(second);
    let both = convert(&first, &Config::default()).unwrap();
    assert_eq!(both.hashes, one.hashes);
    assert_eq!(both.report.embedded_metadata.len(), 2);
    assert_eq!(both.report.embedded_metadata[0].section, 1);
    assert_eq!(both.report.embedded_metadata[1].section, 2);
}

#[test]
fn metadata_section_limit_and_exact_comment_limit() {
    let (mut part, value) = complete(E(false));
    part.extend(summary(&value, E(false), true));
    assert!(convert(&part.repeat(64), &Config::default()).is_ok());
    assert!(convert(&part.repeat(65), &Config::default()).is_err());
    for extra in [0, 1] {
        let (mut capture, mut value) = complete(E(false));
        value["capture"]["padding"] = json!("");
        let used = b"FZWIFI_META_V1\n".len() + serde_json::to_vec(&value).unwrap().len();
        value["capture"]["padding"] = json!("x".repeat(16384 - used + extra));
        capture.extend(summary(&value, E(false), true));
        assert_eq!(convert(&capture, &Config::default()).is_ok(), extra == 0);
    }
}

#[test]
fn malformed_block_and_option_lengths_never_panic() {
    let (mut original, value) = complete(E(false));
    original.extend(summary(&value, E(false), true));
    for end in 0..original.len() {
        let result = std::panic::catch_unwind(|| convert(&original[..end], &Config::default()));
        assert!(result.is_ok(), "panic at truncation {end}");
    }
    for offset in 0..original.len() {
        for bit in [1, 128, 255] {
            let mut data = original.clone();
            data[offset] ^= bit;
            assert!(
                std::panic::catch_unwind(|| convert(&data, &Config::default())).is_ok(),
                "panic at mutation {offset}/{bit}"
            );
        }
    }
    for e in [E(false), E(true)] {
        for options in [vec![0, 0, 1, 0], vec![1, 0, 255, 255], vec![0; 8]] {
            let shb = section(e);
            let mut body = shb[8..shb.len() - 4].to_vec();
            body.extend(options);
            assert!(convert(&block(0x0a0d0d0a, &body, e), &Config::default()).is_err());
        }
    }
}

#[test]
fn many_unknown_empty_options_are_streamed_without_entry_allocations() {
    let e = E(false);
    let shb = section(e);
    let mut body = shb[8..shb.len() - 4].to_vec();
    body.extend(option(77, &[], e).repeat(250_000));
    let valid = block(0x0a0d0d0a, &body, e);
    assert!(convert(&valid, &Config::default()).is_ok());
    body.extend([1, 0, 255, 255]);
    assert!(convert(&block(0x0a0d0d0a, &body, e), &Config::default()).is_err());
}
