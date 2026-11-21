mod common;
use common::*;
use serde_json::{Value, json};
use wifi_cap2hashcat::{Config, convert};

fn input() -> (Vec<u8>, Value) {
    let mut result = section(E(false));
    result.extend(interface(127, 6, 0, None, E(false)));
    let mut bytes = 24;
    for (t, f) in exchange() {
        let packet = radio(&f, 0, false);
        bytes += 16 + packet.len();
        result.extend(epb(0, u64::from(t), &packet, E(false)));
    }
    (
        result,
        json!({"schema":"fz-wifi.capture", "version":1,
        "source_format":"pcap-radiotap", "source_records":5, "source_bytes":bytes,
        "capture":{"epoch":0,"mic_verified":true,"ssid":"untrusted","attempts":[]}}),
    )
}
fn summary(value: &Value) -> Vec<u8> {
    let mut body = vec![0; 12];
    let mut comment = b"FZWIFI_META_V1\n".to_vec();
    comment.extend(serde_json::to_vec(value).unwrap());
    body.extend(option(1, &comment, E(false)));
    body.extend([0; 4]);
    block(5, &body, E(false))
}
#[test]
fn metadata_is_provenance_and_hashes_are_unchanged() {
    let (mut capture, value) = input();
    let plain = convert(&capture, &Config::default()).unwrap();
    capture.extend(summary(&value));
    let result = convert(&capture, &Config::default()).unwrap();
    assert_eq!(result.hashes, plain.hashes);
    assert!(!result.hashes.is_empty());
    assert_eq!(result.report.validation, "structural_only");
    assert_eq!(result.report.embedded_metadata[0].data, value);
    assert_eq!(result.report.exports[0].ssid_hex, hex::encode(SSID));
}
#[test]
fn invalid_metadata_counts_versions_types_and_limits_fail() {
    for (key, replacement) in [
        ("version", json!(2)),
        ("schema", json!("unknown")),
        ("source_records", json!(1)),
        ("source_bytes", json!(0)),
        ("capture", json!([])),
        ("capture", json!({"huge":"x".repeat(16384)})),
    ] {
        let (mut capture, mut value) = input();
        value[key] = replacement;
        capture.extend(summary(&value));
        assert!(convert(&capture, &Config::default()).is_err(), "{key}");
    }
}
#[test]
fn duplicate_truncated_or_followed_by_packets_is_not_a_completed_capture() {
    let (base, value) = input();
    let tail = summary(&value);
    let mut duplicate = base.clone();
    duplicate.extend(&tail);
    duplicate.extend(&tail);
    assert!(convert(&duplicate, &Config::default()).is_err());
    let mut after = base.clone();
    after.extend(&tail);
    after.extend(epb(0, 6000, &radio(&frame(1), 0, false), E(false)));
    assert!(convert(&after, &Config::default()).is_err());
    for n in 1..tail.len() {
        let mut truncated = base.clone();
        truncated.extend(&tail[..n]);
        assert!(convert(&truncated, &Config::default()).is_err());
    }
}
#[test]
fn metadata_does_not_supply_a_missing_ssid() {
    let mut capture = section(E(false));
    capture.extend(interface(127, 6, 0, None, E(false)));
    let mut bytes = 24;
    for m in 1..=2 {
        let packet = radio(&frame(m), 0, false);
        bytes += 16 + packet.len();
        capture.extend(epb(0, u64::from(m) * 1000, &packet, E(false)));
    }
    capture.extend(summary(&json!({"schema":"fz-wifi.capture", "version":1,
        "source_format":"pcap-radiotap", "source_records":2, "source_bytes":bytes,
        "capture":{"ssid":"test-lab", "mic_verified":true}})));
    let result = convert(&capture, &Config::default()).unwrap();
    assert!(result.hashes.is_empty());
    assert_eq!(result.report.skipped_m2["missing_ssid"], 1);
}
