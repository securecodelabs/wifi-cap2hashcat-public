mod common;
use common::*;
use wifi_cap2hashcat::{Config, convert};

fn run(bytes: &[u8]) -> wifi_cap2hashcat::Conversion {
    convert(bytes, &Config::default()).unwrap()
}
fn raw(frames: &[(u32, Vec<u8>)]) -> wifi_cap2hashcat::Conversion {
    run(&pcap(frames, 105, false, false))
}

#[test]
fn complete_exchange_exports_m2_m3_and_zeroes_only_mic() {
    let r = run(&capture());
    assert_eq!(r.hashes.len(), 1);
    assert_eq!(r.report.key_messages, [1, 1, 1, 1]);
    assert_eq!(r.report.validation, "structural_only");
    assert_eq!(r.report.exports[0].m2_packet, 3);
    assert_eq!(r.report.exports[0].peer_packet, 4);
    let fields: Vec<_> = r.hashes[0].split('*').collect();
    assert_eq!(fields.len(), 9);
    assert_eq!(fields[2], "55".repeat(16));
    assert_eq!(fields[3], hex::encode(AP));
    assert_eq!(fields[4], hex::encode(STA));
    assert_eq!(fields[5], hex::encode(SSID));
    assert_eq!(fields[6], "11".repeat(32));
    let mut expected = key(2);
    expected[81..97].fill(0);
    assert_eq!(hex::decode(fields[7]).unwrap(), expected);
    assert_eq!(fields[8], "02");
}
#[test]
fn m1_m2_is_exported_as_challenge() {
    let r = raw(&exchange()[..3]);
    assert_eq!(r.hashes.len(), 1);
    assert!(r.hashes[0].ends_with("*00"));
}
#[test]
fn m2_m3_without_m1_or_m4_is_sufficient() {
    let frames = exchange();
    let r = raw(&[frames[0].clone(), frames[2].clone(), frames[3].clone()]);
    assert_eq!(r.hashes.len(), 1);
    assert!(r.hashes[0].ends_with("*02"));
}
#[test]
fn all_classic_endianness_and_timestamp_precisions_agree() {
    let expected = run(&capture()).hashes;
    for be in [false, true] {
        for nano in [false, true] {
            let frames: Vec<_> = exchange()
                .into_iter()
                .map(|(t, b)| (if nano { t * 1000 } else { t }, b))
                .collect();
            assert_eq!(run(&pcap(&frames, 105, be, nano)).hashes, expected);
        }
    }
}
#[test]
fn ng_endianness_decimal_and_binary_resolutions() {
    let expected = run(&capture()).hashes;
    for e in [E(false), E(true)] {
        for resolution in [6, 9, 0x8a] {
            let b = ng(&exchange(), e, resolution, -123456);
            assert_eq!(run(&b).hashes, expected);
        }
    }
}
#[test]
fn ng_timestamp_resolution_affects_pair_window() {
    let frames = vec![(0, beacon(SSID)), (1, frame(1)), (2, frame(2))];
    let cfg = Config {
        timeout_ms: 500,
        ..Config::default()
    };
    assert!(
        convert(&ng(&frames, E(false), 0, 0), &cfg)
            .unwrap()
            .hashes
            .is_empty()
    );
    assert_eq!(
        convert(&ng(&frames, E(false), 6, 0), &cfg)
            .unwrap()
            .hashes
            .len(),
        1
    );
}
#[test]
fn ng_interfaces_and_sections_cannot_be_mixed() {
    let e = E(false);
    let mut b = section(e);
    b.extend(interface(105, 6, 0, None, e));
    b.extend(interface(105, 6, 0, None, e));
    b.extend(epb(0, 0, &beacon(SSID), e));
    b.extend(epb(1, 0, &beacon(SSID), e));
    b.extend(epb(0, 1000, &frame(1), e));
    b.extend(epb(1, 2000, &frame(2), e));
    assert!(run(&b).hashes.is_empty());
    let mut a = ng(&[(0, beacon(SSID)), (1000, frame(1))], e, 6, 0);
    a.extend(ng(&[(0, beacon(SSID)), (2000, frame(2))], E(true), 6, 0));
    assert!(run(&a).hashes.is_empty());
}
#[test]
fn ng_mixed_endian_sections_deduplicate_same_hash() {
    let mut b = ng(&exchange(), E(false), 6, 0);
    b.extend(ng(&exchange(), E(true), 6, 0));
    let r = run(&b);
    assert_eq!(r.hashes.len(), 1);
    assert_eq!(r.report.duplicate_exports, 1);
}
#[test]
fn radiotap_with_and_without_fcs() {
    for fcs in [false, true] {
        let frames: Vec<_> = exchange()
            .into_iter()
            .map(|(t, b)| (t, radio(&b, if fcs { 0x10 } else { 0 }, fcs)))
            .collect();
        assert_eq!(
            run(&pcap(&frames, 127, false, false)).hashes,
            run(&capture()).hashes
        );
    }
}
#[test]
fn radiotap_qos_ht_and_data_padding() {
    for ht in [false, true] {
        let mut frames = vec![(0, radio(&beacon(SSID), 0x20, false))];
        for m in 1..=3 {
            let b = data_frame(&key(m), m != 2, true, ht, true, STA);
            frames.push((u32::from(m) * 1000, radio(&b, 0x20, false)));
        }
        assert_eq!(run(&pcap(&frames, 127, false, false)).hashes.len(), 1);
    }
}
#[test]
fn bad_fcs_is_never_used() {
    let frames: Vec<_> = exchange()
        .into_iter()
        .map(|(t, b)| {
            let mut r = radio(&b, 0x10, true);
            *r.last_mut().unwrap() ^= 1;
            (t, r)
        })
        .collect();
    let r = run(&pcap(&frames, 127, false, false));
    assert!(r.hashes.is_empty());
    assert_eq!(r.report.skipped_packets["bad_fcs"], 5);
}
#[test]
fn raw_ng_explicit_fcs_is_validated() {
    let e = E(true);
    let mut b = section(e);
    b.extend(interface(105, 6, 0, Some(32), e));
    for (t, mut f) in exchange() {
        f.extend(crc32fast::hash(&f).to_le_bytes());
        b.extend(epb(0, u64::from(t), &f, e));
    }
    assert_eq!(run(&b).hashes, run(&capture()).hashes);
}
#[test]
fn retransmissions_are_deduplicated() {
    let mut frames = exchange();
    frames.extend([(2500, frame(2)), (3500, frame(3))]);
    let r = raw(&frames);
    assert_eq!(r.hashes.len(), 1);
    assert_eq!(r.report.duplicate_exports, 1);
}
#[test]
fn capture_record_order_does_not_change_matching() {
    let mut frames = exchange();
    frames.reverse();
    assert_eq!(raw(&frames).hashes, run(&capture()).hashes);
}
#[test]
fn different_clients_cannot_be_paired() {
    let m2 = data_frame(&key(2), false, false, false, false, [2, 0, 0, 0, 0, 3]);
    let r = raw(&[
        (0, beacon(SSID)),
        (1000, frame(1)),
        (2000, m2),
        (3000, frame(3)),
    ]);
    assert!(r.hashes.is_empty());
    assert_eq!(r.report.skipped_m2["no_matching_m1_or_m3"], 1);
}
#[test]
fn replay_mismatch_and_overflow_do_not_pair() {
    for replay in [0u64, 20, u64::MAX] {
        let mut m2 = key(2);
        m2[9..17].copy_from_slice(&replay.to_be_bytes());
        let r = raw(&[
            (0, beacon(SSID)),
            (1000, frame(1)),
            (2000, data_frame(&m2, false, false, false, false, STA)),
            (3000, frame(3)),
        ]);
        assert!(r.hashes.is_empty());
    }
}
#[test]
fn stale_or_reversed_timestamps_do_not_pair() {
    for frames in [
        vec![(0, beacon(SSID)), (1000, frame(2)), (2000, frame(1))],
        vec![(0, beacon(SSID)), (1000, frame(3)), (2000, frame(2))],
    ] {
        assert!(raw(&frames).hashes.is_empty());
    }
    let cfg = Config {
        timeout_ms: 1,
        ..Config::default()
    };
    let frames = [(0, beacon(SSID)), (1000, frame(1)), (3001, frame(2))];
    assert!(
        convert(&pcap(&frames, 105, false, false), &cfg)
            .unwrap()
            .hashes
            .is_empty()
    );
}
#[test]
fn conflicting_m1_m3_nonces_are_rejected() {
    let mut m3 = key(3);
    m3[17] ^= 1;
    let r = raw(&[
        (0, beacon(SSID)),
        (1000, frame(1)),
        (2000, frame(2)),
        (3000, data_frame(&m3, true, false, false, false, STA)),
    ]);
    assert!(r.hashes.is_empty());
    assert_eq!(r.report.skipped_m2["ambiguous_anonce"], 1);
}
#[test]
fn repeated_replay_values_in_separate_sessions_are_kept() {
    let mut frames = exchange();
    let mut m2 = key(2);
    m2[17] ^= 1;
    m2[81] ^= 1;
    let mut m1 = key(1);
    m1[17] ^= 1;
    frames.extend([
        (100_000, data_frame(&m1, true, false, false, false, STA)),
        (101_000, data_frame(&m2, false, false, false, false, STA)),
    ]);
    // Tight window separates the two sessions with reused replay counters.
    let r = convert(
        &pcap(&frames, 105, false, false),
        &Config {
            timeout_ms: 10,
            ..Config::default()
        },
    )
    .unwrap();
    assert_eq!(r.hashes.len(), 2);
}
#[test]
fn hidden_non_utf8_and_ambiguous_ssids() {
    let mut frames = exchange();
    frames[0].1 = beacon(&[]);
    assert!(raw(&frames).hashes.is_empty());
    let cfg = Config {
        bssid: Some(AP),
        ssid: Some(vec![0xff, 0, 0x7f]),
        ..Config::default()
    };
    let r = convert(&pcap(&frames, 105, false, false), &cfg).unwrap();
    assert_eq!(r.report.exports[0].ssid_hex, "ff007f");
    frames.push((5000, beacon(b"one")));
    frames.push((6000, beacon(b"two")));
    assert_eq!(raw(&frames).report.skipped_m2["ambiguous_ssid"], 1);
    assert_eq!(
        convert(&pcap(&frames, 105, false, false), &cfg)
            .unwrap()
            .hashes
            .len(),
        1
    );
}
#[test]
fn bssid_filter_and_override_validation() {
    let cfg = Config {
        bssid: Some([2, 0, 0, 0, 0, 99]),
        ..Config::default()
    };
    assert!(convert(&capture(), &cfg).unwrap().hashes.is_empty());
    for ssid in [vec![], vec![0; 33]] {
        assert!(
            convert(
                &capture(),
                &Config {
                    bssid: Some(AP),
                    ssid: Some(ssid),
                    ..Config::default()
                }
            )
            .is_err()
        );
    }
    assert!(
        convert(
            &capture(),
            &Config {
                ssid: Some(b"x".to_vec()),
                ..Config::default()
            }
        )
        .is_err()
    );
}
#[test]
fn wpa3_and_unsupported_akms_are_not_exported_as_wpa2() {
    for (version, akm) in [(0, 8), (2, 8), (3, 2), (2, 1)] {
        let mut m2 = key(2);
        m2[6] = (m2[6] & !7) | version;
        m2[118] = akm;
        let r = raw(&[
            (0, beacon(SSID)),
            (1000, frame(1)),
            (2000, data_frame(&m2, false, false, false, false, STA)),
            (3000, frame(3)),
        ]);
        assert!(r.hashes.is_empty());
    }
}
#[test]
fn malformed_eapol_lengths_mic_nonce_and_rsn_are_rejected() {
    let mut variants = Vec::new();
    let mut e = key(2);
    e[3] = 1;
    variants.push(e);
    let mut e = key(2);
    e[98] = 1;
    variants.push(e);
    let mut e = key(2);
    e[81..97].fill(0);
    variants.push(e);
    let mut e = key(2);
    e[17..49].fill(0);
    variants.push(e);
    let mut e = key(2);
    e[100] = 255;
    variants.push(e);
    let mut e = key(2);
    e[107] = 255;
    variants.push(e);
    for e in variants {
        let r = raw(&[
            (0, beacon(SSID)),
            (1000, frame(1)),
            (2000, data_frame(&e, false, false, false, false, STA)),
        ]);
        assert!(r.hashes.is_empty());
    }
}
#[test]
fn protected_fragmented_wds_and_wrong_direction_are_rejected() {
    for flag in [0x4000u16, 0x0400, 0x0300] {
        let mut f = frame(2);
        let fc = u16::from_le_bytes([f[0], f[1]]) | flag;
        f[..2].copy_from_slice(&fc.to_le_bytes());
        assert!(
            raw(&[(0, beacon(SSID)), (1000, frame(1)), (2000, f)])
                .hashes
                .is_empty()
        );
    }
    let f = data_frame(&key(2), true, false, false, false, STA);
    assert!(
        raw(&[(0, beacon(SSID)), (1000, frame(1)), (2000, f)])
            .hashes
            .is_empty()
    );
}
#[test]
fn malformed_classic_container_fails_without_partial_export() {
    let mut b = capture();
    b.push(0);
    assert!(convert(&b, &Config::default()).is_err());
    let mut b = capture();
    b[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(convert(&b, &Config::default()).is_err());
    let mut b = capture();
    b[28..32].copy_from_slice(&1_000_000u32.to_le_bytes());
    assert!(convert(&b, &Config::default()).is_err());
}
#[test]
fn truncated_radio_packet_is_skipped() {
    let mut b = capture();
    let original = u32::from_le_bytes(b[36..40].try_into().unwrap());
    b[36..40].copy_from_slice(&(original + 1).to_le_bytes());
    let r = run(&b);
    assert_eq!(r.report.skipped_packets["truncated_or_bad_packet"], 1);
    assert!(r.hashes.is_empty()); // SSID context was truncated.
}
#[test]
fn malformed_ng_trailer_interface_options_and_lengths_fail() {
    let valid = ng(&exchange(), E(false), 6, 0);
    let mut b = valid.clone();
    *b.last_mut().unwrap() ^= 1;
    assert!(convert(&b, &Config::default()).is_err());
    let mut b = section(E(false));
    b.extend(epb(0, 0, &frame(2), E(false)));
    assert!(convert(&b, &Config::default()).is_err());
    let mut b = valid.clone();
    b[40..42].copy_from_slice(&65535u16.to_le_bytes()); // corrupt IDB snaplen; test options below too.
    b[46..48].copy_from_slice(&65535u16.to_le_bytes()); // tsresol option length
    assert!(convert(&b, &Config::default()).is_err());
    let mut b = valid;
    b[4..8].copy_from_slice(&13u32.to_le_bytes());
    assert!(convert(&b, &Config::default()).is_err());
}
#[test]
fn simple_packets_can_supply_ssid_but_not_handshake_timestamps() {
    let e = E(false);
    let mut b = section(e);
    b.extend(interface(105, 6, 0, None, e));
    for f in [beacon(SSID), frame(1), frame(2)] {
        let mut body = e.u32(f.len() as u32).to_vec();
        body.extend(f);
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        b.extend(block(3, &body, e));
    }
    let r = run(&b);
    assert!(r.hashes.is_empty());
    assert_eq!(r.report.skipped_packets["missing_timestamp"], 2);
}
#[test]
fn every_truncated_prefix_and_deterministic_mutations_do_not_panic() {
    for b in [
        capture(),
        ng(&exchange(), E(false), 6, 0),
        ng(&exchange(), E(true), 9, -1),
    ] {
        for end in 0..b.len() {
            let _ = convert(&b[..end], &Config::default());
        }
        let mut seed = 0x12345678u32;
        for _ in 0..1000 {
            let mut mutated = b.clone();
            for _ in 0..4 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                let pos = seed as usize % mutated.len();
                mutated[pos] ^= (seed >> 24) as u8;
            }
            let _ = convert(&mutated, &Config::default());
        }
    }
}
#[test]
fn resource_limit_fails_instead_of_silently_discarding() {
    let mut frames = vec![(0, beacon(SSID))];
    frames.extend((0..2049).map(|t| (t, frame(1))));
    let err = convert(&pcap(&frames, 105, false, false), &Config::default()).unwrap_err();
    assert!(err.to_string().contains("2048"));
}
