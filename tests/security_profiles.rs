mod common;

use common::*;
use wifi_cap2hashcat::{Cipher, Config, convert};

fn cipher(value: u8) -> Cipher {
    match value {
        2 => Cipher::Tkip,
        4 => Cipher::Ccmp128,
        8 => Cipher::Gcmp128,
        _ => panic!("fixture cipher"),
    }
}

#[test]
fn shared_c_and_rust_security_corpus_matches_golden_exports() {
    let mut name = "";
    let mut expected = (0, 0, 0, "");
    let mut frames = Vec::new();
    let mut golden = None;
    let mut cases = 0;
    for line in include_str!("fixtures/security-profiles.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("CASE") => {
                name = fields[1];
                expected = (
                    fields[2].parse::<u8>().unwrap(),
                    fields[3].parse::<u8>().unwrap(),
                    fields[4].parse::<u8>().unwrap(),
                    fields[5],
                );
                frames.clear();
                golden = None;
            }
            Some("FRAME") => frames.push((
                fields[1].parse::<u32>().unwrap(),
                hex::decode(fields[3]).unwrap(),
            )),
            Some("HASH") => golden = Some(fields[1]),
            Some("END") => {
                // The same packets must produce the same result in each supported container.
                let radio_frames: Vec<_> = frames
                    .iter()
                    .map(|(t, f)| (*t, radio(f, 0x10, true)))
                    .collect();
                for input in [
                    pcap(&frames, 105, false, false),
                    pcap(&radio_frames, 127, false, false),
                    ng(&frames, E(false), 6, 0),
                ] {
                    let result = convert(&input, &Config::default()).unwrap();
                    if let Some(hash) = golden {
                        assert_eq!(result.hashes, [hash], "{name}");
                        let profile = result.report.exports[0].security_profile;
                        assert_eq!(profile.pairwise_cipher, cipher(expected.0), "{name}");
                        assert_eq!(profile.group_cipher, cipher(expected.1), "{name}");
                        assert_eq!(profile.descriptor_version, expected.2, "{name}");
                        assert_eq!(
                            (profile.protocol, profile.akm, profile.descriptor_type),
                            ("RSN", "PSK", 2)
                        );
                        assert_eq!(profile.client_pmf, "disabled");
                        let report = serde_json::to_value(&result.report).unwrap();
                        assert_eq!(report["exports"][0]["security_profile"]["akm"], "PSK");
                    } else {
                        assert!(result.hashes.is_empty(), "{name}");
                        if expected.3 == "ambiguous_security_profile" {
                            assert_eq!(result.report.skipped_m2[expected.3], 2, "{name}");
                        }
                    }
                }
                cases += 1;
            }
            _ => {}
        }
    }
    assert_eq!(cases, 38);
}

fn selected(pair: u8, group: u8, version: u8) -> Vec<u8> {
    let mut m2 = key(2);
    m2[6] = (m2[6] & !7) | version;
    m2[106] = group;
    m2[112] = pair;
    m2
}

fn run(m2: &[u8], version: u8) -> wifi_cap2hashcat::Conversion {
    let mut m1 = key(1);
    m1[6] = (m1[6] & !7) | version;
    let frames = [
        (0, beacon(SSID)),
        (1000, data_frame(&m1, true, false, false, false, STA)),
        (2000, data_frame(m2, false, false, false, false, STA)),
    ];
    convert(&pcap(&frames, 105, false, false), &Config::default()).unwrap()
}

#[test]
fn full_pairwise_selector_space_keeps_unknown_and_256_bit_suites_out() {
    for pair in 0..=u8::MAX {
        for version in [1, 2] {
            let result = run(&selected(pair, 2, version), version);
            let supported = (pair == 2 && version == 1) || (matches!(pair, 4 | 8) && version == 2);
            assert_eq!(
                !result.hashes.is_empty(),
                supported,
                "pair={pair}, version={version}"
            );
        }
    }
}

#[test]
fn full_group_selector_space_is_checked_for_each_pairwise_profile() {
    for pair in [2, 4, 8] {
        let version = if pair == 2 { 1 } else { 2 };
        for group in 0..=u8::MAX {
            let supported = match pair {
                2 => group == 2,
                4 => matches!(group, 2 | 4),
                _ => matches!(group, 2 | 4 | 8),
            };
            assert_eq!(
                !run(&selected(pair, group, version), version)
                    .hashes
                    .is_empty(),
                supported,
                "pair={pair}, group={group}"
            );
        }
    }
}

#[test]
fn profile_records_client_pmf_and_raw_management_suite_without_changing_m2() {
    let mut m2 = selected(8, 8, 2);
    m2[119] = 0xc0;
    m2.extend([0, 0, 0, 15, 172, 6]); // Zero PMKIDs, BIP-CMAC-128 selector.
    m2[3] += 6;
    m2[98] += 6;
    m2[100] += 6;
    let result = run(&m2, 2);
    let profile = result.report.exports[0].security_profile;
    assert_eq!(profile.client_pmf, "required");
    assert_eq!(profile.group_management_cipher, Some([0, 15, 172, 6]));
    let fields: Vec<_> = result.hashes[0].split('*').collect();
    m2[81..97].fill(0);
    assert_eq!(hex::decode(fields[7]).unwrap(), m2);
}

#[test]
fn mismatched_key_lengths_and_multiple_selected_suites_are_rejected() {
    for pair in [2, 4, 8] {
        let version = if pair == 2 { 1 } else { 2 };
        let mut m2 = selected(pair, 2, version);
        m2[8] = if pair == 2 { 16 } else { 32 };
        assert_eq!(
            run(&m2, version).report.skipped_packets["cipher_key_length_mismatch"],
            1
        );
        m2[8] = 0;
        // An M2 must select exactly one pairwise suite, unlike an AP advertisement.
        m2[107] = 2;
        assert!(run(&m2, version).hashes.is_empty());
    }
}

#[test]
fn separate_profiles_with_different_versions_or_replays_remain_usable() {
    let mut frames = vec![(0, beacon(SSID))];
    for (i, pair) in [2, 4, 8].into_iter().enumerate() {
        let version = if pair == 2 { 1 } else { 2 };
        let mut m1 = key(1);
        let mut m2 = selected(pair, 2, version);
        m1[6] = (m1[6] & !7) | version;
        for e in [&mut m1, &mut m2] {
            e[9..17].copy_from_slice(&(7 + i as u64).to_be_bytes());
        }
        frames.push((1000, data_frame(&m1, true, false, false, false, STA)));
        frames.push((2000, data_frame(&m2, false, false, false, false, STA)));
    }
    let result = convert(&pcap(&frames, 105, false, false), &Config::default()).unwrap();
    assert_eq!(result.hashes.len(), 3);
}
