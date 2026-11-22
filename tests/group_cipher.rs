mod common;

use common::*;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use wifi_cap2hashcat::{Config, Conversion, convert};

// Offsets in our synthetic M2, including the EAPOL header and RSN IE header.
const GROUP: usize = 103;
const PAIRWISE: usize = 109;
const AKM: usize = 115;

fn frames(m2: &[u8], peer: u8, group_cipher: u8) -> Vec<(u32, Vec<u8>)> {
    let mut beacon = beacon(SSID);
    // Give the synthetic AP the same group cipher as the client's RSN selection.
    beacon[38 + SSID.len() + 7] = group_cipher;
    let peer_time = if peer == 1 { 1000 } else { 3000 };
    vec![
        (0, beacon),
        (peer_time, frame(peer)),
        (2000, data_frame(m2, false, false, false, false, STA)),
    ]
}

fn convert_m2(m2: &[u8], peer: u8) -> Conversion {
    convert(
        &pcap(&frames(m2, peer, m2[GROUP + 3]), 105, false, false),
        &Config::default(),
    )
    .unwrap()
}

#[test]
fn ccmp_pairwise_accepts_only_tkip_or_ccmp_group_suites() {
    for group in 0..=u8::MAX {
        let mut m2 = key(2);
        m2[GROUP + 3] = group;
        let result = convert_m2(&m2, 1);
        if matches!(group, 2 | 4) {
            assert_eq!(result.hashes.len(), 1, "group {group}");
            assert_eq!(result.report.key_messages, [1, 1, 0, 0]);
            assert!(result.hashes[0].ends_with("*00"));
            let fields: Vec<_> = result.hashes[0].split('*').collect();
            m2[81..97].fill(0);
            assert_eq!(hex::decode(fields[7]).unwrap(), m2); // Never rewrite the RSN IE.
        } else {
            assert!(result.hashes.is_empty(), "group {group}");
            let reason = if group == 8 {
                "unsupported_cipher_combination"
            } else {
                "unsupported_group_cipher"
            };
            assert_eq!(result.report.skipped_packets[reason], 1);
        }
    }
}

#[test]
fn tkip_group_supports_m2_m3_radiotap_and_pcapng_without_normalizing_bytes() {
    let mut m2 = key(2);
    m2[GROUP + 3] = 2;
    let frames = frames(&m2, 3, 2);
    let radio_frames: Vec<_> = frames
        .iter()
        .map(|(t, f)| (*t, radio(f, 0x10, true)))
        .collect();
    let inputs = [
        pcap(&frames, 105, false, false),
        pcap(&radio_frames, 127, false, false),
        ng(&frames, E(false), 6, 0),
    ];
    let mut expected = None;
    for input in inputs {
        let result = convert(&input, &Config::default()).unwrap();
        assert_eq!(result.hashes.len(), 1);
        assert_eq!(result.report.key_messages, [0, 1, 1, 0]);
        assert_eq!(result.report.exports[0].message_pair, "02");
        assert!(result.hashes[0].ends_with("*02"));
        if let Some(hash) = &expected {
            assert_eq!(&result.hashes[0], hash);
        }
        expected = Some(result.hashes[0].clone());
    }
}

#[test]
fn group_allowlist_does_not_relax_pairwise_akm_descriptor_or_structure_checks() {
    for group in [2, 4] {
        for (offset, value, reason) in [
            (GROUP, 1, "unsupported_group_cipher"),
            (GROUP + 1, 0, "unsupported_group_cipher"),
            (GROUP + 2, 0, "unsupported_group_cipher"),
            (PAIRWISE + 3, 2, "cipher_descriptor_mismatch"),
            (PAIRWISE + 3, 9, "unsupported_pairwise_cipher"),
            (PAIRWISE, 1, "unsupported_pairwise_cipher"),
            (AKM + 3, 8, "unsupported_akm"),
            (AKM + 3, 1, "unsupported_akm"),
            (AKM, 1, "unsupported_akm"),
            (6, 0x09, "cipher_descriptor_mismatch"),
            (6, 0x0b, "unsupported_descriptor_version"),
            (101, 2, "malformed_rsn"),
            (100, 255, "malformed_information_elements"),
        ] {
            let mut m2 = key(2);
            m2[GROUP + 3] = group;
            m2[offset] = value;
            let result = convert_m2(&m2, 1);
            assert!(result.hashes.is_empty(), "group={group} offset={offset}");
            assert_eq!(result.report.skipped_packets[reason], 1);
        }
        let mut m2 = key(2);
        m2[GROUP + 3] = group;
        m2[9..17].copy_from_slice(&99u64.to_be_bytes());
        assert!(convert_m2(&m2, 1).hashes.is_empty());
    }
}

// Test-only MIC generation over synthetic bytes, independently of the converter.
fn mic(eapol: &[u8], anonce: &[u8; 32]) -> Vec<u8> {
    let mut pmk = [0; 32];
    pbkdf2_hmac::<Sha1>(b"synthetic-test-password", SSID, 4096, &mut pmk);
    let mut addresses = [AP, STA];
    addresses.sort();
    let snonce: [u8; 32] = eapol[17..49].try_into().unwrap();
    let mut nonces = [*anonce, snonce];
    nonces.sort();
    let mut prf = Hmac::<Sha1>::new_from_slice(&pmk).unwrap();
    prf.update(b"Pairwise key expansion\0");
    for address in addresses {
        prf.update(&address);
    }
    for nonce in nonces {
        prf.update(&nonce);
    }
    prf.update(&[0]);
    let block = prf.finalize().into_bytes();
    let mut signature = Hmac::<Sha1>::new_from_slice(&block[..16]).unwrap();
    let mut zeroed = eapol.to_vec();
    zeroed[81..97].fill(0);
    signature.update(&zeroed);
    signature.finalize().into_bytes()[..16].to_vec()
}

#[test]
fn tkip_group_export_preserves_cryptographically_valid_m2() {
    let mut m2 = key(2);
    m2[GROUP + 3] = 2;
    let anonce = [0x11; 32];
    let expected_mic = mic(&m2, &anonce);
    m2[81..97].copy_from_slice(&expected_mic);
    for peer in [1, 3] {
        let result = convert_m2(&m2, peer);
        assert_eq!(result.hashes.len(), 1);
        let fields: Vec<_> = result.hashes[0].split('*').collect();
        let exported = hex::decode(fields[7]).unwrap();
        assert_eq!(exported[GROUP + 3], 2);
        assert_eq!(hex::decode(fields[2]).unwrap(), mic(&exported, &anonce));
        // Replacing TKIP with CCMP in the captured bytes would invalidate the MIC.
        let mut changed = exported;
        changed[GROUP + 3] = 4;
        assert_ne!(expected_mic, mic(&changed, &anonce));
    }
}
