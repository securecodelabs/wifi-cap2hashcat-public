mod common;
use common::*;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use wifi_cap2hashcat::{Config, convert};

// Public example from https://hashcat.net/wiki/doku.php?id=example_hashes
// Public example password: hashcat! . No user capture or password is a fixture.
#[test]
fn official_hashcat_vector_roundtrips_and_mic_verifies_independently() {
    let line = include_str!("fixtures/hashcat-example.hc22000").trim();
    let parts: Vec<_> = line.split('*').collect();
    let mic = hex::decode(parts[2]).unwrap();
    let ap: [u8; 6] = hex::decode(parts[3]).unwrap().try_into().unwrap();
    let sta: [u8; 6] = hex::decode(parts[4]).unwrap().try_into().unwrap();
    let ssid = hex::decode(parts[5]).unwrap();
    let anonce = hex::decode(parts[6]).unwrap();
    let mut eapol = hex::decode(parts[7]).unwrap();
    let replay = u64::from_be_bytes(eapol[9..17].try_into().unwrap());
    eapol[81..97].copy_from_slice(&mic);
    let mut m1 = key(1);
    m1[9..17].copy_from_slice(&replay.to_be_bytes());
    m1[17..49].copy_from_slice(&anonce);
    let mut m3 = key(3);
    m3[9..17].copy_from_slice(&(replay + 1).to_be_bytes());
    m3[17..49].copy_from_slice(&anonce);
    let mut frames = vec![(0, beacon(&ssid))];
    frames[0].1[10..16].copy_from_slice(&ap);
    frames[0].1[16..22].copy_from_slice(&ap);
    for (i, e) in [&m1, &eapol, &m3].into_iter().enumerate() {
        let from_ap = i != 1;
        let mut b = data_frame(e, from_ap, false, false, false, sta);
        if from_ap {
            b[10..16].copy_from_slice(&ap);
        } else {
            b[4..10].copy_from_slice(&ap);
        }
        b[16..22].copy_from_slice(&ap);
        frames.push((1000 * (i as u32 + 1), b));
    }
    let result = convert(&pcap(&frames, 105, false, false), &Config::default()).unwrap();
    assert_eq!(result.hashes.len(), 1);
    let expected = parts[..8].join("*") + "*02";
    assert_eq!(result.hashes[0], expected);
    let fields: Vec<_> = result.hashes[0].split('*').collect();
    let zeroed_eapol = hex::decode(fields[7]).unwrap();
    let mut pmk = [0; 32];
    pbkdf2_hmac::<Sha1>(b"hashcat!", &ssid, 4096, &mut pmk);
    let mut addresses = [ap, sta];
    addresses.sort();
    let snonce: [u8; 32] = zeroed_eapol[17..49].try_into().unwrap();
    let mut nonces = [anonce.try_into().unwrap(), snonce];
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
    signature.update(&zeroed_eapol);
    assert_eq!(&signature.finalize().into_bytes()[..16], mic);
}
