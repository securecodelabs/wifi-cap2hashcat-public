use aes_kw::{KeyInit as AesKeyInit, KwAes128};
use anyhow::Result;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const STATION: [u8; 6] = [2, 0, 0, 0, 0, 2];
const ANONCE: [u8; 32] = [0x11; 32];
const SNONCE: [u8; 32] = [0x22; 32];
const RSN: [u8; 22] = [
    48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
];

fn header(control: u16, receiver: [u8; 6], transmitter: [u8; 6], sequence: u16) -> Vec<u8> {
    let mut bytes = control.to_le_bytes().to_vec();
    bytes.extend([0; 2]);
    bytes.extend(receiver);
    bytes.extend(transmitter);
    bytes.extend(AP);
    bytes.extend((sequence << 4).to_le_bytes());
    bytes
}

pub fn beacon(ssid: &[u8]) -> Vec<u8> {
    let mut bytes = header(0x0080, [255; 6], AP, 0);
    bytes.extend(1_000_000_u64.to_le_bytes());
    bytes.extend(100_u16.to_le_bytes());
    bytes.extend(0x0411_u16.to_le_bytes());
    bytes.extend([0, ssid.len() as u8]);
    bytes.extend(ssid);
    bytes.extend([1, 4, 0x82, 0x84, 0x8b, 0x96]); // Supported rates.
    bytes.extend([3, 1, 1]); // Channel 1.
    bytes.extend(RSN);
    bytes
}

fn signature(key: &[u8], bytes: &[u8]) -> [u8; 20] {
    let mut hmac =
        <Hmac<Sha1> as hmac::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(bytes);
    hmac.finalize().into_bytes().into()
}

fn ptk(ssid: &[u8], password: &[u8]) -> Vec<u8> {
    let mut pmk = [0; 32];
    pbkdf2_hmac::<Sha1>(password, ssid, 4096, &mut pmk);
    let mut addresses = [AP, STATION];
    let mut nonces = [ANONCE, SNONCE];
    addresses.sort();
    nonces.sort();
    let mut input = b"Pairwise key expansion\0".to_vec();
    input.extend(addresses.concat());
    input.extend(nonces.concat());
    let mut result = Vec::new();
    for counter in 0..4 {
        input.push(counter);
        result.extend(signature(&pmk, &input));
        input.pop();
    }
    result.truncate(64);
    result
}

fn encrypted_key_data(kek: &[u8]) -> Result<Vec<u8>> {
    let mut data = RSN.to_vec();
    data.extend([0xdd, 22, 0, 15, 172, 1, 1, 0]); // GTK KDE, key ID 1.
    data.extend([0x33; 16]); // Deterministic synthetic GTK; never used on a network.
    data.extend([0xdd, 0]); // IEEE 802.11 padding to a multiple of eight bytes.
    let wrapper = KwAes128::new_from_slice(kek)
        .map_err(|_| anyhow::anyhow!("Invalid synthetic KEK length"))?;
    let mut output = vec![0; data.len() + 8];
    wrapper
        .wrap_key(&data, &mut output)
        .map_err(|error| anyhow::anyhow!("Wrap synthetic M3 key data: {error:?}"))?;
    Ok(output)
}

fn key(message: u8, ptk: &[u8], m3_data: &[u8]) -> Vec<u8> {
    let data = match message {
        2 => RSN.as_slice(),
        3 => m3_data,
        _ => &[],
    };
    let mut eapol = vec![0; 99 + data.len()];
    eapol[..2].copy_from_slice(&[2, 3]);
    eapol[2..4].copy_from_slice(&((95 + data.len()) as u16).to_be_bytes());
    eapol[4] = 2;
    let info: u16 = match message {
        1 => 0x008a,
        2 => 0x010a,
        3 => 0x13ca,
        _ => 0x030a,
    };
    eapol[5..7].copy_from_slice(&info.to_be_bytes());
    if message == 1 || message == 3 {
        eapol[7..9].copy_from_slice(&16_u16.to_be_bytes());
    }
    eapol[9..17].copy_from_slice(&(if message < 3 { 7_u64 } else { 8_u64 }).to_be_bytes());
    match message {
        1 | 3 => eapol[17..49].copy_from_slice(&ANONCE),
        2 => eapol[17..49].copy_from_slice(&SNONCE),
        _ => (),
    }
    eapol[97..99].copy_from_slice(&(data.len() as u16).to_be_bytes());
    eapol[99..].copy_from_slice(data);
    if message != 1 {
        let mic = signature(&ptk[..16], &eapol);
        eapol[81..97].copy_from_slice(&mic[..16]);
    }
    eapol
}

pub fn exchange(ssid: &[u8], password: &[u8]) -> Result<Vec<Vec<u8>>> {
    let ptk = ptk(ssid, password);
    let encrypted = encrypted_key_data(&ptk[16..32])?;
    Ok((1..=4)
        .map(|message| {
            let from_ap = message == 1 || message == 3;
            let mut frame = if from_ap {
                header(0x0208, STATION, AP, u16::from(message))
            } else {
                header(0x0108, AP, STATION, u16::from(message))
            };
            frame.extend([0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
            frame.extend(key(message, &ptk, &encrypted));
            frame
        })
        .collect())
}
