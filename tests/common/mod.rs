#![allow(dead_code)]
pub const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const STA: [u8; 6] = [2, 0, 0, 0, 0, 2];
pub const SSID: &[u8] = b"test-lab";
pub const RSN: [u8; 22] = [
    48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0x80, 0,
];
pub fn header(fc: u16, a1: [u8; 6], a2: [u8; 6], a3: [u8; 6]) -> Vec<u8> {
    let mut b = fc.to_le_bytes().to_vec();
    b.extend([0; 2]);
    b.extend(a1);
    b.extend(a2);
    b.extend(a3);
    b.extend([0; 2]);
    b
}
pub fn beacon(ssid: &[u8]) -> Vec<u8> {
    let mut b = header(0x80, [0xff; 6], AP, AP);
    b.extend([0; 12]);
    b.extend([0, ssid.len() as u8]);
    b.extend(ssid);
    b.extend(RSN);
    b
}
pub fn key(message: u8) -> Vec<u8> {
    let data = if message == 2 { RSN.as_slice() } else { &[] };
    let mut e = vec![0u8; 99 + data.len()];
    e[0] = 2;
    e[1] = 3;
    let body_len = (e.len() - 4) as u16;
    e[2..4].copy_from_slice(&body_len.to_be_bytes());
    e[4] = 2;
    let info: u16 = match message {
        1 => 0x008a,
        2 => 0x010a,
        3 => 0x13ca,
        4 => 0x030a,
        _ => panic!(),
    };
    e[5..7].copy_from_slice(&info.to_be_bytes());
    e[9..17].copy_from_slice(&(if message <= 2 { 7u64 } else { 8u64 }).to_be_bytes());
    if message != 4 {
        e[17..49].fill(if message == 2 { 0x22 } else { 0x11 });
    }
    if message != 1 {
        e[81..97].fill(0x55);
    }
    e[97..99].copy_from_slice(&(data.len() as u16).to_be_bytes());
    e[99..].copy_from_slice(data);
    e
}
pub fn data_frame(
    eapol: &[u8],
    from_ap: bool,
    qos: bool,
    ht: bool,
    pad: bool,
    station: [u8; 6],
) -> Vec<u8> {
    let fc = 8
        | if from_ap { 0x0200 } else { 0x0100 }
        | if qos { 0x80 } else { 0 }
        | if ht { 0x8000 } else { 0 };
    let mut b = if from_ap {
        header(fc, station, AP, AP)
    } else {
        header(fc, AP, station, AP)
    };
    if qos {
        b.extend([0; 2]);
    }
    if ht {
        b.extend([0; 4]);
    }
    if pad {
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
    }
    b.extend([0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    b.extend(eapol);
    b
}
pub fn frame(message: u8) -> Vec<u8> {
    data_frame(
        &key(message),
        message == 1 || message == 3,
        false,
        false,
        false,
        STA,
    )
}
pub fn radio(frame: &[u8], flags: u8, fcs: bool) -> Vec<u8> {
    let mut b = vec![0, 0, 9, 0, 2, 0, 0, 0, flags];
    b.extend(frame);
    if fcs {
        b.extend(crc32fast::hash(frame).to_le_bytes());
    }
    b
}
#[derive(Clone, Copy)]
pub struct E(pub bool);
impl E {
    pub fn u16(self, v: u16) -> [u8; 2] {
        if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
    pub fn u32(self, v: u32) -> [u8; 4] {
        if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
    pub fn i64(self, v: i64) -> [u8; 8] {
        if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
}
pub fn pcap(frames: &[(u32, Vec<u8>)], link: u32, be: bool, nano: bool) -> Vec<u8> {
    let e = E(be);
    let mut b = e.u32(if nano { 0xa1b23c4d } else { 0xa1b2c3d4 }).to_vec();
    b.extend(e.u16(2));
    b.extend(e.u16(4));
    b.extend([0; 8]);
    b.extend(e.u32(65535));
    b.extend(e.u32(link));
    for (fraction, frame) in frames {
        b.extend(e.u32(100));
        b.extend(e.u32(*fraction));
        b.extend(e.u32(frame.len() as u32));
        b.extend(e.u32(frame.len() as u32));
        b.extend(frame);
    }
    b
}
pub fn exchange() -> Vec<(u32, Vec<u8>)> {
    vec![
        (0, beacon(SSID)),
        (1000, frame(1)),
        (2000, frame(2)),
        (3000, frame(3)),
        (4000, frame(4)),
    ]
}
pub fn capture() -> Vec<u8> {
    pcap(&exchange(), 105, false, false)
}
pub fn block(kind: u32, body: &[u8], e: E) -> Vec<u8> {
    assert_eq!(body.len() % 4, 0);
    let len = (body.len() + 12) as u32;
    let mut b = e.u32(kind).to_vec();
    b.extend(e.u32(len));
    b.extend(body);
    b.extend(e.u32(len));
    b
}
pub fn option(code: u16, value: &[u8], e: E) -> Vec<u8> {
    let mut b = e.u16(code).to_vec();
    b.extend(e.u16(value.len() as u16));
    b.extend(value);
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b
}
pub fn section(e: E) -> Vec<u8> {
    let mut body = e.u32(0x1a2b3c4d).to_vec();
    body.extend(e.u16(1));
    body.extend(e.u16(0));
    body.extend(e.i64(-1));
    block(0x0a0d0d0a, &body, e)
}
pub fn interface(link: u16, resolution: u8, offset: i64, fcs: Option<u8>, e: E) -> Vec<u8> {
    let mut body = e.u16(link).to_vec();
    body.extend([0; 2]);
    body.extend(e.u32(65535));
    body.extend(option(9, &[resolution], e));
    body.extend(option(14, &e.i64(offset), e));
    if let Some(bits) = fcs {
        body.extend(option(13, &[bits], e));
    }
    body.extend([0; 4]);
    block(1, &body, e)
}
pub fn epb(id: u32, ticks: u64, frame: &[u8], e: E) -> Vec<u8> {
    let mut body = e.u32(id).to_vec();
    body.extend(e.u32((ticks >> 32) as u32));
    body.extend(e.u32(ticks as u32));
    body.extend(e.u32(frame.len() as u32));
    body.extend(e.u32(frame.len() as u32));
    body.extend(frame);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    block(6, &body, e)
}
pub fn ng(frames: &[(u32, Vec<u8>)], e: E, resolution: u8, offset: i64) -> Vec<u8> {
    let mut b = section(e);
    b.extend(interface(105, resolution, offset, None, e));
    for (ticks, frame) in frames {
        b.extend(epb(0, u64::from(*ticks), frame, e));
    }
    b
}
