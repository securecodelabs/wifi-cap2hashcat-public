const EPOCH: u32 = 1_700_000_000;

pub fn pcap(packets: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut output = 0xa1b2c3d4_u32.to_le_bytes().to_vec();
    output.extend(2_u16.to_le_bytes());
    output.extend(4_u16.to_le_bytes());
    output.extend([0; 8]);
    output.extend(65535_u32.to_le_bytes());
    output.extend(105_u32.to_le_bytes()); // LINKTYPE_IEEE802_11, no Radiotap or FCS.
    for (micros, packet) in packets {
        for field in [EPOCH, *micros, packet.len() as u32, packet.len() as u32] {
            output.extend(field.to_le_bytes());
        }
        output.extend(packet);
    }
    output
}

fn block(output: &mut Vec<u8>, kind: u32, mut body: Vec<u8>) {
    body.resize(body.len().next_multiple_of(4), 0);
    let length = (body.len() + 12) as u32;
    output.extend(kind.to_le_bytes());
    output.extend(length.to_le_bytes());
    output.extend(body);
    output.extend(length.to_le_bytes());
}

pub fn pcapng(packets: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut section = 0x1a2b3c4d_u32.to_le_bytes().to_vec();
    section.extend(1_u16.to_le_bytes());
    section.extend(0_u16.to_le_bytes());
    section.extend((-1_i64).to_le_bytes());
    block(&mut output, 0x0a0d0d0a, section);
    let mut interface = 105_u16.to_le_bytes().to_vec();
    interface.extend([0; 2]);
    interface.extend(65535_u32.to_le_bytes());
    block(&mut output, 1, interface); // Default if_tsresol is microseconds.
    for (micros, packet) in packets {
        let ticks = u64::from(EPOCH) * 1_000_000 + u64::from(*micros);
        let mut body = Vec::new();
        for field in [
            0,
            (ticks >> 32) as u32,
            ticks as u32,
            packet.len() as u32,
            packet.len() as u32,
        ] {
            body.extend(field.to_le_bytes());
        }
        body.extend(packet);
        block(&mut output, 6, body);
    }
    output
}
