//! Minimal classic-pcap ingestion for Ethernet/IPv4/ICMP baseline captures.
//! Other link types and protocols can be added through extractors later.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpMessage {
    pub packet_index: usize,
    pub timestamp_ns: u64,
    /// Offset of the ICMP message in the original pcap file.
    pub source_offset: usize,
    pub source_ipv4: [u8; 4],
    pub destination_ipv4: [u8; 4],
    pub bytes: Vec<u8>,
}

struct IcmpSlice<'a> {
    offset: usize,
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    bytes: &'a [u8],
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u32(self, input: &[u8]) -> u32 {
        let bytes: [u8; 4] = input.try_into().expect("validated four-byte field");
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

pub fn extract_icmp_messages(data: &[u8]) -> Result<Vec<IcmpMessage>, String> {
    if data.len() < 24 {
        return Err("pcap global header is truncated".into());
    }
    let (endian, nanos) = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => return Err("unsupported pcap magic".into()),
    };
    let linktype = endian.u32(&data[20..24]) & 0xffff;
    if linktype != 1 {
        return Err(format!(
            "unsupported pcap link type {linktype}; expected Ethernet (1)"
        ));
    }
    let mut offset = 24;
    let mut packet_index = 0;
    let mut messages = Vec::new();
    while offset < data.len() {
        if data.len() - offset < 16 {
            return Err(format!("truncated packet header at byte {offset}"));
        }
        let ts_sec = endian.u32(&data[offset..offset + 4]) as u64;
        let ts_fraction = endian.u32(&data[offset + 4..offset + 8]) as u64;
        let captured_length = endian.u32(&data[offset + 8..offset + 12]) as usize;
        let frame_start = offset + 16;
        let frame_end = frame_start
            .checked_add(captured_length)
            .ok_or("pcap packet length overflow")?;
        if frame_end > data.len() {
            return Err(format!("truncated packet data at byte {frame_start}"));
        }
        let frame = &data[frame_start..frame_end];
        let fraction_ns = if nanos {
            ts_fraction
        } else {
            ts_fraction * 1000
        };
        if fraction_ns >= 1_000_000_000 {
            return Err(format!("invalid packet timestamp at index {packet_index}"));
        }
        let timestamp_ns = ts_sec
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(fraction_ns))
            .ok_or("packet timestamp overflow")?;
        if let Some(icmp) = extract_ethernet_icmp(frame)? {
            messages.push(IcmpMessage {
                packet_index,
                timestamp_ns,
                source_offset: frame_start + icmp.offset,
                source_ipv4: icmp.source_ipv4,
                destination_ipv4: icmp.destination_ipv4,
                bytes: icmp.bytes.to_vec(),
            });
        }
        offset = frame_end;
        packet_index += 1;
    }
    Ok(messages)
}

fn extract_ethernet_icmp(frame: &[u8]) -> Result<Option<IcmpSlice<'_>>, String> {
    if frame.len() < 14 {
        return Err("truncated Ethernet frame".into());
    }
    if frame[12..14] != [0x08, 0x00] {
        return Ok(None);
    }
    let ip = &frame[14..];
    if ip.len() < 20 {
        return Err("truncated IPv4 header".into());
    }
    let version = ip[0] >> 4;
    let header_length = (ip[0] & 0x0f) as usize * 4;
    if version != 4 || header_length < 20 || ip.len() < header_length {
        return Err("invalid IPv4 header".into());
    }
    let total_length = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_length < header_length || ip.len() < total_length {
        return Err("truncated IPv4 payload".into());
    }
    let fragment_bits = u16::from_be_bytes([ip[6], ip[7]]);
    if ip[9] != 1 || fragment_bits & 0x3fff != 0 {
        return Ok(None);
    }
    let icmp = &ip[header_length..total_length];
    if icmp.len() < 8 {
        return Err("truncated ICMP message".into());
    }
    let source_ipv4 = ip[12..16].try_into().expect("validated IPv4 header");
    let destination_ipv4 = ip[16..20].try_into().expect("validated IPv4 header");
    Ok(Some(IcmpSlice {
        offset: 14 + header_length,
        source_ipv4,
        destination_ipv4,
        bytes: icmp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_has_valid_request_reply_pairs_and_high_sequence_bytes() {
        let data = include_bytes!("../examples/icmp_echo.pcap");
        let messages = extract_icmp_messages(data).unwrap();
        let truth: serde_json::Value =
            serde_json::from_str(include_str!("../examples/icmp_echo.truth.json")).unwrap();
        assert_eq!(messages.len(), 24);
        assert_eq!(messages[0].bytes[0], 8);
        assert_eq!(messages[1].bytes[0], 0);
        assert_eq!(&messages[0].bytes[4..8], &[0x12, 0x34, 0, 0]);
        assert_eq!(&messages[12].bytes[4..8], &[0x23, 0x45, 1, 1]);
        for (message, case) in messages.iter().zip(truth["cases"].as_array().unwrap()) {
            assert_eq!(
                &data[message.source_offset..message.source_offset + message.bytes.len()],
                message.bytes
            );
            assert_eq!(message.bytes[0] as u64, case["type"].as_u64().unwrap());
            assert_eq!(
                u16::from_be_bytes([message.bytes[4], message.bytes[5]]) as u64,
                case["identifier"].as_u64().unwrap()
            );
            assert_eq!(
                u16::from_be_bytes([message.bytes[6], message.bytes[7]]) as u64,
                case["sequence"].as_u64().unwrap()
            );
            assert_eq!(
                message.bytes.len() - 8,
                case["payload_length"].as_u64().unwrap() as usize
            );
            assert_eq!(icmp_checksum(&message.bytes), 0);
        }
    }

    fn icmp_checksum(input: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in input.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn rejects_truncated_packet_without_returning_partial_evidence() {
        let data = include_bytes!("../examples/icmp_echo.pcap");
        assert!(extract_icmp_messages(&data[..data.len() - 1]).is_err());
    }
}
