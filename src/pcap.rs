//! Ethernet/IPv4 transport extraction from classic pcap and pcapng.
//! ICMP messages, UDP datagrams, and TCP segment payloads share capture parsing and retain exact
//! byte offsets into the original capture. Ethernet VLAN tags are unwrapped before IPv4 parsing.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportMessage {
    pub packet_index: usize,
    pub timestamp_ns: u64,
    /// Offset of the extracted bytes in the original capture file.
    pub source_offset: usize,
    pub source_ipv4: [u8; 4],
    pub destination_ipv4: [u8; 4],
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub tcp_sequence: Option<u32>,
    pub tcp_syn: bool,
    pub bytes: Vec<u8>,
}

pub type IcmpMessage = TransportMessage;

#[derive(Debug)]
struct TransportSlice<'a> {
    offset: usize,
    source_ipv4: [u8; 4],
    destination_ipv4: [u8; 4],
    source_port: Option<u16>,
    destination_port: Option<u16>,
    tcp_sequence: Option<u32>,
    tcp_syn: bool,
    bytes: &'a [u8],
}

#[derive(Clone, Copy)]
enum Transport {
    Icmp,
    Udp,
    Tcp,
}

impl Transport {
    fn ipv4_protocol(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Udp => 17,
            Self::Tcp => 6,
        }
    }
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, input: &[u8]) -> u16 {
        let bytes: [u8; 2] = input.try_into().expect("validated two-byte field");
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, input: &[u8]) -> u32 {
        let bytes: [u8; 4] = input.try_into().expect("validated four-byte field");
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    fn i64(self, input: &[u8]) -> i64 {
        let bytes: [u8; 8] = input.try_into().expect("validated eight-byte field");
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

pub fn extract_icmp_messages(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcap_messages(data, Transport::Icmp)
}

pub fn extract_udp_messages(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcap_messages(data, Transport::Udp)
}

/// Return application bytes from individual TCP segments. This does not reassemble streams.
pub fn extract_tcp_segments(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcap_messages(data, Transport::Tcp)
}

fn extract_pcap_messages(
    data: &[u8],
    transport: Transport,
) -> Result<Vec<TransportMessage>, String> {
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
        push_ethernet_transport(
            &mut messages,
            frame,
            frame_start,
            packet_index,
            timestamp_ns,
            transport,
        )?;
        offset = frame_end;
        packet_index += 1;
    }
    Ok(messages)
}

#[derive(Clone, Copy)]
struct PcapngInterface {
    linktype: u16,
    timestamp_units_per_second: u128,
    timestamp_offset_seconds: i64,
}

/// Extract Ethernet/IPv4/ICMP messages from pcapng Enhanced Packet Blocks.
/// Section headers and interface timestamp resolutions are honored; other
/// block types are skipped only when they cannot contain packet bytes.
pub fn extract_pcapng_icmp_messages(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcapng_messages(data, Transport::Icmp)
}

pub fn extract_pcapng_udp_messages(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcapng_messages(data, Transport::Udp)
}

pub fn extract_pcapng_tcp_segments(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcapng_messages(data, Transport::Tcp)
}

fn extract_pcapng_messages(
    data: &[u8],
    transport: Transport,
) -> Result<Vec<TransportMessage>, String> {
    let mut offset = 0_usize;
    let mut section_endian = None;
    let mut interfaces = Vec::<PcapngInterface>::new();
    let mut messages = Vec::new();
    let mut packet_index = 0;
    while offset < data.len() {
        if data.len() - offset < 12 {
            return Err(format!("truncated pcapng block at byte {offset}"));
        }
        let is_section_header = data[offset..offset + 4] == [0x0a, 0x0d, 0x0d, 0x0a];
        let endian = if is_section_header {
            if data.len() - offset < 28 {
                return Err("truncated pcapng section header".into());
            }
            match &data[offset + 8..offset + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                _ => return Err("invalid pcapng byte-order magic".into()),
            }
        } else {
            section_endian.ok_or("pcapng must start with a section header")?
        };
        let block_length = endian.u32(&data[offset + 4..offset + 8]) as usize;
        if block_length < 12 || !block_length.is_multiple_of(4) {
            return Err(format!("invalid pcapng block length at byte {offset}"));
        }
        let end = offset
            .checked_add(block_length)
            .ok_or("pcapng block length overflow")?;
        if end > data.len() {
            return Err(format!("truncated pcapng block at byte {offset}"));
        }
        if endian.u32(&data[end - 4..end]) as usize != block_length {
            return Err(format!(
                "pcapng block length trailer mismatch at byte {offset}"
            ));
        }
        let block_type = endian.u32(&data[offset..offset + 4]);
        let body = &data[offset + 8..end - 4];
        match block_type {
            0x0a0d0d0a => {
                if body.len() < 16 || endian.u16(&body[4..6]) != 1 {
                    return Err("unsupported pcapng section header".into());
                }
                section_endian = Some(endian);
                interfaces.clear();
            }
            1 => {
                if body.len() < 8 {
                    return Err("truncated pcapng interface description".into());
                }
                let (timestamp_units_per_second, timestamp_offset_seconds) =
                    timestamp_options(&body[8..], endian)?;
                interfaces.push(PcapngInterface {
                    linktype: endian.u16(&body[..2]),
                    timestamp_units_per_second,
                    timestamp_offset_seconds,
                });
            }
            6 => {
                if body.len() < 20 {
                    return Err("truncated pcapng enhanced packet".into());
                }
                let interface_id = endian.u32(&body[..4]) as usize;
                let interface = interfaces
                    .get(interface_id)
                    .ok_or_else(|| format!("unknown pcapng interface {interface_id}"))?;
                if interface.linktype != 1 {
                    return Err(format!(
                        "unsupported pcapng link type {} on interface {interface_id}",
                        interface.linktype
                    ));
                }
                let captured_length = endian.u32(&body[12..16]) as usize;
                let original_length = endian.u32(&body[16..20]) as usize;
                if original_length < captured_length || captured_length > body.len() - 20 {
                    return Err("invalid pcapng captured packet length".into());
                }
                let ticks =
                    ((endian.u32(&body[4..8]) as u64) << 32) | endian.u32(&body[8..12]) as u64;
                let ticks_ns =
                    (u128::from(ticks) * 1_000_000_000) / interface.timestamp_units_per_second;
                let timestamp_ns = i128::try_from(ticks_ns)
                    .map_err(|_| "pcapng timestamp overflow")?
                    + i128::from(interface.timestamp_offset_seconds) * 1_000_000_000;
                let timestamp_ns =
                    u64::try_from(timestamp_ns).map_err(|_| "pcapng timestamp out of range")?;
                let frame_start = offset + 28;
                push_ethernet_transport(
                    &mut messages,
                    &body[20..20 + captured_length],
                    frame_start,
                    packet_index,
                    timestamp_ns,
                    transport,
                )?;
                packet_index += 1;
            }
            2 | 3 => return Err("pcapng legacy packet blocks are not supported".into()),
            _ => {}
        }
        offset = end;
    }
    if section_endian.is_none() {
        return Err("pcapng has no section header".into());
    }
    Ok(messages)
}

fn timestamp_options(options: &[u8], endian: Endian) -> Result<(u128, i64), String> {
    let mut position = 0;
    let mut units = 1_000_000_u128;
    let mut offset_seconds = 0_i64;
    while position < options.len() {
        if options.len() - position < 4 {
            return Err("truncated pcapng interface option".into());
        }
        let code = endian.u16(&options[position..position + 2]);
        let length = endian.u16(&options[position + 2..position + 4]) as usize;
        let data_start = position + 4;
        let data_end = data_start
            .checked_add(length)
            .ok_or("pcapng option length overflow")?;
        if data_end > options.len() {
            return Err("truncated pcapng interface option".into());
        }
        if code == 0 {
            if length != 0 {
                return Err("invalid pcapng end-of-options".into());
            }
            break;
        }
        if code == 9 {
            if length != 1 {
                return Err("invalid pcapng timestamp resolution".into());
            }
            let value = options[data_start];
            units = if value & 0x80 == 0 {
                10_u128
                    .checked_pow(u32::from(value))
                    .ok_or("pcapng timestamp resolution overflow")?
            } else {
                2_u128
                    .checked_pow(u32::from(value & 0x7f))
                    .ok_or("pcapng timestamp resolution overflow")?
            };
        } else if code == 14 {
            if length != 8 {
                return Err("invalid pcapng timestamp offset".into());
            }
            offset_seconds = endian.i64(&options[data_start..data_end]);
        }
        position = (data_end + 3) & !3;
        if position > options.len() {
            return Err("truncated pcapng option padding".into());
        }
    }
    Ok((units, offset_seconds))
}

fn push_ethernet_transport(
    messages: &mut Vec<TransportMessage>,
    frame: &[u8],
    frame_start: usize,
    packet_index: usize,
    timestamp_ns: u64,
    transport: Transport,
) -> Result<(), String> {
    if let Some(message) = extract_ethernet_transport(frame, transport)? {
        messages.push(TransportMessage {
            packet_index,
            timestamp_ns,
            source_offset: frame_start + message.offset,
            source_ipv4: message.source_ipv4,
            destination_ipv4: message.destination_ipv4,
            source_port: message.source_port,
            destination_port: message.destination_port,
            tcp_sequence: message.tcp_sequence,
            tcp_syn: message.tcp_syn,
            bytes: message.bytes.to_vec(),
        });
    }
    Ok(())
}

fn extract_ethernet_transport(
    frame: &[u8],
    transport: Transport,
) -> Result<Option<TransportSlice<'_>>, String> {
    if frame.len() < 14 {
        return Err("truncated Ethernet frame".into());
    }
    let mut ip_start = 14;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut vlan_depth = 0;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if vlan_depth == 4 {
            return Err("Ethernet frame has more than four VLAN tags".into());
        }
        if frame.len() < ip_start + 4 {
            return Err("truncated Ethernet VLAN tag".into());
        }
        ether_type = u16::from_be_bytes([frame[ip_start + 2], frame[ip_start + 3]]);
        ip_start += 4;
        vlan_depth += 1;
    }
    if ether_type != 0x0800 {
        return Ok(None);
    }
    let ip = &frame[ip_start..];
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
    if ip[9] != transport.ipv4_protocol() || fragment_bits & 0x3fff != 0 {
        return Ok(None);
    }
    let payload = &ip[header_length..total_length];
    let (bytes, source_port, destination_port, tcp_sequence, tcp_syn, transport_header_length) =
        match transport {
            Transport::Icmp => {
                if payload.len() < 8 {
                    return Err("truncated ICMP message".into());
                }
                (payload, None, None, None, false, 0)
            }
            Transport::Udp => {
                if payload.len() < 8 {
                    return Err("truncated UDP header".into());
                }
                let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                if length < 8 || length > payload.len() {
                    return Err("invalid UDP datagram length".into());
                }
                if length == 8 {
                    return Ok(None);
                }
                (
                    &payload[8..length],
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                    None,
                    false,
                    8,
                )
            }
            Transport::Tcp => {
                if payload.len() < 20 {
                    return Err("truncated TCP header".into());
                }
                let header_length = ((payload[12] >> 4) as usize) * 4;
                if header_length < 20 || header_length > payload.len() {
                    return Err("invalid TCP data offset".into());
                }
                if header_length == payload.len() {
                    return Ok(None);
                }
                (
                    &payload[header_length..],
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                    Some(u32::from_be_bytes(
                        payload[4..8].try_into().expect("TCP header checked"),
                    )),
                    payload[13] & 0x02 != 0,
                    header_length,
                )
            }
        };
    let source_ipv4 = ip[12..16].try_into().expect("validated IPv4 header");
    let destination_ipv4 = ip[16..20].try_into().expect("validated IPv4 header");
    Ok(Some(TransportSlice {
        offset: ip_start + header_length + transport_header_length,
        source_ipv4,
        destination_ipv4,
        source_port,
        destination_port,
        tcp_sequence,
        tcp_syn,
        bytes,
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

    #[test]
    fn dns_udp_fixture_preserves_datagrams_ports_and_source_offsets() {
        let raw = include_bytes!("../examples/dns_udp.pcap");
        let classic = extract_udp_messages(raw).unwrap();
        let enhanced_raw = include_bytes!("../examples/dns_udp.pcapng");
        let enhanced = extract_pcapng_udp_messages(enhanced_raw).unwrap();
        let truth: serde_json::Value =
            serde_json::from_str(include_str!("../examples/dns_udp.truth.json")).unwrap();
        assert_eq!(classic.len(), 12);
        assert_eq!(enhanced.len(), classic.len());
        for ((left, right), case) in classic
            .iter()
            .zip(&enhanced)
            .zip(truth["cases"].as_array().unwrap())
        {
            assert_eq!(left.bytes, right.bytes);
            assert_eq!(left.timestamp_ns, right.timestamp_ns);
            assert_eq!(left.source_port, right.source_port);
            assert_eq!(left.destination_port, right.destination_port);
            assert_eq!(
                left.bytes.len() as u64 + 8,
                case["udp_length"].as_u64().unwrap()
            );
            assert_eq!(
                u16::from_be_bytes([left.bytes[0], left.bytes[1]]) as u64,
                case["transaction_id"].as_u64().unwrap()
            );
            assert_eq!(
                left.source_port == Some(53),
                case["response"].as_bool().unwrap()
            );
            assert_eq!(
                &raw[left.source_offset..left.source_offset + left.bytes.len()],
                left.bytes
            );
            assert_eq!(
                &enhanced_raw[right.source_offset..right.source_offset + right.bytes.len()],
                right.bytes
            );
        }
        assert!(extract_icmp_messages(raw).unwrap().is_empty());
        let mut bad_length = raw.to_vec();
        bad_length[classic[0].source_offset - 8 + 4..classic[0].source_offset - 8 + 6]
            .copy_from_slice(&0xffff_u16.to_be_bytes());
        assert!(
            extract_udp_messages(&bad_length)
                .unwrap_err()
                .contains("invalid UDP datagram length")
        );
        let first_frame_length = u32::from_le_bytes(raw[32..36].try_into().unwrap()) as usize;
        let mut no_payload = raw[40..40 + first_frame_length].to_vec();
        no_payload[16..18].copy_from_slice(&28_u16.to_be_bytes());
        no_payload[38..40].copy_from_slice(&8_u16.to_be_bytes());
        assert!(
            extract_ethernet_transport(&no_payload, Transport::Udp)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn tcp_fixture_preserves_segment_payloads_sequences_and_offsets() {
        let raw = include_bytes!("../examples/tcp_payload.pcap");
        let classic = extract_tcp_segments(raw).unwrap();
        let enhanced_raw = include_bytes!("../examples/tcp_payload.pcapng");
        let enhanced = extract_pcapng_tcp_segments(enhanced_raw).unwrap();
        let truth: serde_json::Value =
            serde_json::from_str(include_str!("../examples/tcp_payload.truth.json")).unwrap();
        assert_eq!(classic.len(), 12);
        assert_eq!(enhanced.len(), classic.len());
        assert_eq!(truth["packet_count"], 18);
        for ((left, right), case) in classic
            .iter()
            .zip(&enhanced)
            .zip(truth["cases"].as_array().unwrap())
        {
            assert_eq!(left.bytes, right.bytes);
            assert_eq!(left.timestamp_ns, right.timestamp_ns);
            assert_eq!(
                left.packet_index as u64,
                case["packet_index"].as_u64().unwrap()
            );
            assert_eq!(
                left.source_offset as u64,
                case["source_offset"].as_u64().unwrap()
            );
            assert_eq!(
                left.tcp_sequence.map(u64::from),
                case["tcp_sequence"].as_u64()
            );
            assert_eq!(
                left.bytes[4..6],
                (case["transaction_id"].as_u64().unwrap() as u16).to_be_bytes()
            );
            assert_eq!(
                left.source_port == Some(4242),
                case["response"].as_bool().unwrap()
            );
            assert_eq!(
                left.bytes,
                crate::workflow::from_hex(case["payload_hex"].as_str().unwrap()).unwrap()
            );
            assert_eq!(
                &raw[left.source_offset..left.source_offset + left.bytes.len()],
                left.bytes
            );
            assert_eq!(
                &enhanced_raw[right.source_offset..right.source_offset + right.bytes.len()],
                right.bytes
            );
        }
        assert!(extract_udp_messages(raw).unwrap().is_empty());
    }

    #[test]
    fn tcp_rejects_invalid_offsets_and_skips_fragmented_ipv4() {
        let raw = include_bytes!("../examples/tcp_payload.pcap");
        let first = extract_tcp_segments(raw).unwrap().remove(0);
        let header_start = first.source_offset - 24;
        let mut bad_offset = raw.to_vec();
        bad_offset[header_start + 12] = 0x40;
        assert!(
            extract_tcp_segments(&bad_offset)
                .unwrap_err()
                .contains("TCP data offset")
        );
        bad_offset[header_start + 12] = 0xf0;
        assert!(
            extract_tcp_segments(&bad_offset)
                .unwrap_err()
                .contains("TCP data offset")
        );
        let mut truncated = raw.to_vec();
        let ip_start = header_start - 20;
        truncated[ip_start + 2..ip_start + 4].copy_from_slice(&39_u16.to_be_bytes());
        assert!(
            extract_tcp_segments(&truncated)
                .unwrap_err()
                .contains("truncated TCP header")
        );
        let mut fragmented = raw.to_vec();
        fragmented[ip_start + 6..ip_start + 8].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert_eq!(extract_tcp_segments(&fragmented).unwrap().len(), 11);
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

    #[test]
    fn pcapng_matches_classic_capture_and_preserves_source_spans() {
        let classic = extract_icmp_messages(include_bytes!("../examples/icmp_echo.pcap")).unwrap();
        let raw = include_bytes!("../examples/icmp_echo.pcapng");
        let enhanced = extract_pcapng_icmp_messages(raw).unwrap();
        assert_eq!(enhanced.len(), 24);
        for (left, right) in classic.iter().zip(&enhanced) {
            assert_eq!(left.packet_index, right.packet_index);
            assert_eq!(left.timestamp_ns, right.timestamp_ns);
            assert_eq!(left.source_ipv4, right.source_ipv4);
            assert_eq!(left.destination_ipv4, right.destination_ipv4);
            assert_eq!(left.bytes, right.bytes);
            assert_eq!(
                &raw[right.source_offset..right.source_offset + right.bytes.len()],
                right.bytes
            );
        }
        assert!(extract_pcapng_icmp_messages(&raw[..raw.len() - 1]).is_err());
    }

    fn block_le(block_type: u32, body: &[u8]) -> Vec<u8> {
        let mut padded = body.to_vec();
        padded.resize(padded.len().div_ceil(4) * 4, 0);
        let length = (12 + padded.len()) as u32;
        let mut block = Vec::new();
        block.extend(block_type.to_le_bytes());
        block.extend(length.to_le_bytes());
        block.extend(padded);
        block.extend(length.to_le_bytes());
        block
    }

    fn block_be(block_type: u32, body: &[u8]) -> Vec<u8> {
        let mut padded = body.to_vec();
        padded.resize(padded.len().div_ceil(4) * 4, 0);
        let length = (12 + padded.len()) as u32;
        let mut block = Vec::new();
        block.extend(block_type.to_be_bytes());
        block.extend(length.to_be_bytes());
        block.extend(padded);
        block.extend(length.to_be_bytes());
        block
    }

    fn vlan_frame(frame: &[u8], tag_types: &[u16]) -> Vec<u8> {
        let mut tagged = frame[..12].to_vec();
        for tag_type in tag_types {
            tagged.extend(tag_type.to_be_bytes());
            tagged.extend(1_u16.to_be_bytes());
        }
        tagged.extend(&frame[12..]);
        tagged
    }

    fn classic_packet_header(raw: &[u8], packet_index: usize) -> usize {
        let mut packet_header = 24;
        for _ in 0..packet_index {
            let length = u32::from_le_bytes(
                raw[packet_header + 8..packet_header + 12]
                    .try_into()
                    .unwrap(),
            ) as usize;
            packet_header += 16 + length;
        }
        packet_header
    }

    fn tagged_classic_packet(raw: &[u8], packet_index: usize, tag_types: &[u16]) -> Vec<u8> {
        let packet_header = classic_packet_header(raw, packet_index);
        let frame_length = u32::from_le_bytes(
            raw[packet_header + 8..packet_header + 12]
                .try_into()
                .unwrap(),
        ) as usize;
        let frame = &raw[packet_header + 16..packet_header + 16 + frame_length];
        let tagged = vlan_frame(frame, tag_types);
        let mut classic = raw[..24].to_vec();
        classic.extend(&raw[packet_header..packet_header + 16]);
        classic[32..36].copy_from_slice(&(tagged.len() as u32).to_le_bytes());
        classic[36..40].copy_from_slice(&(tagged.len() as u32).to_le_bytes());
        classic.extend(tagged);
        classic
    }

    #[test]
    fn vlan_tags_preserve_udp_and_tcp_payload_offsets() {
        let dns = include_bytes!("../examples/dns_udp.pcap");
        let expected_udp = extract_udp_messages(dns).unwrap().remove(0);
        let tagged_udp = tagged_classic_packet(dns, expected_udp.packet_index, &[0x8100]);
        let udp = extract_udp_messages(&tagged_udp).unwrap().remove(0);
        assert_eq!(udp.bytes, expected_udp.bytes);
        assert_eq!(udp.source_port, expected_udp.source_port);
        assert_eq!(udp.destination_port, expected_udp.destination_port);
        assert_eq!(udp.source_offset, expected_udp.source_offset + 4);
        assert_eq!(
            &tagged_udp[udp.source_offset..udp.source_offset + udp.bytes.len()],
            udp.bytes
        );

        let tcp_raw = include_bytes!("../examples/tcp_payload.pcap");
        let expected_tcp = extract_tcp_segments(tcp_raw).unwrap().remove(0);
        let tagged_tcp =
            tagged_classic_packet(tcp_raw, expected_tcp.packet_index, &[0x88a8, 0x8100]);
        let tcp = extract_tcp_segments(&tagged_tcp).unwrap().remove(0);
        assert_eq!(tcp.bytes, expected_tcp.bytes);
        assert_eq!(tcp.tcp_sequence, expected_tcp.tcp_sequence);
        assert_eq!(tcp.source_port, expected_tcp.source_port);
        assert_eq!(tcp.destination_port, expected_tcp.destination_port);
        let original_frame_start = classic_packet_header(tcp_raw, expected_tcp.packet_index) + 16;
        assert_eq!(
            tcp.source_offset,
            40 + expected_tcp.source_offset - original_frame_start + 8
        );
        assert_eq!(
            &tagged_tcp[tcp.source_offset..tcp.source_offset + tcp.bytes.len()],
            tcp.bytes
        );
    }

    #[test]
    fn vlan_tagged_frames_preserve_icmp_bytes_and_file_offsets() {
        let original = include_bytes!("../examples/icmp_echo.pcap");
        let frame_length = u32::from_le_bytes(original[32..36].try_into().unwrap()) as usize;
        let frame = &original[40..40 + frame_length];
        let expected = extract_icmp_messages(original).unwrap().remove(0);

        for tag_types in [
            vec![0x8100],
            vec![0x88a8, 0x8100],
            vec![0x9100, 0x88a8, 0x8100, 0x8100],
        ] {
            let tagged = vlan_frame(frame, &tag_types);
            let mut classic = original[..40].to_vec();
            classic[32..36].copy_from_slice(&(tagged.len() as u32).to_le_bytes());
            classic[36..40].copy_from_slice(&(tagged.len() as u32).to_le_bytes());
            classic.extend(&tagged);
            let message = extract_icmp_messages(&classic).unwrap().remove(0);
            assert_eq!(message.bytes, expected.bytes);
            assert_eq!(
                message.source_offset,
                expected.source_offset + 4 * tag_types.len()
            );
            assert_eq!(
                &classic[message.source_offset..message.source_offset + message.bytes.len()],
                message.bytes
            );

            let mut enhanced = block_le(
                0x0a0d0d0a,
                &[
                    0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff,
                ],
            );
            enhanced.extend(block_le(1, &[1, 0, 0, 0, 0xff, 0xff, 0, 0]));
            let mut packet = vec![0; 12];
            packet.extend((tagged.len() as u32).to_le_bytes());
            packet.extend((tagged.len() as u32).to_le_bytes());
            packet.extend(&tagged);
            enhanced.extend(block_le(6, &packet));
            let ng_message = extract_pcapng_icmp_messages(&enhanced).unwrap().remove(0);
            assert_eq!(ng_message.bytes, expected.bytes);
            assert_eq!(
                &enhanced
                    [ng_message.source_offset..ng_message.source_offset + ng_message.bytes.len()],
                ng_message.bytes
            );
        }

        let partial = vlan_frame(frame, &[0x8100]);
        assert_eq!(
            extract_ethernet_transport(&partial[..16], Transport::Icmp).unwrap_err(),
            "truncated Ethernet VLAN tag"
        );
        assert!(
            extract_ethernet_transport(&vlan_frame(frame, &[0x8100; 5]), Transport::Icmp)
                .unwrap_err()
                .contains("more than four VLAN tags")
        );
    }

    #[test]
    fn pcapng_honors_nanosecond_resolution_and_interface_offset() {
        let classic = include_bytes!("../examples/icmp_echo.pcap");
        let frame_length = u32::from_le_bytes(classic[32..36].try_into().unwrap()) as usize;
        let frame = &classic[40..40 + frame_length];
        let mut section = Vec::new();
        section.extend(0x1a2b3c4d_u32.to_le_bytes());
        section.extend(1_u16.to_le_bytes());
        section.extend(0_u16.to_le_bytes());
        section.extend((-1_i64).to_le_bytes());
        let mut idb = Vec::new();
        idb.extend(1_u16.to_le_bytes());
        idb.extend(0_u16.to_le_bytes());
        idb.extend(65535_u32.to_le_bytes());
        idb.extend(9_u16.to_le_bytes());
        idb.extend(1_u16.to_le_bytes());
        idb.extend([9, 0, 0, 0]);
        idb.extend(14_u16.to_le_bytes());
        idb.extend(8_u16.to_le_bytes());
        idb.extend(1_i64.to_le_bytes());
        let ticks = 1_700_000_000_000_000_123_u64;
        let mut epb = Vec::new();
        epb.extend(0_u32.to_le_bytes());
        epb.extend(((ticks >> 32) as u32).to_le_bytes());
        epb.extend((ticks as u32).to_le_bytes());
        epb.extend((frame_length as u32).to_le_bytes());
        epb.extend((frame_length as u32).to_le_bytes());
        epb.extend(frame);
        let raw = [
            block_le(0x0a0d0d0a, &section),
            block_le(1, &idb),
            block_le(6, &epb),
        ]
        .concat();
        let messages = extract_pcapng_icmp_messages(&raw).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].timestamp_ns, ticks + 1_000_000_000);
        assert_eq!(messages[0].bytes[0], 8);
    }

    #[test]
    fn pcapng_resets_interfaces_across_big_endian_section() {
        let classic = include_bytes!("../examples/icmp_echo.pcap");
        let frame_length = u32::from_le_bytes(classic[32..36].try_into().unwrap()) as usize;
        let frame = &classic[40..40 + frame_length];
        let mut section = Vec::new();
        section.extend(0x1a2b3c4d_u32.to_be_bytes());
        section.extend(1_u16.to_be_bytes());
        section.extend(0_u16.to_be_bytes());
        section.extend((-1_i64).to_be_bytes());
        let mut idb = Vec::new();
        idb.extend(1_u16.to_be_bytes());
        idb.extend(0_u16.to_be_bytes());
        idb.extend(65535_u32.to_be_bytes());
        let mut epb = Vec::new();
        epb.extend(0_u32.to_be_bytes());
        epb.extend(0_u32.to_be_bytes());
        epb.extend(2_000_000_u32.to_be_bytes());
        epb.extend((frame_length as u32).to_be_bytes());
        epb.extend((frame_length as u32).to_be_bytes());
        epb.extend(frame);
        let mut raw = include_bytes!("../examples/icmp_echo.pcapng").to_vec();
        raw.extend(block_be(0x0a0d0d0a, &section));
        raw.extend(block_be(1, &idb));
        raw.extend(block_be(6, &epb));
        let messages = extract_pcapng_icmp_messages(&raw).unwrap();
        assert_eq!(messages.len(), 25);
        assert_eq!(messages[24].packet_index, 24);
        assert_eq!(messages[24].timestamp_ns, 2_000_000_000);
        assert_eq!(messages[24].bytes[0], 8);
    }
}
