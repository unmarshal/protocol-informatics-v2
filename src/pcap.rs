//! Ethernet IPv4/IPv6 transport extraction from classic pcap and pcapng.
//! ICMP messages, UDP datagrams, and TCP segment payloads share capture parsing and retain exact
//! byte offsets into the original capture. Ethernet VLAN tags are unwrapped before IP parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportMessage {
    pub packet_index: usize,
    pub timestamp_ns: u64,
    /// Offset of the extracted bytes in the original capture file.
    pub source_offset: usize,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
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
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    tcp_sequence: Option<u32>,
    tcp_syn: bool,
    bytes: &'a [u8],
}

#[derive(Clone, Copy)]
enum Transport {
    Icmp,
    Icmpv6,
    Udp,
    Tcp,
}

impl Transport {
    fn protocol(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Icmpv6 => 58,
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

pub fn extract_icmpv6_messages(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcap_messages(data, Transport::Icmpv6)
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

pub fn extract_pcapng_icmpv6_messages(data: &[u8]) -> Result<Vec<TransportMessage>, String> {
    extract_pcapng_messages(data, Transport::Icmpv6)
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
            source_ip: message.source_ip,
            destination_ip: message.destination_ip,
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
    let ip = &frame[ip_start..];
    let (source_ip, destination_ip, payload, transport_offset) = match ether_type {
        0x0800 => {
            if matches!(transport, Transport::Icmpv6) {
                return Ok(None);
            }
            if ip.len() < 20 {
                return Err("truncated IPv4 header".into());
            }
            let header_length = (ip[0] & 0x0f) as usize * 4;
            if ip[0] >> 4 != 4 || header_length < 20 || ip.len() < header_length {
                return Err("invalid IPv4 header".into());
            }
            let total_length = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            if total_length < header_length || ip.len() < total_length {
                return Err("truncated IPv4 payload".into());
            }
            let fragment_bits = u16::from_be_bytes([ip[6], ip[7]]);
            if ip[9] != transport.protocol() || fragment_bits & 0x3fff != 0 {
                return Ok(None);
            }
            let source = IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&ip[12..16]).expect("validated IPv4 header"),
            ));
            let destination = IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&ip[16..20]).expect("validated IPv4 header"),
            ));
            (
                source,
                destination,
                &ip[header_length..total_length],
                header_length,
            )
        }
        0x86dd => {
            if matches!(transport, Transport::Icmp) {
                return Ok(None);
            }
            if ip.len() < 40 {
                return Err("truncated IPv6 header".into());
            }
            if ip[0] >> 4 != 6 {
                return Err("invalid IPv6 header".into());
            }
            let payload_length = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            if payload_length == 0 {
                return Ok(None); // IPv6 jumbograms are not supported.
            }
            let packet_end = 40 + payload_length;
            if ip.len() < packet_end {
                return Err("truncated IPv6 payload".into());
            }
            let mut next_header = ip[6];
            let mut cursor = 40;
            let mut extension_count = 0;
            while matches!(next_header, 0 | 43 | 60) {
                if extension_count == 8 {
                    return Err("IPv6 extension header chain exceeds eight headers".into());
                }
                if cursor + 2 > packet_end {
                    return Err("truncated IPv6 extension header".into());
                }
                let extension_length = (usize::from(ip[cursor + 1]) + 1) * 8;
                if cursor + extension_length > packet_end {
                    return Err("truncated IPv6 extension header".into());
                }
                next_header = ip[cursor];
                cursor += extension_length;
                extension_count += 1;
            }
            if next_header == 44 {
                if cursor + 8 > packet_end {
                    return Err("truncated IPv6 fragment header".into());
                }
                return Ok(None); // Even atomic fragments need explicit policy before extraction.
            }
            if next_header != transport.protocol() {
                return Ok(None);
            }
            let source = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&ip[8..24]).expect("validated IPv6 header"),
            ));
            let destination = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&ip[24..40]).expect("validated IPv6 header"),
            ));
            (source, destination, &ip[cursor..packet_end], cursor)
        }
        _ => return Ok(None),
    };
    let (bytes, source_port, destination_port, tcp_sequence, tcp_syn, transport_header_length) =
        match transport {
            Transport::Icmp | Transport::Icmpv6 => {
                let minimum_length = if matches!(transport, Transport::Icmpv6) {
                    4
                } else {
                    8
                };
                if payload.len() < minimum_length {
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
    Ok(Some(TransportSlice {
        offset: ip_start + transport_offset + transport_header_length,
        source_ip,
        destination_ip,
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
    fn ipv6_fixtures_preserve_transport_payloads_and_offsets() {
        let classic = include_bytes!("../examples/ipv6_mixed.pcap");
        let enhanced = include_bytes!("../examples/ipv6_mixed.pcapng");
        let truth: serde_json::Value =
            serde_json::from_str(include_str!("../examples/ipv6_mixed.truth.json")).unwrap();
        let cases = truth["cases"].as_array().unwrap();
        for (kind, classic_messages, enhanced_messages, expected_count) in [
            (
                "icmpv6",
                extract_icmpv6_messages(classic).unwrap(),
                extract_pcapng_icmpv6_messages(enhanced).unwrap(),
                12,
            ),
            (
                "udp",
                extract_udp_messages(classic).unwrap(),
                extract_pcapng_udp_messages(enhanced).unwrap(),
                8,
            ),
            (
                "tcp",
                extract_tcp_segments(classic).unwrap(),
                extract_pcapng_tcp_segments(enhanced).unwrap(),
                4,
            ),
        ] {
            let expected: Vec<_> = cases.iter().filter(|case| case["kind"] == kind).collect();
            assert_eq!(classic_messages.len(), expected_count);
            assert_eq!(enhanced_messages.len(), expected_count);
            for ((left, right), case) in classic_messages
                .iter()
                .zip(&enhanced_messages)
                .zip(expected)
            {
                assert_eq!(left.packet_index as u64, case["packet_index"]);
                assert_eq!(left.timestamp_ns, case["timestamp_ns"]);
                assert_eq!(left.source_ip.to_string(), case["source_ip"]);
                assert_eq!(left.destination_ip.to_string(), case["destination_ip"]);
                assert_eq!(left.bytes, right.bytes);
                assert_eq!(crate::workflow::to_hex(&left.bytes), case["bytes_hex"]);
                assert_eq!(left.source_offset as u64, case["pcap_source_offset"]);
                assert_eq!(right.source_offset as u64, case["pcapng_source_offset"]);
                assert_eq!(
                    &classic[left.source_offset..left.source_offset + left.bytes.len()],
                    left.bytes
                );
                assert_eq!(
                    &enhanced[right.source_offset..right.source_offset + right.bytes.len()],
                    right.bytes
                );
            }
        }
        assert!(extract_icmp_messages(classic).unwrap().is_empty());

        let with_option = extract_icmpv6_messages(classic).unwrap()[6].source_offset;
        let mut bad_option = classic.to_vec();
        bad_option[with_option - 7] = 255;
        assert!(
            extract_icmpv6_messages(&bad_option)
                .unwrap_err()
                .contains("truncated IPv6 extension header")
        );

        for option_kind in [43, 60] {
            let mut other_option = classic.to_vec();
            other_option[with_option - 8 - 40 + 6] = option_kind;
            assert_eq!(extract_icmpv6_messages(&other_option).unwrap().len(), 12);
        }

        let mut fragmented = classic.to_vec();
        fragmented[40 + 14 + 6] = 44;
        assert_eq!(extract_icmpv6_messages(&fragmented).unwrap().len(), 11);

        let mut bad_length = classic.to_vec();
        bad_length[40 + 14 + 4..40 + 14 + 6].copy_from_slice(&9_u16.to_be_bytes());
        assert!(
            extract_icmpv6_messages(&bad_length)
                .unwrap_err()
                .contains("truncated IPv6 payload")
        );
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
            assert_eq!(left.source_ip, right.source_ip);
            assert_eq!(left.destination_ip, right.destination_ip);
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcapngInterfaceQuality {
    pub section_index: usize,
    pub interface_id: usize,
    pub link_type: u16,
    pub snapshot_length: u32,
    pub captured_packet_count: u64,
    pub received_packets: Option<u64>,
    pub dropped_packets: Option<u64>,
    pub os_dropped_packets: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PcapngQuality {
    pub captured_packet_count: u64,
    pub interfaces: Vec<PcapngInterfaceQuality>,
}

/// IDB and latest ISB counters, scoped to their section/interface. Missing is
/// unknown, including when an ISB omits an option; zero is retained as zero.
pub fn pcapng_quality(data: &[u8]) -> Result<PcapngQuality, String> {
    let mut result = PcapngQuality {
        captured_packet_count: 0,
        interfaces: Vec::new(),
    };
    let mut offset = 0;
    let mut endian = None;
    let mut section_count = 0;
    let mut section_start = 0;
    while offset < data.len() {
        if data.len() - offset < 12 {
            return Err("truncated pcapng block".into());
        }
        let section = data[offset..offset + 4] == [10, 13, 13, 10];
        if section {
            if data.len() - offset < 28 {
                return Err("truncated section".into());
            }
            endian = Some(match &data[offset + 8..offset + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                _ => return Err("invalid byte order".into()),
            });
        }
        let e = endian.ok_or("missing pcapng section")?;
        let length = e.u32(&data[offset + 4..offset + 8]) as usize;
        if length < 12 || !length.is_multiple_of(4) || length > data.len() - offset {
            return Err("invalid pcapng block size".into());
        }
        let end = offset + length;
        if e.u32(&data[end - 4..end]) as usize != length {
            return Err("invalid block trailer".into());
        }
        let body = &data[offset + 8..end - 4];
        match e.u32(&data[offset..offset + 4]) {
            0x0a0d0d0a => {
                if body.len() < 16 || e.u16(&body[4..6]) != 1 {
                    return Err("unsupported section".into());
                }
                section_start = result.interfaces.len();
                section_count += 1;
            }
            1 => {
                if body.len() < 8 {
                    return Err("truncated IDB".into());
                }
                result.interfaces.push(PcapngInterfaceQuality {
                    section_index: section_count - 1,
                    interface_id: result.interfaces.len() - section_start,
                    link_type: e.u16(&body[..2]),
                    snapshot_length: e.u32(&body[4..8]),
                    captured_packet_count: 0,
                    received_packets: None,
                    dropped_packets: None,
                    os_dropped_packets: None,
                });
            }
            6 | 5 => {
                let block_type = e.u32(&data[offset..offset + 4]);
                if body.len() < if block_type == 6 { 20 } else { 12 } {
                    return Err("truncated EPB/ISB".into());
                }
                let index = section_start
                    .checked_add(e.u32(&body[..4]) as usize)
                    .ok_or("interface overflow")?;
                let interface = result
                    .interfaces
                    .get_mut(index)
                    .ok_or("unknown interface")?;
                if block_type == 6 {
                    let captured = e.u32(&body[12..16]) as usize;
                    if captured > body.len() - 20 || captured > e.u32(&body[16..20]) as usize {
                        return Err("invalid packet length".into());
                    }
                    interface.captured_packet_count += 1;
                    result.captured_packet_count += 1;
                } else {
                    let mut options = &body[12..];
                    interface.received_packets = None;
                    interface.dropped_packets = None;
                    interface.os_dropped_packets = None;
                    while !options.is_empty() {
                        if options.len() < 4 {
                            return Err("truncated ISB option".into());
                        }
                        let code = e.u16(&options[..2]);
                        let len = e.u16(&options[2..4]) as usize;
                        options = &options[4..];
                        if code == 0 {
                            if len != 0 {
                                return Err("invalid option terminator".into());
                            }
                            break;
                        }
                        let padded = (len + 3) & !3;
                        if padded > options.len() {
                            return Err("invalid ISB option length".into());
                        }
                        if matches!(code, 4 | 5 | 7) {
                            if len != 8 {
                                return Err("invalid ISB counter".into());
                            }
                            let bytes: [u8; 8] = options[..8].try_into().unwrap();
                            let value = match e {
                                Endian::Little => u64::from_le_bytes(bytes),
                                Endian::Big => u64::from_be_bytes(bytes),
                            };
                            match code {
                                4 => interface.received_packets = Some(value),
                                5 => interface.dropped_packets = Some(value),
                                7 => interface.os_dropped_packets = Some(value),
                                _ => unreachable!(),
                            }
                        }
                        options = &options[padded..];
                    }
                }
            }
            2 | 3 => return Err("legacy packet blocks unsupported".into()),
            _ => {}
        }
        offset = end;
    }
    if endian.is_none() {
        return Err("missing pcapng section".into());
    }
    Ok(result)
}

#[cfg(test)]
mod quality_tests {
    use super::*;
    fn block(kind: u32, body: &[u8], big: bool) -> Vec<u8> {
        let word = |n: u32| {
            if big {
                n.to_be_bytes()
            } else {
                n.to_le_bytes()
            }
        };
        let len = body.len() as u32 + 12;
        [
            word(kind).as_slice(),
            word(len).as_slice(),
            body,
            word(len).as_slice(),
        ]
        .concat()
    }
    fn section(big: bool) -> Vec<u8> {
        let body = if big {
            [
                0x1a, 0x2b, 0x3c, 0x4d, 0, 1, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
            ]
        } else {
            [
                0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
            ]
        };
        block(0x0a0d0d0a, &body, big)
    }
    #[test]
    fn statistics_preserve_zero_unknown_sections_and_endianness() {
        let mut raw = Vec::new();
        for big in [false, true] {
            raw.extend(section(big));
            raw.extend(block(
                1,
                if big {
                    &[0, 1, 0, 0, 0, 0, 255, 255]
                } else {
                    &[1, 0, 0, 0, 255, 255, 0, 0]
                },
                big,
            ));
            let mut stats = vec![0; 12];
            stats.extend(if big { [0, 5, 0, 8] } else { [5, 0, 8, 0] });
            stats.extend([0; 8]);
            stats.extend(if big { [0, 7, 0, 8] } else { [7, 0, 8, 0] });
            stats.extend(if big {
                9_u64.to_be_bytes()
            } else {
                9_u64.to_le_bytes()
            });
            raw.extend(block(5, &stats, big));
        }
        let quality = pcapng_quality(&raw).unwrap();
        assert_eq!(quality.interfaces.len(), 2);
        for (i, iface) in quality.interfaces.iter().enumerate() {
            assert_eq!(iface.section_index, i);
            assert_eq!(iface.interface_id, 0);
            assert_eq!(iface.snapshot_length, 65535);
            assert_eq!(iface.link_type, 1);
            assert_eq!(iface.dropped_packets, Some(0));
            assert_eq!(iface.received_packets, None);
            assert_eq!(iface.os_dropped_packets, Some(9));
        }
        raw.pop();
        assert!(pcapng_quality(&raw).is_err());
    }
}
