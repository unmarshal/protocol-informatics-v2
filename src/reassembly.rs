//! Conservative TCP reassembly within one capture and one directional IPv4 flow.
//! A sequence gap starts another observation. Conflicting overlap rejects the capture.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::pcap::TransportMessage;

const MAX_REASSEMBLED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub message_start: usize,
    pub message_end: usize,
    pub packet_index: usize,
    pub file_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledMessage {
    pub source_ipv4: [u8; 4],
    pub destination_ipv4: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
    pub tcp_sequence: u32,
    pub first_packet_index: usize,
    pub first_timestamp_ns: u64,
    pub gap_before: bool,
    pub bytes: Vec<u8>,
    pub source_spans: Vec<SourceSpan>,
}

type FlowKey = ([u8; 4], [u8; 4], u16, u16);

fn payload_sequence(segment: &TransportMessage) -> u32 {
    segment
        .tcp_sequence
        .expect("TCP segment has a sequence number")
        .wrapping_add(u32::from(segment.tcp_syn))
}

fn start_run(segment: &TransportMessage, gap_before: bool) -> ReassembledMessage {
    ReassembledMessage {
        source_ipv4: segment.source_ipv4,
        destination_ipv4: segment.destination_ipv4,
        source_port: segment.source_port.expect("TCP segment has a source port"),
        destination_port: segment
            .destination_port
            .expect("TCP segment has a destination port"),
        tcp_sequence: payload_sequence(segment),
        first_packet_index: segment.packet_index,
        first_timestamp_ns: segment.timestamp_ns,
        gap_before,
        bytes: segment.bytes.clone(),
        source_spans: vec![SourceSpan {
            message_start: 0,
            message_end: segment.bytes.len(),
            packet_index: segment.packet_index,
            file_offset: segment.source_offset,
        }],
    }
}

/// Reassemble bytes from each directional 4-tuple independently. Sequence arithmetic
/// accepts a window smaller than 2^31 bytes around the first observed segment.
pub fn reassemble_tcp_segments(
    segments: &[TransportMessage],
) -> Result<Vec<ReassembledMessage>, String> {
    let mut flows: BTreeMap<FlowKey, Vec<&TransportMessage>> = BTreeMap::new();
    for segment in segments {
        if segment.tcp_sequence.is_none()
            || segment.source_port.is_none()
            || segment.destination_port.is_none()
            || segment.bytes.is_empty()
        {
            return Err("reassembly requires nonempty TCP segment payloads".into());
        }
        if segment.bytes.len() > MAX_REASSEMBLED_BYTES {
            return Err("TCP segment payload exceeds 32 MiB".into());
        }
        flows
            .entry((
                segment.source_ipv4,
                segment.destination_ipv4,
                segment.source_port.unwrap(),
                segment.destination_port.unwrap(),
            ))
            .or_default()
            .push(segment);
    }
    let mut output = Vec::new();
    for (flow, segments) in flows {
        let reference = payload_sequence(segments[0]);
        let mut ordered: Vec<_> = segments
            .into_iter()
            .map(|segment| {
                (
                    payload_sequence(segment).wrapping_sub(reference) as i32 as i64,
                    segment,
                )
            })
            .collect();
        ordered.sort_by_key(|(start, segment)| (*start, segment.packet_index));
        let mut current: Option<(i64, ReassembledMessage)> = None;
        for (start, segment) in ordered {
            let Some((run_start, run)) = current.as_mut() else {
                current = Some((start, start_run(segment, false)));
                continue;
            };
            let relative = usize::try_from(start - *run_start)
                .map_err(|_| "TCP sequence window exceeds supported range".to_string())?;
            if relative > run.bytes.len() {
                output.push(current.take().expect("run exists").1);
                current = Some((start, start_run(segment, true)));
                continue;
            }
            let overlap = (run.bytes.len() - relative).min(segment.bytes.len());
            if run.bytes[relative..relative + overlap] != segment.bytes[..overlap] {
                return Err(format!(
                    "conflicting TCP overlap in flow {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} near sequence {}",
                    flow.0[0],
                    flow.0[1],
                    flow.0[2],
                    flow.0[3],
                    flow.2,
                    flow.1[0],
                    flow.1[1],
                    flow.1[2],
                    flow.1[3],
                    flow.3,
                    payload_sequence(segment)
                ));
            }
            let suffix = &segment.bytes[overlap..];
            if !suffix.is_empty() {
                if run.bytes.len() + suffix.len() > MAX_REASSEMBLED_BYTES {
                    return Err("reassembled TCP run exceeds 32 MiB".into());
                }
                let message_start = run.bytes.len();
                run.bytes.extend_from_slice(suffix);
                run.source_spans.push(SourceSpan {
                    message_start,
                    message_end: run.bytes.len(),
                    packet_index: segment.packet_index,
                    file_offset: segment.source_offset + overlap,
                });
                run.first_packet_index = run.first_packet_index.min(segment.packet_index);
                run.first_timestamp_ns = run.first_timestamp_ns.min(segment.timestamp_ns);
            }
        }
        if let Some((_, run)) = current {
            output.push(run);
        }
    }
    output.sort_by_key(|run| (run.first_packet_index, run.source_ipv4, run.source_port));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(index: usize, sequence: u32, bytes: &[u8]) -> TransportMessage {
        TransportMessage {
            packet_index: index,
            timestamp_ns: index as u64,
            source_offset: 100 + index * 20,
            source_ipv4: [192, 0, 2, 1],
            destination_ipv4: [192, 0, 2, 2],
            source_port: Some(1234),
            destination_port: Some(4321),
            tcp_sequence: Some(sequence),
            tcp_syn: false,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn reorders_deduplicates_and_preserves_each_contributing_span() {
        let parts = [
            segment(0, 0xffff_fffe, b"cdef"),
            segment(1, 0xffff_fffc, b"ab"),
            segment(2, 0, b"ef"),
            segment(3, 2, b"gh"),
        ];
        let runs = reassemble_tcp_segments(&parts).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].bytes, b"abcdefgh");
        assert_eq!(runs[0].tcp_sequence, 0xffff_fffc);
        assert_eq!(runs[0].source_spans.len(), 3);
        assert_eq!(runs[0].source_spans[0].packet_index, 1);
        assert_eq!(runs[0].source_spans[1].packet_index, 0);
        assert_eq!(runs[0].source_spans[2].packet_index, 3);
    }

    #[test]
    fn gaps_split_runs_and_conflicting_overlap_is_rejected() {
        let parts = [segment(0, 100, b"abc"), segment(1, 105, b"fgh")];
        let runs = reassemble_tcp_segments(&parts).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].bytes, b"abc");
        assert_eq!(runs[1].bytes, b"fgh");
        assert!(runs[1].gap_before);
        let conflict = [segment(0, 100, b"abc"), segment(1, 102, b"Xde")];
        assert!(
            reassemble_tcp_segments(&conflict)
                .unwrap_err()
                .contains("conflicting TCP overlap")
        );
    }

    #[test]
    fn syn_consumes_a_sequence_number_before_payload_bytes() {
        let mut first = segment(0, 99, b"ab");
        first.tcp_syn = true;
        let second = segment(1, 102, b"cd");
        let runs = reassemble_tcp_segments(&[first, second]).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].tcp_sequence, 100);
        assert_eq!(runs[0].bytes, b"abcd");
    }

    #[test]
    fn parser_and_reassembler_apply_syn_offset_to_data_bearing_segment() {
        let mut raw = include_bytes!("../examples/tcp_stream.pcap").to_vec();
        let original = crate::pcap::extract_tcp_segments(&raw).unwrap();
        let first = &original[0];
        let second = &original[1];
        let first_header = first.source_offset - 20;
        let second_header = second.source_offset - 20;
        raw[first_header + 13] |= 0x02;
        raw[second_header + 4..second_header + 8]
            .copy_from_slice(&(second.tcp_sequence.unwrap() + 1).to_be_bytes());
        let parsed = crate::pcap::extract_tcp_segments(&raw).unwrap();
        assert!(parsed[0].tcp_syn);
        let runs = reassemble_tcp_segments(&parsed).unwrap();
        assert_eq!(runs[0].tcp_sequence, first.tcp_sequence.unwrap() + 1);
        assert_eq!(runs[0].bytes, b"PI2Q\0\0\x01a");
    }

    #[test]
    fn split_fixture_reassembles_classic_and_pcapng_with_exact_provenance() {
        let raw = include_bytes!("../examples/tcp_stream.pcap");
        let enhanced_raw = include_bytes!("../examples/tcp_stream.pcapng");
        let classic =
            reassemble_tcp_segments(&crate::pcap::extract_tcp_segments(raw).unwrap()).unwrap();
        let enhanced = reassemble_tcp_segments(
            &crate::pcap::extract_pcapng_tcp_segments(enhanced_raw).unwrap(),
        )
        .unwrap();
        let truth: serde_json::Value =
            serde_json::from_str(include_str!("../examples/tcp_stream.truth.json")).unwrap();
        assert_eq!(classic.len(), 12);
        assert_eq!(enhanced.len(), classic.len());
        for (case_index, case) in truth["cases"].as_array().unwrap().iter().enumerate() {
            let request = &classic[case_index * 2];
            let response = &classic[case_index * 2 + 1];
            assert_eq!(
                request.bytes,
                crate::workflow::from_hex(case["request_hex"].as_str().unwrap()).unwrap()
            );
            assert_eq!(
                response.bytes,
                crate::workflow::from_hex(case["response_hex"].as_str().unwrap()).unwrap()
            );
            assert_eq!(request.source_spans.len(), 2);
            assert_eq!(request.source_spans[0].message_end, 5);
            assert_eq!(request.source_spans[1].message_start, 5);
            assert_eq!(
                u16::from_be_bytes(request.bytes[4..6].try_into().unwrap()) as u64,
                case["transaction_id"].as_u64().unwrap()
            );
            assert_eq!(request.bytes, enhanced[case_index * 2].bytes);
            for (run, capture) in [
                (request, raw.as_slice()),
                (response, raw.as_slice()),
                (&enhanced[case_index * 2], enhanced_raw.as_slice()),
                (&enhanced[case_index * 2 + 1], enhanced_raw.as_slice()),
            ] {
                for span in &run.source_spans {
                    assert_eq!(
                        &capture[span.file_offset
                            ..span.file_offset + span.message_end - span.message_start],
                        &run.bytes[span.message_start..span.message_end],
                    );
                }
            }
        }
        assert!(
            classic[3 * 2].source_spans[0].packet_index
                > classic[3 * 2].source_spans[1].packet_index
        );
    }
}
