//! Bounded length-prefix framing probes and held-out structural inference.
//! A structural fit is a candidate boundary model, not proof of field meaning.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::reassembly::SourceSpan;
use crate::workflow::{Observation, State, from_hex, to_hex};

const MAX_RECORDS: usize = 256;
const MAX_SPANS_PER_RECORD: usize = 16;
const MAX_INFERENCE_OBSERVATIONS: usize = 16;
const MAX_INFERENCE_BYTES: usize = 64 * 1024;
const MAX_REPORTED_CANDIDATES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
}

impl ByteOrder {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "big" | "big_endian" => Ok(Self::BigEndian),
            "little" | "little_endian" => Ok(Self::LittleEndian),
            _ => Err("byte order must be big or little".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthMode {
    Total,
    Payload,
}

impl LengthMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "total" => Ok(Self::Total),
            "payload" => Ok(Self::Payload),
            _ => Err("length mode must be total or payload".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FramingConfig {
    pub start_offset: usize,
    pub prefix_offset: usize,
    pub prefix_width: usize,
    pub byte_order: ByteOrder,
    pub length_mode: LengthMode,
    pub alignment: usize,
}

impl FramingConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.prefix_offset > 128 {
            return Err(
                "length field offset must be at most 128 bytes from each record start".into(),
            );
        }
        if !matches!(self.prefix_width, 1 | 2 | 4) {
            return Err("length field width must be 1, 2, or 4 bytes".into());
        }
        if !matches!(self.alignment, 1 | 2 | 4 | 8) {
            return Err("record alignment must be 1, 2, 4, or 8 bytes".into());
        }
        Ok(self)
    }

    fn header_length(self) -> usize {
        self.prefix_offset + self.prefix_width
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FramingStatus {
    Complete,
    StartOutsideObservation,
    TruncatedPrefix,
    InvalidLength,
    TruncatedRecord,
    TruncatedPadding,
    RecordLimit,
}

#[derive(Debug, Clone, Serialize)]
pub struct FramedRecord {
    pub index: usize,
    pub start: usize,
    pub logical_end: usize,
    pub end: usize,
    pub length_field_start: usize,
    pub length_field_end: usize,
    pub length_value: u32,
    pub preview_hex: String,
    pub source_file_offset: Option<usize>,
    pub source_span_count: usize,
    pub source_spans_truncated: bool,
    pub source_spans: Vec<SourceSpan>,
}

#[derive(Debug, Serialize)]
pub struct FramingProbe {
    pub revision: u64,
    pub observation_id: String,
    pub coordinate_system: &'static str,
    pub observation_length: usize,
    pub config: FramingConfig,
    pub status: FramingStatus,
    pub next_offset: usize,
    pub remaining_bytes: usize,
    pub record_count: usize,
    pub records: Vec<FramedRecord>,
}

#[derive(Debug, Clone)]
struct CoreRecord {
    start: usize,
    logical_end: usize,
    end: usize,
    length_field_start: usize,
    length_field_end: usize,
    length_value: u32,
}

struct CoreProbe {
    status: FramingStatus,
    next_offset: usize,
    records: Vec<CoreRecord>,
}

fn read_length(bytes: &[u8], order: ByteOrder) -> u32 {
    match order {
        ByteOrder::BigEndian => bytes
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte)),
        ByteOrder::LittleEndian => bytes
            .iter()
            .rev()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte)),
    }
}

fn probe_bytes(bytes: &[u8], config: FramingConfig) -> CoreProbe {
    let mut offset = config.start_offset;
    let mut records = Vec::new();
    let status = loop {
        if offset == bytes.len() {
            break FramingStatus::Complete;
        }
        if records.len() == MAX_RECORDS {
            break FramingStatus::RecordLimit;
        }
        let Some(length_field_start) = offset.checked_add(config.prefix_offset) else {
            break FramingStatus::TruncatedPrefix;
        };
        let Some(length_field_end) = length_field_start.checked_add(config.prefix_width) else {
            break FramingStatus::TruncatedPrefix;
        };
        if length_field_end > bytes.len() {
            break FramingStatus::TruncatedPrefix;
        }
        let length_value = read_length(
            &bytes[length_field_start..length_field_end],
            config.byte_order,
        );
        let logical_length = match config.length_mode {
            LengthMode::Total => length_value as usize,
            LengthMode::Payload => {
                let Some(length) = config.header_length().checked_add(length_value as usize) else {
                    break FramingStatus::TruncatedRecord;
                };
                length
            }
        };
        if logical_length < config.header_length() {
            break FramingStatus::InvalidLength;
        }
        let Some(logical_end) = offset.checked_add(logical_length) else {
            break FramingStatus::TruncatedRecord;
        };
        if logical_end > bytes.len() {
            break FramingStatus::TruncatedRecord;
        }
        let Some(padded_length) = logical_length
            .checked_add(config.alignment - 1)
            .map(|length| length & !(config.alignment - 1))
        else {
            break FramingStatus::TruncatedPadding;
        };
        let Some(end) = offset.checked_add(padded_length) else {
            break FramingStatus::TruncatedPadding;
        };
        if end > bytes.len() {
            break FramingStatus::TruncatedPadding;
        }
        records.push(CoreRecord {
            start: offset,
            logical_end,
            end,
            length_field_start,
            length_field_end,
            length_value,
        });
        offset = end;
    };
    CoreProbe {
        status,
        next_offset: offset,
        records,
    }
}

fn clipped_spans(observation: &Observation, start: usize, end: usize) -> Vec<SourceSpan> {
    observation
        .source_spans
        .iter()
        .filter_map(|span| {
            let message_start = span.message_start.max(start);
            let message_end = span.message_end.min(end);
            (message_start < message_end).then(|| SourceSpan {
                message_start,
                message_end,
                packet_index: span.packet_index,
                file_offset: span.file_offset + message_start - span.message_start,
            })
        })
        .collect()
}

pub fn probe_observation(
    state: &State,
    observation_id: &str,
    config: FramingConfig,
) -> Result<FramingProbe, String> {
    let config = config.validate()?;
    let observation = state
        .observations
        .iter()
        .find(|observation| observation.id == observation_id)
        .ok_or_else(|| format!("unknown observation {observation_id}"))?;
    let bytes = from_hex(&observation.bytes_hex)?;
    if config.start_offset >= bytes.len() {
        return Err(format!(
            "start offset must be inside the {}-byte observation",
            bytes.len()
        ));
    }
    let core = probe_bytes(&bytes, config);
    let records: Vec<_> = core
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let mut source_spans = clipped_spans(observation, record.start, record.end);
            let source_span_count = source_spans.len();
            source_spans.truncate(MAX_SPANS_PER_RECORD);
            FramedRecord {
                index,
                start: record.start,
                logical_end: record.logical_end,
                end: record.end,
                length_field_start: record.length_field_start,
                length_field_end: record.length_field_end,
                length_value: record.length_value,
                preview_hex: to_hex(&bytes[record.start..record.end.min(record.start + 16)]),
                source_file_offset: observation.source_offset.map(|base| base + record.start),
                source_span_count,
                source_spans_truncated: source_span_count > MAX_SPANS_PER_RECORD,
                source_spans,
            }
        })
        .collect();
    Ok(FramingProbe {
        revision: state.revision,
        observation_id: observation_id.into(),
        coordinate_system: "observation_bytes",
        observation_length: bytes.len(),
        config,
        status: core.status,
        next_offset: core.next_offset,
        remaining_bytes: bytes.len() - core.next_offset,
        record_count: records.len(),
        records,
    })
}

#[derive(Debug, Serialize)]
pub struct FramingCounterexample {
    pub observation_id: String,
    pub status: FramingStatus,
    pub next_offset: usize,
    pub record_count: usize,
}

#[derive(Debug, Serialize)]
pub struct FramingCandidate {
    pub config: FramingConfig,
    pub discovery_records: usize,
    pub distinct_discovery_lengths: usize,
    pub validation_matches: usize,
    pub validation_records: usize,
    pub validation_counterexamples: Vec<FramingCounterexample>,
}

#[derive(Debug, Serialize)]
pub struct FramingInference {
    pub revision: u64,
    pub method: &'static str,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub discovery_count: usize,
    pub validation_count: usize,
    pub candidate_count: usize,
    pub reported_candidate_limit: usize,
    pub candidates: Vec<FramingCandidate>,
}

pub(crate) fn trial_observations<'a>(
    state: &'a State,
    trial_id: &str,
) -> Result<Vec<&'a Observation>, String> {
    let selected: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| {
            state
                .captures
                .iter()
                .any(|capture| capture.id == observation.capture_id && capture.trial_id == trial_id)
        })
        .collect();
    if selected.is_empty() || selected.len() > MAX_INFERENCE_OBSERVATIONS {
        return Err(format!(
            "trial {trial_id} needs 1 to {MAX_INFERENCE_OBSERVATIONS} observations for framing inference"
        ));
    }
    if selected
        .iter()
        .any(|observation| observation.bytes_hex.len() / 2 > MAX_INFERENCE_BYTES)
    {
        return Err(format!(
            "framing inference supports at most {MAX_INFERENCE_BYTES} bytes per observation"
        ));
    }
    Ok(selected)
}

pub fn infer_length_prefix(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
) -> Result<FramingInference, String> {
    infer_length_prefix_for_offsets(
        state,
        discovery_trial_id,
        validation_trial_id,
        &[0, 1, 2, 3, 4],
    )
}

pub(crate) fn infer_length_prefix_for_offsets(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
    prefix_offsets: &[usize],
) -> Result<FramingInference, String> {
    let discovery_trial = state
        .trials
        .iter()
        .find(|trial| trial.id == discovery_trial_id)
        .ok_or_else(|| format!("unknown trial {discovery_trial_id}"))?;
    let validation_trial = state
        .trials
        .iter()
        .find(|trial| trial.id == validation_trial_id)
        .ok_or_else(|| format!("unknown trial {validation_trial_id}"))?;
    if discovery_trial_id == validation_trial_id
        || discovery_trial.experiment_id != validation_trial.experiment_id
    {
        return Err("discovery and validation must be distinct trials of one experiment".into());
    }
    let discovery = trial_observations(state, discovery_trial_id)?;
    let validation = trial_observations(state, validation_trial_id)?;
    if discovery.len() < 2 {
        return Err("framing inference needs at least two discovery observations".into());
    }
    let discovery_bytes: Vec<_> = discovery
        .iter()
        .map(|observation| from_hex(&observation.bytes_hex))
        .collect::<Result<_, _>>()?;
    let validation_bytes: Vec<_> = validation
        .iter()
        .map(|observation| from_hex(&observation.bytes_hex))
        .collect::<Result<_, _>>()?;

    let mut candidates = Vec::new();
    for start_offset in 0..=8 {
        for &prefix_offset in prefix_offsets {
            for prefix_width in [1, 2, 4] {
                for byte_order in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
                    if prefix_width == 1 && byte_order == ByteOrder::LittleEndian {
                        continue;
                    }
                    for length_mode in [LengthMode::Total, LengthMode::Payload] {
                        for alignment in [1, 2, 4] {
                            let config = FramingConfig {
                                start_offset,
                                prefix_offset,
                                prefix_width,
                                byte_order,
                                length_mode,
                                alignment,
                            };
                            let mut values = BTreeSet::new();
                            let mut discovery_records = 0;
                            let mut fits_discovery = true;
                            for bytes in &discovery_bytes {
                                if start_offset >= bytes.len() {
                                    fits_discovery = false;
                                    break;
                                }
                                let probe = probe_bytes(bytes, config);
                                if probe.status != FramingStatus::Complete
                                    || probe.records.len() < 2
                                {
                                    fits_discovery = false;
                                    break;
                                }
                                discovery_records += probe.records.len();
                                values
                                    .extend(probe.records.iter().map(|record| record.length_value));
                            }
                            if !fits_discovery || values.len() < 2 {
                                continue;
                            }
                            let mut validation_matches = 0;
                            let mut validation_records = 0;
                            let mut validation_counterexamples = Vec::new();
                            for (observation, bytes) in validation.iter().zip(&validation_bytes) {
                                if start_offset >= bytes.len() {
                                    validation_counterexamples.push(FramingCounterexample {
                                        observation_id: observation.id.clone(),
                                        status: FramingStatus::StartOutsideObservation,
                                        next_offset: bytes.len(),
                                        record_count: 0,
                                    });
                                    continue;
                                }
                                let probe = probe_bytes(bytes, config);
                                if probe.status == FramingStatus::Complete
                                    && probe.records.len() >= 2
                                {
                                    validation_matches += 1;
                                    validation_records += probe.records.len();
                                } else {
                                    validation_counterexamples.push(FramingCounterexample {
                                        observation_id: observation.id.clone(),
                                        status: probe.status,
                                        next_offset: probe.next_offset,
                                        record_count: probe.records.len(),
                                    });
                                }
                            }
                            candidates.push(FramingCandidate {
                                config,
                                discovery_records,
                                distinct_discovery_lengths: values.len(),
                                validation_matches,
                                validation_records,
                                validation_counterexamples,
                            });
                        }
                    }
                }
            }
        }
    }
    candidates.sort_by(|left, right| {
        right
            .validation_matches
            .cmp(&left.validation_matches)
            .then(
                left.validation_counterexamples
                    .len()
                    .cmp(&right.validation_counterexamples.len()),
            )
            .then(right.discovery_records.cmp(&left.discovery_records))
            .then(left.config.cmp(&right.config))
    });
    let candidate_count = candidates.len();
    candidates.truncate(MAX_REPORTED_CANDIDATES);
    Ok(FramingInference {
        revision: state.revision,
        method: "length_prefix_exact_fit_v1",
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        discovery_count: discovery.len(),
        validation_count: validation.len(),
        candidate_count,
        reported_candidate_limit: MAX_REPORTED_CANDIDATES,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(length_mode: LengthMode) -> FramingConfig {
        FramingConfig {
            start_offset: 0,
            prefix_offset: 0,
            prefix_width: 1,
            byte_order: ByteOrder::BigEndian,
            length_mode,
            alignment: 1,
        }
    }

    #[test]
    fn partial_record_and_record_limit_are_explicit() {
        let partial = probe_bytes(&[2, 0xaa, 0xbb, 1], config(LengthMode::Payload));
        assert_eq!(partial.status, FramingStatus::TruncatedRecord);
        assert_eq!(partial.next_offset, 3);
        assert_eq!(partial.records.len(), 1);

        let bounded = probe_bytes(&[0; MAX_RECORDS + 1], config(LengthMode::Payload));
        assert_eq!(bounded.status, FramingStatus::RecordLimit);
        assert_eq!(bounded.records.len(), MAX_RECORDS);

        let invalid = probe_bytes(&[0], config(LengthMode::Total));
        assert_eq!(invalid.status, FramingStatus::InvalidLength);
        assert!(invalid.records.is_empty());
    }

    #[test]
    fn long_reassembled_record_reports_bounded_provenance() {
        let mut bytes = vec![19];
        bytes.extend([0xaa; 19]);
        let spans: Vec<_> = (0..20)
            .map(|index| SourceSpan {
                message_start: index,
                message_end: index + 1,
                packet_index: index,
                file_offset: 100 + index,
            })
            .collect();
        let state = State {
            schema_version: 11,
            revision: 1,
            question: "test".into(),
            hypotheses: Vec::new(),
            experiments: Vec::new(),
            trials: Vec::new(),
            captures: Vec::new(),
            capture_runs: Vec::new(),
            observations: vec![Observation {
                id: "obs-1".into(),
                capture_id: "cap-1".into(),
                source_index: 0,
                source_offset: None,
                timestamp_ns: None,
                direction: None,
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: spans,
                bytes_hex: to_hex(&bytes),
            }],
            framing_runs: Vec::new(),
            varint_runs: Vec::new(),
            actions: Vec::new(),
            tags: Vec::new(),
            window_tags: Vec::new(),
            capture_tag_batches: Vec::new(),
            known_values: Vec::new(),
            frame_known_values: Vec::new(),
            analyses: Vec::new(),
            decisions: Vec::new(),
        };
        let probe = probe_observation(&state, "obs-1", config(LengthMode::Payload)).unwrap();
        assert_eq!(probe.status, FramingStatus::Complete);
        assert_eq!(probe.records[0].source_span_count, 20);
        assert_eq!(probe.records[0].source_spans.len(), MAX_SPANS_PER_RECORD);
        assert!(probe.records[0].source_spans_truncated);
    }
}
