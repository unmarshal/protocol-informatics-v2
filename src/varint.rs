//! Bounded unsigned LEB128 length-prefix records with held-out structural checks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::framing::{
    FramedRecord, FramingCounterexample, FramingStatus, LengthMode, trial_observations,
};
use crate::reassembly::SourceSpan;
use crate::workflow::{Observation, State, from_hex, to_hex};

const MAX_RECORDS: usize = 256;
const MAX_SPANS_PER_RECORD: usize = 16;
const MAX_REPORTED_CANDIDATES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VarintConfig {
    pub start_offset: usize,
    pub field_offset: usize,
    pub length_mode: LengthMode,
    pub alignment: usize,
}

impl VarintConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.field_offset > 128 {
            return Err(
                "length field offset must be at most 128 bytes from each record start".into(),
            );
        }
        if !matches!(self.alignment, 1 | 2 | 4 | 8) {
            return Err("record alignment must be 1, 2, 4, or 8 bytes".into());
        }
        Ok(self)
    }
}

#[derive(Debug, Serialize)]
pub struct VarintProbe {
    pub revision: u64,
    pub observation_id: String,
    pub coordinate_system: &'static str,
    pub observation_length: usize,
    pub config: VarintConfig,
    pub status: FramingStatus,
    pub next_offset: usize,
    pub remaining_bytes: usize,
    pub record_count: usize,
    pub records: Vec<FramedRecord>,
}

#[derive(Debug)]
struct CoreRecord {
    start: usize,
    logical_end: usize,
    end: usize,
    length_field_start: usize,
    length_field_end: usize,
    length_value: u32,
}

#[derive(Debug)]
struct CoreProbe {
    status: FramingStatus,
    next_offset: usize,
    records: Vec<CoreRecord>,
}

fn read_u32_leb128(bytes: &[u8], start: usize) -> Result<(u32, usize), FramingStatus> {
    let mut value = 0_u32;
    for index in 0..5 {
        let Some(&byte) = bytes.get(start + index) else {
            return Err(FramingStatus::TruncatedPrefix);
        };
        if index == 4 && byte & 0xf0 != 0 {
            return Err(FramingStatus::InvalidLength);
        }
        value |= u32::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            if index > 0 && value < (1_u32 << (7 * index)) {
                return Err(FramingStatus::InvalidLength);
            }
            return Ok((value, start + index + 1));
        }
    }
    Err(FramingStatus::InvalidLength)
}

fn probe_bytes(bytes: &[u8], config: VarintConfig) -> CoreProbe {
    let mut offset = config.start_offset;
    let mut records = Vec::new();
    let status = loop {
        if offset == bytes.len() {
            break FramingStatus::Complete;
        }
        if records.len() == MAX_RECORDS {
            break FramingStatus::RecordLimit;
        }
        let Some(length_field_start) = offset.checked_add(config.field_offset) else {
            break FramingStatus::TruncatedPrefix;
        };
        let (length_value, length_field_end) = match read_u32_leb128(bytes, length_field_start) {
            Ok(decoded) => decoded,
            Err(status) => break status,
        };
        let header_length = length_field_end - offset;
        let logical_length = match config.length_mode {
            LengthMode::Total => length_value as usize,
            LengthMode::Payload => {
                let Some(length) = header_length.checked_add(length_value as usize) else {
                    break FramingStatus::TruncatedRecord;
                };
                length
            }
        };
        if logical_length < header_length {
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

pub fn probe_varint(
    state: &State,
    observation_id: &str,
    config: VarintConfig,
) -> Result<VarintProbe, String> {
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
    let records = core
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
    Ok(VarintProbe {
        revision: state.revision,
        observation_id: observation_id.into(),
        coordinate_system: "observation_bytes",
        observation_length: bytes.len(),
        config,
        status: core.status,
        next_offset: core.next_offset,
        remaining_bytes: bytes.len() - core.next_offset,
        record_count: core.records.len(),
        records,
    })
}

#[derive(Debug, Serialize)]
pub struct VarintCandidate {
    pub config: VarintConfig,
    pub discovery_records: usize,
    pub distinct_discovery_lengths: usize,
    pub discovery_multibyte_prefixes: usize,
    pub validation_matches: usize,
    pub validation_records: usize,
    pub validation_counterexamples: Vec<FramingCounterexample>,
}

#[derive(Debug, Serialize)]
pub struct VarintInference {
    pub revision: u64,
    pub method: &'static str,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub discovery_count: usize,
    pub validation_count: usize,
    pub candidate_count: usize,
    pub reported_candidate_limit: usize,
    pub candidates: Vec<VarintCandidate>,
}

pub fn infer_varint(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
) -> Result<VarintInference, String> {
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
        return Err("varint inference needs at least two discovery observations".into());
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
        for field_offset in 0..=2 {
            for length_mode in [LengthMode::Total, LengthMode::Payload] {
                for alignment in [1, 2, 4] {
                    let config = VarintConfig {
                        start_offset,
                        field_offset,
                        length_mode,
                        alignment,
                    };
                    let mut values = BTreeSet::new();
                    let mut discovery_records = 0;
                    let mut discovery_multibyte_prefixes = 0;
                    let mut fits_discovery = true;
                    for bytes in &discovery_bytes {
                        if start_offset >= bytes.len() {
                            fits_discovery = false;
                            break;
                        }
                        let probe = probe_bytes(bytes, config);
                        if probe.status != FramingStatus::Complete || probe.records.len() < 2 {
                            fits_discovery = false;
                            break;
                        }
                        discovery_records += probe.records.len();
                        for record in probe.records {
                            values.insert(record.length_value);
                            if record.length_field_end - record.length_field_start > 1 {
                                discovery_multibyte_prefixes += 1;
                            }
                        }
                    }
                    if !fits_discovery || values.len() < 2 || discovery_multibyte_prefixes == 0 {
                        continue;
                    }
                    let mut validation_matches = 0;
                    let mut validation_records = 0;
                    let mut validation_counterexamples = Vec::new();
                    for (observation, bytes) in validation.iter().zip(&validation_bytes) {
                        let probe = if start_offset < bytes.len() {
                            probe_bytes(bytes, config)
                        } else {
                            CoreProbe {
                                status: FramingStatus::StartOutsideObservation,
                                next_offset: bytes.len(),
                                records: Vec::new(),
                            }
                        };
                        if probe.status == FramingStatus::Complete && probe.records.len() >= 2 {
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
                    candidates.push(VarintCandidate {
                        config,
                        discovery_records,
                        distinct_discovery_lengths: values.len(),
                        discovery_multibyte_prefixes,
                        validation_matches,
                        validation_records,
                        validation_counterexamples,
                    });
                }
            }
        }
    }
    candidates.sort_by(|a, b| {
        b.validation_matches
            .cmp(&a.validation_matches)
            .then(
                b.discovery_multibyte_prefixes
                    .cmp(&a.discovery_multibyte_prefixes),
            )
            .then(b.discovery_records.cmp(&a.discovery_records))
            .then(a.config.cmp(&b.config))
    });
    let candidate_count = candidates.len();
    candidates.truncate(MAX_REPORTED_CANDIDATES);
    Ok(VarintInference {
        revision: state.revision,
        method: "unsigned_leb128_length_exact_fit_v1",
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

    #[test]
    fn canonical_unsigned_leb128_rejects_overlong_and_overflow() {
        assert_eq!(read_u32_leb128(&[0x00], 0), Ok((0, 1)));
        assert_eq!(read_u32_leb128(&[0x80, 0x01], 0), Ok((128, 2)));
        assert_eq!(
            read_u32_leb128(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0),
            Ok((u32::MAX, 5))
        );
        assert_eq!(
            read_u32_leb128(&[0x80, 0x00], 0),
            Err(FramingStatus::InvalidLength)
        );
        assert_eq!(
            read_u32_leb128(&[0x80], 0),
            Err(FramingStatus::TruncatedPrefix)
        );
        assert_eq!(
            read_u32_leb128(&[0xff, 0xff, 0xff, 0xff, 0x10], 0),
            Err(FramingStatus::InvalidLength)
        );
    }
}
