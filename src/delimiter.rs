//! Conservative delimiter-terminated record probes and held-out checks.
//! A structural fit does not establish escaping rules or record semantics.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::framing::{clipped_spans, trial_observations};
use crate::reassembly::SourceSpan;
use crate::workflow::{State, from_hex, to_hex};

const MAX_DELIMITER_BYTES: usize = 4;
const MAX_START_OFFSET: usize = 8;
const MAX_RECORDS: usize = 256;
const MAX_SPANS_PER_RECORD: usize = 16;
const MIN_RECORDS_FOR_INFERENCE: usize = 3;
const MAX_COUNTEREXAMPLES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DelimiterConfig {
    pub start_offset: usize,
    pub delimiter_hex: String,
}

impl DelimiterConfig {
    pub fn validate(mut self) -> Result<Self, String> {
        let delimiter = from_hex(&self.delimiter_hex)?;
        if delimiter.is_empty() || delimiter.len() > MAX_DELIMITER_BYTES {
            return Err(format!(
                "delimiter must contain 1 to {MAX_DELIMITER_BYTES} bytes"
            ));
        }
        self.delimiter_hex = to_hex(&delimiter);
        Ok(self)
    }

    fn bytes(&self) -> Result<Vec<u8>, String> {
        from_hex(&self.delimiter_hex)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelimiterStatus {
    Complete,
    StartOutsideObservation,
    UnterminatedRecord,
    EmptyRecord,
    RecordLimit,
}

#[derive(Debug, Serialize)]
pub struct DelimitedRecord {
    pub index: usize,
    pub start: usize,
    pub payload_end: usize,
    pub end: usize,
    pub payload_length: usize,
    pub preview_hex: String,
    pub source_file_offset: Option<usize>,
    pub source_span_count: usize,
    pub source_spans_truncated: bool,
    pub source_spans: Vec<SourceSpan>,
}

#[derive(Debug, Serialize)]
pub struct DelimiterProbe {
    pub revision: u64,
    pub observation_id: String,
    pub coordinate_system: &'static str,
    pub observation_length: usize,
    pub config: DelimiterConfig,
    pub status: DelimiterStatus,
    pub next_offset: usize,
    pub remaining_bytes: usize,
    pub record_count: usize,
    pub records: Vec<DelimitedRecord>,
}

#[derive(Debug, Clone)]
struct CoreRecord {
    start: usize,
    payload_end: usize,
    end: usize,
}

#[derive(Debug)]
struct CoreProbe {
    status: DelimiterStatus,
    next_offset: usize,
    records: Vec<CoreRecord>,
}

fn probe_bytes(bytes: &[u8], start_offset: usize, delimiter: &[u8]) -> CoreProbe {
    let mut offset = start_offset;
    let mut records = Vec::new();
    let status = loop {
        if offset == bytes.len() {
            break DelimiterStatus::Complete;
        }
        if records.len() == MAX_RECORDS {
            break DelimiterStatus::RecordLimit;
        }
        let Some(relative) = bytes[offset..]
            .windows(delimiter.len())
            .position(|window| window == delimiter)
        else {
            break DelimiterStatus::UnterminatedRecord;
        };
        let payload_end = offset + relative;
        if payload_end == offset {
            break DelimiterStatus::EmptyRecord;
        }
        let end = payload_end + delimiter.len();
        records.push(CoreRecord {
            start: offset,
            payload_end,
            end,
        });
        offset = end;
    };
    CoreProbe {
        status,
        next_offset: offset,
        records,
    }
}

pub fn probe_observation(
    state: &State,
    observation_id: &str,
    config: DelimiterConfig,
) -> Result<DelimiterProbe, String> {
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
    let delimiter = config.bytes()?;
    let core = probe_bytes(&bytes, config.start_offset, &delimiter);
    let records: Vec<_> = core
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let mut source_spans = clipped_spans(observation, record.start, record.end);
            let source_span_count = source_spans.len();
            source_spans.truncate(MAX_SPANS_PER_RECORD);
            DelimitedRecord {
                index,
                start: record.start,
                payload_end: record.payload_end,
                end: record.end,
                payload_length: record.payload_end - record.start,
                preview_hex: to_hex(&bytes[record.start..record.end.min(record.start + 16)]),
                source_file_offset: observation.source_offset.map(|base| base + record.start),
                source_span_count,
                source_spans_truncated: source_span_count > MAX_SPANS_PER_RECORD,
                source_spans,
            }
        })
        .collect();
    Ok(DelimiterProbe {
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
pub struct DelimiterCounterexample {
    pub observation_id: String,
    pub status: DelimiterStatus,
    pub next_offset: usize,
    pub record_count: usize,
}

#[derive(Debug, Serialize)]
pub struct DelimiterCandidate {
    pub config: DelimiterConfig,
    pub discovery_records: usize,
    pub distinct_discovery_payload_lengths: usize,
    pub validation_matches: usize,
    pub validation_total: usize,
    pub validation_records: usize,
    pub validation_counterexamples: Vec<DelimiterCounterexample>,
    pub validation_counterexamples_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct DelimiterInference {
    pub revision: u64,
    pub method: &'static str,
    pub provisional: bool,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub discovery_count: usize,
    pub validation_count: usize,
    pub minimum_records_per_observation: usize,
    pub maximum_delimiter_bytes: usize,
    pub maximum_start_offset: usize,
    pub candidate_count: usize,
    pub fully_validated_candidate_count: usize,
    pub candidates: Vec<DelimiterCandidate>,
}

pub fn infer_delimiter(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
) -> Result<DelimiterInference, String> {
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
        return Err("delimiter inference needs at least two discovery observations".into());
    }
    if discovery
        .iter()
        .map(|observation| &observation.bytes_hex)
        .collect::<BTreeSet<_>>()
        .len()
        < 2
    {
        return Err("delimiter inference needs two distinct discovery messages".into());
    }
    let discovery_bytes = discovery
        .iter()
        .map(|observation| from_hex(&observation.bytes_hex))
        .collect::<Result<Vec<_>, _>>()?;
    let validation_bytes = validation
        .iter()
        .map(|observation| from_hex(&observation.bytes_hex))
        .collect::<Result<Vec<_>, _>>()?;
    let first = &discovery_bytes[0];
    let mut candidates = Vec::new();
    for delimiter_length in 1..=MAX_DELIMITER_BYTES.min(first.len()) {
        let delimiter = &first[first.len() - delimiter_length..];
        for start_offset in 0..=MAX_START_OFFSET.min(first.len().saturating_sub(1)) {
            let mut discovery_records = 0;
            let mut payload_lengths = BTreeSet::new();
            let mut discovery_fit = true;
            for bytes in &discovery_bytes {
                if start_offset >= bytes.len() {
                    discovery_fit = false;
                    break;
                }
                let probe = probe_bytes(bytes, start_offset, delimiter);
                if probe.status != DelimiterStatus::Complete
                    || probe.records.len() < MIN_RECORDS_FOR_INFERENCE
                {
                    discovery_fit = false;
                    break;
                }
                discovery_records += probe.records.len();
                payload_lengths.extend(
                    probe
                        .records
                        .iter()
                        .map(|record| record.payload_end - record.start),
                );
            }
            if !discovery_fit || payload_lengths.len() < 2 {
                continue;
            }
            let mut validation_matches = 0;
            let mut validation_records = 0;
            let mut counterexamples = Vec::new();
            let mut counterexample_count: usize = 0;
            for (observation, bytes) in validation.iter().zip(&validation_bytes) {
                let probe = if start_offset < bytes.len() {
                    probe_bytes(bytes, start_offset, delimiter)
                } else {
                    CoreProbe {
                        status: DelimiterStatus::StartOutsideObservation,
                        next_offset: 0,
                        records: Vec::new(),
                    }
                };
                if probe.status == DelimiterStatus::Complete
                    && probe.records.len() >= MIN_RECORDS_FOR_INFERENCE
                {
                    validation_matches += 1;
                    validation_records += probe.records.len();
                } else {
                    counterexample_count += 1;
                    if counterexamples.len() < MAX_COUNTEREXAMPLES {
                        counterexamples.push(DelimiterCounterexample {
                            observation_id: observation.id.clone(),
                            status: probe.status,
                            next_offset: probe.next_offset,
                            record_count: probe.records.len(),
                        });
                    }
                }
            }
            candidates.push(DelimiterCandidate {
                config: DelimiterConfig {
                    start_offset,
                    delimiter_hex: to_hex(delimiter),
                },
                discovery_records,
                distinct_discovery_payload_lengths: payload_lengths.len(),
                validation_matches,
                validation_total: validation.len(),
                validation_records,
                validation_counterexamples_omitted: counterexample_count
                    .saturating_sub(counterexamples.len()),
                validation_counterexamples: counterexamples,
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .validation_matches
            .cmp(&left.validation_matches)
            .then_with(|| {
                right
                    .config
                    .delimiter_hex
                    .len()
                    .cmp(&left.config.delimiter_hex.len())
            })
            .then_with(|| left.config.start_offset.cmp(&right.config.start_offset))
    });
    Ok(DelimiterInference {
        revision: state.revision,
        method: "delimiter_suffix_candidates_v1",
        provisional: true,
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        discovery_count: discovery.len(),
        validation_count: validation.len(),
        minimum_records_per_observation: MIN_RECORDS_FOR_INFERENCE,
        maximum_delimiter_bytes: MAX_DELIMITER_BYTES,
        maximum_start_offset: MAX_START_OFFSET,
        candidate_count: candidates.len(),
        fully_validated_candidate_count: candidates
            .iter()
            .filter(|candidate| candidate.validation_matches == validation.len())
            .count(),
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_record_and_unterminated_tail_remain_explicit() {
        let empty = probe_bytes(b"a\n\n", 0, b"\n");
        assert_eq!(empty.status, DelimiterStatus::EmptyRecord);
        assert_eq!(empty.records.len(), 1);
        assert_eq!(empty.next_offset, 2);
        let unfinished = probe_bytes(b"a\nb", 0, b"\n");
        assert_eq!(unfinished.status, DelimiterStatus::UnterminatedRecord);
        assert_eq!(unfinished.records.len(), 1);
        assert_eq!(unfinished.next_offset, 2);
    }

    #[test]
    fn record_limit_and_delimiter_width_are_bounded() {
        let bytes = b"a\n".repeat(MAX_RECORDS + 1);
        let result = probe_bytes(&bytes, 0, b"\n");
        assert_eq!(result.status, DelimiterStatus::RecordLimit);
        assert_eq!(result.records.len(), MAX_RECORDS);
        assert!(
            DelimiterConfig {
                start_offset: 0,
                delimiter_hex: "0d0a000001".into(),
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            DelimiterConfig {
                start_offset: 0,
                delimiter_hex: "0D0A".into(),
            }
            .validate()
            .unwrap()
            .delimiter_hex,
            "0d0a"
        );
    }
}
