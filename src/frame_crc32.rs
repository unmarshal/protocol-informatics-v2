//! Held-out tests for an IEEE CRC32 stored in the last four logical frame bytes.
//! A match is an exact structural hypothesis, not proof of a protocol field name.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::framing::{ByteOrder, FramingBoundaryRule};
use crate::workflow::{State, from_hex};

const MAX_RUNS_PER_SET: usize = 16;
const MAX_FRAMES: usize = 512;
const MAX_TOTAL_BYTES: usize = 512 * 1024;
const MAX_COVERAGE_START: usize = 16;
const MAX_COUNTEREXAMPLES: usize = 20;

#[derive(Debug, Serialize)]
pub struct FrameCrc32Candidate {
    pub coverage_start: usize,
    pub stored_byte_order: ByteOrder,
    pub distinct_discovery_values: usize,
    pub discovery_matches: usize,
    pub validation_matches: usize,
    pub validation_total: usize,
    pub validation_counterexample_count: usize,
    pub first_validation_counterexample_frame_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FrameCrc32Inference {
    pub revision: u64,
    pub method: &'static str,
    pub coordinate_system: &'static str,
    pub coverage_end: &'static str,
    pub stored_field: &'static str,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub discovery_run_keys: Vec<String>,
    pub validation_run_keys: Vec<String>,
    pub boundary_rule: FramingBoundaryRule,
    pub discovery_capture_count: usize,
    pub discovery_frame_count: usize,
    pub validation_capture_count: usize,
    pub validation_frame_count: usize,
    pub maximum_coverage_start: usize,
    pub maximum_total_logical_bytes_per_set: usize,
    pub candidate_count: usize,
    pub candidates: Vec<FrameCrc32Candidate>,
}

struct FrameExample {
    id: String,
    bytes: Vec<u8>,
}

struct SelectedFrames {
    trial_id: String,
    experiment_id: String,
    capture_ids: BTreeSet<String>,
    boundary_rule: FramingBoundaryRule,
    examples: Vec<FrameExample>,
}

fn select_frames(state: &State, keys: &[String]) -> Result<SelectedFrames, String> {
    if keys.is_empty() || keys.len() > MAX_RUNS_PER_SET {
        return Err(format!(
            "choose 1 to {MAX_RUNS_PER_SET} committed framing run keys per set"
        ));
    }
    let unique_keys: BTreeSet<_> = keys.iter().collect();
    if unique_keys.len() != keys.len() {
        return Err("framing run keys must be unique within each set".into());
    }
    let captures: BTreeMap<_, _> = state
        .captures
        .iter()
        .map(|capture| (capture.id.as_str(), capture))
        .collect();
    let observations: BTreeMap<_, _> = state
        .observations
        .iter()
        .map(|observation| (observation.id.as_str(), observation))
        .collect();
    let trials: BTreeMap<_, _> = state
        .trials
        .iter()
        .map(|trial| (trial.id.as_str(), trial))
        .collect();
    let mut selected = Vec::new();
    let mut chosen_observations = BTreeSet::new();
    let mut trial_id = None;
    let mut experiment_id = None;
    let mut boundary_rule = None;
    let mut capture_ids = BTreeSet::new();
    let mut total_bytes = 0_usize;
    for key in keys {
        let run = state
            .framing_runs
            .iter()
            .find(|run| run.key == *key)
            .ok_or_else(|| format!("unknown fixed-width framing run key {key}"))?;
        if !chosen_observations.insert(run.observation_id.as_str()) {
            return Err("choose only one framing interpretation per observation".into());
        }
        let rule = run.config.boundary_rule();
        if boundary_rule.is_some_and(|previous| previous != rule) {
            return Err("selected framing runs must use one boundary rule".into());
        }
        boundary_rule = Some(rule);
        let observation = observations
            .get(run.observation_id.as_str())
            .ok_or_else(|| format!("unknown observation {}", run.observation_id))?;
        let capture = captures
            .get(observation.capture_id.as_str())
            .ok_or_else(|| format!("unknown capture {}", observation.capture_id))?;
        let trial = trials
            .get(capture.trial_id.as_str())
            .ok_or_else(|| format!("unknown trial {}", capture.trial_id))?;
        if trial_id.is_some_and(|previous| previous != trial.id) {
            return Err("each run-key set must belong to one trial".into());
        }
        trial_id = Some(trial.id.as_str());
        experiment_id = Some(trial.experiment_id.as_str());
        capture_ids.insert(capture.id.clone());
        let bytes = from_hex(&observation.bytes_hex)?;
        for record in &run.records {
            if record.logical_end > bytes.len() || record.logical_end < record.start {
                return Err(format!("frame {} has invalid logical bounds", record.id));
            }
            let logical = &bytes[record.start..record.logical_end];
            if logical.len() < 5 {
                return Err(format!(
                    "frame {} is too short for a CRC32 suffix",
                    record.id
                ));
            }
            total_bytes = total_bytes.saturating_add(logical.len());
            if total_bytes > MAX_TOTAL_BYTES || selected.len() >= MAX_FRAMES {
                return Err(format!(
                    "CRC32 inference supports at most {MAX_FRAMES} frames and {MAX_TOTAL_BYTES} logical bytes per set"
                ));
            }
            selected.push(FrameExample {
                id: record.id.clone(),
                bytes: logical.to_vec(),
            });
        }
    }
    Ok(SelectedFrames {
        trial_id: trial_id.expect("nonempty keys").into(),
        experiment_id: experiment_id.expect("nonempty keys").into(),
        capture_ids,
        boundary_rule: boundary_rule.expect("nonempty keys"),
        examples: selected,
    })
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}

fn matches(frame: &FrameExample, coverage_start: usize, order: ByteOrder) -> Option<u32> {
    let checksum_start = frame.bytes.len().checked_sub(4)?;
    if coverage_start >= checksum_start {
        return None;
    }
    let expected = crc32_ieee(&frame.bytes[coverage_start..checksum_start]);
    let stored: [u8; 4] = frame.bytes[checksum_start..].try_into().ok()?;
    let actual = match order {
        ByteOrder::BigEndian => u32::from_be_bytes(stored),
        ByteOrder::LittleEndian => u32::from_le_bytes(stored),
    };
    (actual == expected).then_some(actual)
}

pub fn infer_frame_crc32(
    state: &State,
    discovery_run_keys: &[String],
    validation_run_keys: &[String],
) -> Result<FrameCrc32Inference, String> {
    if discovery_run_keys
        .iter()
        .any(|key| validation_run_keys.contains(key))
    {
        return Err("discovery and validation run keys must be disjoint".into());
    }
    let discovery = select_frames(state, discovery_run_keys)?;
    let validation = select_frames(state, validation_run_keys)?;
    if discovery.trial_id == validation.trial_id
        || discovery.experiment_id != validation.experiment_id
    {
        return Err(
            "discovery and validation runs must use distinct trials of one experiment".into(),
        );
    }
    if discovery.boundary_rule != validation.boundary_rule {
        return Err("discovery and validation runs must use one boundary rule".into());
    }
    if discovery.capture_ids.len() < 2 || validation.capture_ids.is_empty() {
        return Err(
            "CRC32 inference needs at least two discovery captures and one validation capture"
                .into(),
        );
    }
    let mut candidates = Vec::new();
    for coverage_start in 0..=MAX_COVERAGE_START {
        for order in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
            let matched: Option<Vec<_>> = discovery
                .examples
                .iter()
                .map(|frame| matches(frame, coverage_start, order))
                .collect();
            let Some(values) = matched else { continue };
            let distinct_values: BTreeSet<_> = values.iter().copied().collect();
            if distinct_values.len() < 2 {
                continue;
            }
            let mut validation_matches = 0;
            let mut counterexamples = Vec::new();
            let mut counterexample_count = 0;
            for frame in &validation.examples {
                if matches(frame, coverage_start, order).is_some() {
                    validation_matches += 1;
                } else {
                    counterexample_count += 1;
                    if counterexamples.len() < MAX_COUNTEREXAMPLES {
                        counterexamples.push(frame.id.clone());
                    }
                }
            }
            candidates.push(FrameCrc32Candidate {
                coverage_start,
                stored_byte_order: order,
                distinct_discovery_values: distinct_values.len(),
                discovery_matches: discovery.examples.len(),
                validation_matches,
                validation_total: validation.examples.len(),
                validation_counterexample_count: counterexample_count,
                first_validation_counterexample_frame_ids: counterexamples,
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .validation_matches
            .cmp(&left.validation_matches)
            .then(left.coverage_start.cmp(&right.coverage_start))
            .then(left.stored_byte_order.cmp(&right.stored_byte_order))
    });
    Ok(FrameCrc32Inference {
        revision: state.revision,
        method: "crc32_ieee_suffix_v1",
        coordinate_system: "logical_frame_bytes",
        coverage_end: "before_last_4_bytes",
        stored_field: "last_4_logical_bytes",
        discovery_trial_id: discovery.trial_id,
        validation_trial_id: validation.trial_id,
        discovery_run_keys: discovery_run_keys.to_vec(),
        validation_run_keys: validation_run_keys.to_vec(),
        boundary_rule: discovery.boundary_rule,
        discovery_capture_count: discovery.capture_ids.len(),
        discovery_frame_count: discovery.examples.len(),
        validation_capture_count: validation.capture_ids.len(),
        validation_frame_count: validation.examples.len(),
        maximum_coverage_start: MAX_COVERAGE_START,
        maximum_total_logical_bytes_per_set: MAX_TOTAL_BYTES,
        candidate_count: candidates.len(),
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::crc32_ieee;

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }
}
