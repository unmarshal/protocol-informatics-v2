//! Test one narrow, falsifiable checksum model against separate trials.
//! A candidate is a two-byte field that equals the Internet checksum of the
//! entire message after those two bytes are zeroed. This does not establish
//! that the protocol actually defines the field as a checksum.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::inference::infer_unsigned_field;
use crate::query::{TrialComparison, compare_trials};
use crate::workflow::{State, from_hex};

const MAX_OBSERVATIONS_PER_TRIAL: usize = 512;
const MAX_MESSAGE_BYTES: usize = 4096;
const MAX_FIELD_START: usize = 63;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumByteOrder {
    BigEndian,
    LittleEndian,
}

#[derive(Debug, Serialize)]
pub struct ChecksumCandidate {
    pub start: usize,
    pub end: usize,
    pub byte_order: ChecksumByteOrder,
    pub discovery_matches: usize,
    pub validation_matches: usize,
    pub validation_total: usize,
    pub counterexample_observation_ids: Vec<String>,
    pub intervention_pair_matches: usize,
    pub intervention_pair_total: usize,
    pub word_aligned: bool,
    pub intervention_supported: bool,
}

#[derive(Debug, Serialize)]
pub struct ChecksumInference {
    pub revision: u64,
    pub method: &'static str,
    pub coordinate_system: &'static str,
    pub coverage: &'static str,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub controlled_baseline_trial_id: String,
    pub controlled_variant_trial_id: String,
    pub controlled_variable: String,
    pub controlled_field_start: usize,
    pub controlled_field_end: usize,
    pub controlled_pair_count: usize,
    pub discovery_count: usize,
    pub validation_count: usize,
    pub duplicate_validation_count: usize,
    pub maximum_message_bytes: usize,
    pub maximum_field_start: usize,
    pub candidate_count: usize,
    pub intervention_supported_count: usize,
    pub candidates: Vec<ChecksumCandidate>,
}

struct Example {
    id: String,
    bytes: Vec<u8>,
}

fn trial_examples(state: &State, trial_id: &str) -> Result<Vec<Example>, String> {
    if !state.trials.iter().any(|trial| trial.id == trial_id) {
        return Err(format!("unknown trial {trial_id}"));
    }
    let capture_ids: BTreeSet<_> = state
        .captures
        .iter()
        .filter(|capture| capture.trial_id == trial_id)
        .map(|capture| &capture.id)
        .collect();
    let selected: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| capture_ids.contains(&observation.capture_id))
        .collect();
    if selected.len() > MAX_OBSERVATIONS_PER_TRIAL {
        return Err(format!(
            "trial {trial_id} exceeds {MAX_OBSERVATIONS_PER_TRIAL} observations"
        ));
    }
    selected
        .into_iter()
        .map(|observation| {
            let bytes = from_hex(&observation.bytes_hex)?;
            if bytes.len() > MAX_MESSAGE_BYTES {
                return Err(format!(
                    "observation {} exceeds {MAX_MESSAGE_BYTES} bytes",
                    observation.id
                ));
            }
            Ok(Example {
                id: observation.id.clone(),
                bytes,
            })
        })
        .collect()
}

fn internet_checksum_with_zeroed_field(bytes: &[u8], field_start: usize) -> u16 {
    let mut sum = 0_u32;
    for (word_index, pair) in bytes.chunks(2).enumerate() {
        let start = word_index * 2;
        let high = if (field_start..field_start + 2).contains(&start) {
            0
        } else {
            pair[0]
        };
        let low_offset = start + 1;
        let low = if low_offset == field_start || low_offset == field_start + 1 {
            0
        } else {
            pair.get(1).copied().unwrap_or(0)
        };
        sum += u32::from(u16::from_be_bytes([high, low]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn matches(example: &Example, start: usize, order: ChecksumByteOrder) -> bool {
    let Some(stored) = example.bytes.get(start..start + 2) else {
        return false;
    };
    let expected = internet_checksum_with_zeroed_field(&example.bytes, start);
    let actual = match order {
        ChecksumByteOrder::BigEndian => u16::from_be_bytes([stored[0], stored[1]]),
        ChecksumByteOrder::LittleEndian => u16::from_le_bytes([stored[0], stored[1]]),
    };
    actual == expected
}

fn explains_intervention(
    comparison: &TrialComparison<'_>,
    checksum_start: usize,
    controlled_start: usize,
    controlled_end: usize,
) -> usize {
    comparison
        .pairs
        .iter()
        .filter(|pair| {
            if pair.left_length != pair.right_length {
                return false;
            }
            let mut checksum_changed = false;
            let mut controlled_changed = false;
            for range in &pair.changed_ranges {
                for offset in range.start..range.end {
                    if (checksum_start..checksum_start + 2).contains(&offset) {
                        checksum_changed = true;
                    } else if (controlled_start..controlled_end).contains(&offset) {
                        controlled_changed = true;
                    } else {
                        return false;
                    }
                }
            }
            checksum_changed && controlled_changed
        })
        .count()
}

pub fn infer_internet_checksum(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
    controlled_baseline_trial_id: &str,
    controlled_variant_trial_id: &str,
    controlled_variable: &str,
) -> Result<ChecksumInference, String> {
    if discovery_trial_id == validation_trial_id {
        return Err("discovery and validation must use different trials".into());
    }
    let discovery = trial_examples(state, discovery_trial_id)?;
    let validation = trial_examples(state, validation_trial_id)?;
    if discovery.len() < 3 || validation.is_empty() {
        return Err(
            "checksum inference needs at least 3 discovery and 1 validation observations".into(),
        );
    }
    let known_field = infer_unsigned_field(state, controlled_variable)?;
    if known_field.truncated {
        return Err(format!(
            "{controlled_variable} has too many numeric candidates to establish a unique field"
        ));
    }
    let confirmed_fields: Vec<_> = known_field
        .candidates
        .iter()
        .filter(|candidate| candidate.preferred)
        .collect();
    if confirmed_fields.len() != 1 {
        return Err(format!(
            "{controlled_variable} needs exactly one shortest unsigned field candidate matching held-out values"
        ));
    }
    let controlled_field = confirmed_fields[0];
    let comparison = compare_trials(
        state,
        controlled_baseline_trial_id,
        controlled_variant_trial_id,
    )?;
    if comparison.pair_count == 0
        || comparison.unmatched_baseline != 0
        || comparison.unmatched_variant != 0
    {
        return Err("controlled trials need matched observations in both directions".into());
    }
    let discovery_bytes: BTreeSet<_> = discovery.iter().map(|example| &example.bytes).collect();
    let duplicate_validation_count = validation
        .iter()
        .filter(|example| discovery_bytes.contains(&example.bytes))
        .count();
    if duplicate_validation_count == validation.len() {
        return Err("validation trial has no new message bytes outside discovery".into());
    }
    let search_length = discovery
        .iter()
        .map(|example| example.bytes.len())
        .min()
        .unwrap_or(0);
    let mut candidates = Vec::new();
    for start in 0..search_length.saturating_sub(1).min(MAX_FIELD_START + 1) {
        for order in [
            ChecksumByteOrder::BigEndian,
            ChecksumByteOrder::LittleEndian,
        ] {
            if !discovery
                .iter()
                .all(|example| matches(example, start, order))
            {
                continue;
            }
            let counterexample_observation_ids: Vec<_> = validation
                .iter()
                .filter(|example| !matches(example, start, order))
                .map(|example| example.id.clone())
                .collect();
            let word_aligned = start % 2 == 0;
            let overlaps_controlled_field =
                start < controlled_field.end && start + 2 > controlled_field.start;
            let intervention_pair_matches = if overlaps_controlled_field {
                0
            } else {
                explains_intervention(
                    &comparison,
                    start,
                    controlled_field.start,
                    controlled_field.end,
                )
            };
            let intervention_supported = word_aligned
                && !overlaps_controlled_field
                && intervention_pair_matches == comparison.pair_count
                && counterexample_observation_ids.is_empty();
            candidates.push(ChecksumCandidate {
                start,
                end: start + 2,
                byte_order: order,
                discovery_matches: discovery.len(),
                validation_matches: validation.len() - counterexample_observation_ids.len(),
                validation_total: validation.len(),
                counterexample_observation_ids,
                intervention_pair_matches,
                intervention_pair_total: comparison.pair_count,
                word_aligned,
                intervention_supported,
            });
        }
    }
    candidates.sort_by_key(|candidate| {
        (
            std::cmp::Reverse(candidate.intervention_supported),
            std::cmp::Reverse(candidate.validation_matches),
            candidate.start,
            match candidate.byte_order {
                ChecksumByteOrder::BigEndian => 0,
                ChecksumByteOrder::LittleEndian => 1,
            },
        )
    });
    let intervention_supported_count = candidates
        .iter()
        .filter(|candidate| candidate.intervention_supported)
        .count();
    Ok(ChecksumInference {
        revision: state.revision,
        method: "internet_checksum16_zero_field_v1",
        coordinate_system: "message_bytes",
        coverage: "whole_message",
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        controlled_baseline_trial_id: controlled_baseline_trial_id.into(),
        controlled_variant_trial_id: controlled_variant_trial_id.into(),
        controlled_variable: controlled_variable.into(),
        controlled_field_start: controlled_field.start,
        controlled_field_end: controlled_field.end,
        controlled_pair_count: comparison.pair_count,
        discovery_count: discovery.len(),
        validation_count: validation.len(),
        duplicate_validation_count,
        maximum_message_bytes: MAX_MESSAGE_BYTES,
        maximum_field_start: MAX_FIELD_START,
        candidate_count: candidates.len(),
        intervention_supported_count,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_handles_odd_length_and_zeroing_at_odd_offset() {
        assert_eq!(
            internet_checksum_with_zeroed_field(&[1, 0, 0, 4, 5], 1),
            0xf9fb
        );
    }
}
