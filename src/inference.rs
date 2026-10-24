//! Locate exact unsigned fields from controlled, externally supplied values.
//! Discovery and validation annotations remain separate so a candidate can
//! fail on data it did not help fit.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::workflow::{KnownValue, State, ValueSet, from_hex};

const MAX_SEARCH_BYTES: usize = 4096;
const MAX_ANNOTATIONS: usize = 1000;
const MAX_RETURNED_CANDIDATES: usize = 100;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    SingleByte,
    BigEndian,
    LittleEndian,
}

#[derive(Debug, Serialize)]
pub struct FieldCandidate {
    pub start: usize,
    pub end: usize,
    pub width: usize,
    pub byte_order: ByteOrder,
    pub discovery_matches: usize,
    pub validation_matches: usize,
    pub validation_total: usize,
    pub counterexample_observation_ids: Vec<String>,
    pub preferred: bool,
}

#[derive(Debug, Serialize)]
pub struct FieldInference {
    pub revision: u64,
    pub variable: String,
    pub method: &'static str,
    pub coordinate_system: &'static str,
    pub discovery_count: usize,
    pub distinct_discovery_values: usize,
    pub validation_count: usize,
    pub discovery_observation_ids: Vec<String>,
    pub validation_observation_ids: Vec<String>,
    pub max_search_bytes: usize,
    pub candidate_count: usize,
    pub validated_candidate_count: usize,
    pub preferred_candidate_count: usize,
    pub truncated: bool,
    pub candidates: Vec<FieldCandidate>,
}

struct Example<'a> {
    annotation: &'a KnownValue,
    bytes: Vec<u8>,
}

fn decoded(bytes: &[u8], order: ByteOrder) -> u64 {
    match order {
        ByteOrder::SingleByte | ByteOrder::BigEndian => bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
        ByteOrder::LittleEndian => bytes
            .iter()
            .rev()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    }
}

pub fn infer_unsigned_field(state: &State, variable: &str) -> Result<FieldInference, String> {
    let annotations: Vec<_> = state
        .known_values
        .iter()
        .filter(|annotation| annotation.variable == variable)
        .collect();
    if annotations.len() > MAX_ANNOTATIONS {
        return Err(format!(
            "{variable} has more than {MAX_ANNOTATIONS} annotations; narrow the investigation"
        ));
    }
    let examples: Vec<Example<'_>> = annotations
        .iter()
        .map(|annotation| {
            let observation = state
                .observations
                .iter()
                .find(|observation| observation.id == annotation.observation_id)
                .ok_or_else(|| format!("unknown observation {}", annotation.observation_id))?;
            Ok(Example {
                annotation,
                bytes: from_hex(&observation.bytes_hex)?,
            })
        })
        .collect::<Result<_, String>>()?;
    let discovery: Vec<_> = examples
        .iter()
        .filter(|example| example.annotation.set == ValueSet::Discovery)
        .collect();
    let validation: Vec<_> = examples
        .iter()
        .filter(|example| example.annotation.set == ValueSet::Validation)
        .collect();
    let distinct_values: BTreeSet<_> = discovery
        .iter()
        .map(|example| example.annotation.value)
        .collect();
    if discovery.len() < 3 || distinct_values.len() < 2 {
        return Err(format!(
            "{variable} needs at least three discovery observations with two distinct values"
        ));
    }
    let search_length = discovery
        .iter()
        .map(|example| example.bytes.len())
        .min()
        .unwrap_or(0)
        .min(MAX_SEARCH_BYTES);
    let mut candidates = Vec::new();
    for width in [1, 2, 4, 8] {
        if width > search_length {
            continue;
        }
        let orders: &[ByteOrder] = if width == 1 {
            &[ByteOrder::SingleByte]
        } else {
            &[ByteOrder::BigEndian, ByteOrder::LittleEndian]
        };
        for start in 0..=search_length - width {
            let end = start + width;
            for order in orders {
                if !discovery.iter().all(|example| {
                    decoded(&example.bytes[start..end], *order) == example.annotation.value
                }) {
                    continue;
                }
                let counterexample_observation_ids: Vec<String> = validation
                    .iter()
                    .filter(|example| {
                        example
                            .bytes
                            .get(start..end)
                            .is_none_or(|span| decoded(span, *order) != example.annotation.value)
                    })
                    .map(|example| example.annotation.observation_id.clone())
                    .collect();
                candidates.push(FieldCandidate {
                    start,
                    end,
                    width,
                    byte_order: *order,
                    discovery_matches: discovery.len(),
                    validation_matches: validation.len() - counterexample_observation_ids.len(),
                    validation_total: validation.len(),
                    counterexample_observation_ids,
                    preferred: false,
                });
            }
        }
    }
    candidates.sort_by_key(|candidate| {
        (
            std::cmp::Reverse(candidate.validation_matches),
            candidate.width,
            candidate.start,
            match candidate.byte_order {
                ByteOrder::SingleByte => 0,
                ByteOrder::BigEndian => 1,
                ByteOrder::LittleEndian => 2,
            },
        )
    });
    let validated_candidate_count = candidates
        .iter()
        .filter(|candidate| {
            candidate.validation_total > 0
                && candidate.validation_matches == candidate.validation_total
        })
        .count();
    if let Some(minimum_width) = candidates
        .iter()
        .filter(|candidate| {
            candidate.validation_total > 0
                && candidate.validation_matches == candidate.validation_total
        })
        .map(|candidate| candidate.width)
        .min()
    {
        for candidate in &mut candidates {
            candidate.preferred = candidate.width == minimum_width
                && candidate.validation_total > 0
                && candidate.validation_matches == candidate.validation_total;
        }
    }
    let preferred_candidate_count = candidates
        .iter()
        .filter(|candidate| candidate.preferred)
        .count();
    let candidate_count = candidates.len();
    candidates.truncate(MAX_RETURNED_CANDIDATES);
    Ok(FieldInference {
        revision: state.revision,
        variable: variable.into(),
        method: "exact_unsigned_match",
        coordinate_system: "message_bytes",
        discovery_count: discovery.len(),
        distinct_discovery_values: distinct_values.len(),
        validation_count: validation.len(),
        discovery_observation_ids: discovery
            .iter()
            .map(|example| example.annotation.observation_id.clone())
            .collect(),
        validation_observation_ids: validation
            .iter()
            .map(|example| example.annotation.observation_id.clone())
            .collect(),
        max_search_bytes: MAX_SEARCH_BYTES,
        candidate_count,
        validated_candidate_count,
        preferred_candidate_count,
        truncated: candidate_count > MAX_RETURNED_CANDIDATES,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{KnownValue, Observation};

    #[test]
    fn held_out_values_disprove_a_spurious_correlated_field() {
        let mut state = crate::workflow::create_test_state();
        for (index, (value, duplicate, set)) in [
            (1, 1, ValueSet::Discovery),
            (2, 2, ValueSet::Discovery),
            (3, 3, ValueSet::Discovery),
            (4, 0xff, ValueSet::Validation),
            (5, 0xee, ValueSet::Validation),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("obs-{index}");
            state.observations.push(Observation {
                id: id.clone(),
                capture_id: "capture".into(),
                source_index: index,
                source_offset: None,
                timestamp_ns: None,
                direction: None,
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: Vec::new(),
                bytes_hex: format!("aa{value:02x}{duplicate:02x}"),
            });
            state.known_values.push(KnownValue {
                id: format!("value-{index}"),
                observation_id: id,
                variable: "counter".into(),
                value,
                set,
            });
        }
        let result = infer_unsigned_field(&state, "counter").unwrap();
        assert_eq!(result.candidate_count, 2);
        assert_eq!(result.candidates[0].start, 1);
        assert_eq!(result.candidates[0].validation_matches, 2);
        assert_eq!(result.candidates[1].start, 2);
        assert_eq!(result.candidates[1].validation_matches, 0);
        assert_eq!(result.candidates[1].counterexample_observation_ids.len(), 2);
    }

    #[test]
    fn keeps_zero_extended_width_ambiguity_visible() {
        let mut state = crate::workflow::create_test_state();
        for (index, (value, set)) in [
            (0, ValueSet::Discovery),
            (1, ValueSet::Discovery),
            (255, ValueSet::Discovery),
            (256, ValueSet::Validation),
            (257, ValueSet::Validation),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("obs-{index}");
            state.observations.push(Observation {
                id: id.clone(),
                capture_id: "capture".into(),
                source_index: index,
                source_offset: None,
                timestamp_ns: None,
                direction: None,
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: Vec::new(),
                bytes_hex: format!("0000{value:04x}"),
            });
            state.known_values.push(KnownValue {
                id: format!("value-{index}"),
                observation_id: id,
                variable: "number".into(),
                value,
                set,
            });
        }
        let result = infer_unsigned_field(&state, "number").unwrap();
        assert_eq!(result.validated_candidate_count, 2);
        assert_eq!(result.preferred_candidate_count, 1);
        let preferred = result
            .candidates
            .iter()
            .find(|candidate| candidate.preferred)
            .unwrap();
        assert_eq!((preferred.start, preferred.end), (2, 4));
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| (candidate.start, candidate.end) == (0, 4)
                    && candidate.validation_matches == 2
                    && !candidate.preferred)
        );
    }
}
