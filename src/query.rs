//! Bounded, stable navigation over a replayed investigation state.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::workflow::{Capture, KnownValue, Observation, State, Tag, from_hex, to_hex};

#[derive(Debug, Serialize)]
pub struct ObservationPreview<'a> {
    pub id: &'a str,
    pub capture_id: &'a str,
    pub trial_id: &'a str,
    pub source_index: usize,
    pub source_offset: Option<usize>,
    pub timestamp_ns: Option<u64>,
    pub direction: Option<&'a str>,
    pub length: usize,
    pub preview_hex: &'a str,
    pub tags: Vec<&'a Tag>,
    pub known_values: Vec<&'a KnownValue>,
}

#[derive(Debug, Serialize)]
pub struct ObservationPage<'a> {
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub observations: Vec<ObservationPreview<'a>>,
}

#[derive(Debug, Serialize)]
pub struct ByteSpan<'a> {
    pub revision: u64,
    pub observation_id: &'a str,
    pub capture_id: &'a str,
    pub artifact: &'a str,
    pub message_length: usize,
    pub start: usize,
    pub end: usize,
    pub coordinate_system: &'static str,
    pub source_file_offset: Option<usize>,
    pub bytes_hex: String,
    pub tags: Vec<&'a Tag>,
}

#[derive(Debug, Serialize)]
pub struct ChangedRange {
    pub start: usize,
    pub end: usize,
    pub left_hex: String,
    pub right_hex: String,
}

#[derive(Debug, Serialize)]
pub struct ObservationDiff<'a> {
    pub revision: u64,
    pub left_id: &'a str,
    pub right_id: &'a str,
    pub left_length: usize,
    pub right_length: usize,
    pub coordinate_system: &'static str,
    pub changed_ranges: Vec<ChangedRange>,
}

#[derive(Debug, Serialize)]
pub struct ChangedPosition {
    pub offset: usize,
    pub pairs_changed: usize,
}

#[derive(Debug, Serialize)]
pub struct TrialComparison<'a> {
    pub revision: u64,
    pub baseline_trial_id: &'a str,
    pub variant_trial_id: &'a str,
    pub pairing: &'static str,
    pub pair_count: usize,
    pub unmatched_baseline: usize,
    pub unmatched_variant: usize,
    pub changed_positions: Vec<ChangedPosition>,
    pub pairs: Vec<ObservationDiff<'a>>,
}

fn capture_for<'a>(state: &'a State, observation: &Observation) -> &'a Capture {
    state
        .captures
        .iter()
        .find(|capture| capture.id == observation.capture_id)
        .expect("replayed state has valid capture references")
}

fn tags_for<'a>(state: &'a State, observation: &Observation) -> Vec<&'a Tag> {
    state
        .tags
        .iter()
        .filter(|tag| tag.observation_id == observation.id)
        .collect()
}

fn values_for<'a>(state: &'a State, observation: &Observation) -> Vec<&'a KnownValue> {
    state
        .known_values
        .iter()
        .filter(|value| value.observation_id == observation.id)
        .collect()
}

pub fn list_observations<'a>(
    state: &'a State,
    trial_id: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<ObservationPage<'a>, String> {
    if limit == 0 || limit > 100 {
        return Err("limit must be between 1 and 100".into());
    }
    if let Some(id) = trial_id
        && !state.trials.iter().any(|trial| trial.id == id)
    {
        return Err(format!("unknown trial {id}"));
    }
    let matches: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| {
            trial_id.is_none_or(|id| capture_for(state, observation).trial_id == id)
        })
        .collect();
    let total = matches.len();
    let observations = matches
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|observation| ObservationPreview {
            id: &observation.id,
            capture_id: &observation.capture_id,
            trial_id: &capture_for(state, observation).trial_id,
            source_index: observation.source_index,
            source_offset: observation.source_offset,
            timestamp_ns: observation.timestamp_ns,
            direction: observation.direction.as_deref(),
            length: observation.bytes_hex.len() / 2,
            preview_hex: &observation.bytes_hex[..observation.bytes_hex.len().min(64)],
            tags: tags_for(state, observation),
            known_values: values_for(state, observation),
        })
        .collect();
    Ok(ObservationPage {
        revision: state.revision,
        total,
        offset,
        next_offset: (offset.saturating_add(limit) < total).then_some(offset + limit),
        observations,
    })
}

pub fn read_span<'a>(
    state: &'a State,
    observation_id: &str,
    start: usize,
    end: usize,
) -> Result<ByteSpan<'a>, String> {
    let observation = state
        .observations
        .iter()
        .find(|observation| observation.id == observation_id)
        .ok_or_else(|| format!("unknown observation {observation_id}"))?;
    let bytes = from_hex(&observation.bytes_hex)?;
    if start >= end || end > bytes.len() || end - start > 4096 {
        return Err(format!(
            "invalid span [{start}, {end}); message has {} bytes and maximum span is 4096",
            bytes.len()
        ));
    }
    let capture = capture_for(state, observation);
    Ok(ByteSpan {
        revision: state.revision,
        observation_id: &observation.id,
        capture_id: &capture.id,
        artifact: &capture.artifact,
        message_length: bytes.len(),
        start,
        end,
        coordinate_system: "message_bytes",
        source_file_offset: observation.source_offset.map(|offset| offset + start),
        bytes_hex: to_hex(&bytes[start..end]),
        tags: tags_for(state, observation),
    })
}

pub fn diff_observations<'a>(
    state: &'a State,
    left_id: &str,
    right_id: &str,
) -> Result<ObservationDiff<'a>, String> {
    let find = |id: &str| {
        state
            .observations
            .iter()
            .find(|observation| observation.id == id)
            .ok_or_else(|| format!("unknown observation {id}"))
    };
    let left_observation = find(left_id)?;
    let right_observation = find(right_id)?;
    let left = from_hex(&left_observation.bytes_hex)?;
    let right = from_hex(&right_observation.bytes_hex)?;
    let mut changed_ranges = Vec::new();
    let width = left.len().max(right.len());
    let mut index = 0;
    while index < width {
        if left.get(index) == right.get(index) {
            index += 1;
            continue;
        }
        let start = index;
        while index < width && left.get(index) != right.get(index) {
            index += 1;
        }
        changed_ranges.push(ChangedRange {
            start,
            end: index,
            left_hex: to_hex(&left[start.min(left.len())..index.min(left.len())]),
            right_hex: to_hex(&right[start.min(right.len())..index.min(right.len())]),
        });
    }
    Ok(ObservationDiff {
        revision: state.revision,
        left_id: &left_observation.id,
        right_id: &right_observation.id,
        left_length: left.len(),
        right_length: right.len(),
        coordinate_system: "message_bytes",
        changed_ranges,
    })
}

/// Pair observations within each direction by their order in the event log.
/// This is a descriptive comparison, not evidence of causal correspondence.
pub fn compare_trials<'a>(
    state: &'a State,
    baseline_id: &str,
    variant_id: &str,
) -> Result<TrialComparison<'a>, String> {
    let baseline = state
        .trials
        .iter()
        .find(|trial| trial.id == baseline_id)
        .ok_or_else(|| format!("unknown trial {baseline_id}"))?;
    let variant = state
        .trials
        .iter()
        .find(|trial| trial.id == variant_id)
        .ok_or_else(|| format!("unknown trial {variant_id}"))?;
    if baseline.id == variant.id {
        return Err("comparison requires two distinct trials".into());
    }
    if baseline.experiment_id != variant.experiment_id {
        return Err("trials belong to different experiments".into());
    }
    let group = |trial_id: &str| -> BTreeMap<String, Vec<&Observation>> {
        let mut groups = BTreeMap::<String, Vec<&Observation>>::new();
        for observation in &state.observations {
            if capture_for(state, observation).trial_id == trial_id {
                groups
                    .entry(observation.direction.clone().unwrap_or_default())
                    .or_default()
                    .push(observation);
            }
        }
        groups
    };
    let baseline_groups = group(baseline_id);
    let variant_groups = group(variant_id);
    let directions: BTreeSet<_> = baseline_groups
        .keys()
        .chain(variant_groups.keys())
        .collect();
    let mut pairs = Vec::new();
    let mut unmatched_baseline = 0;
    let mut unmatched_variant = 0;
    let mut changed_counts = BTreeMap::<usize, usize>::new();
    for direction in directions {
        let left = baseline_groups
            .get(direction)
            .map_or(&[][..], Vec::as_slice);
        let right = variant_groups.get(direction).map_or(&[][..], Vec::as_slice);
        unmatched_baseline += left.len().saturating_sub(right.len());
        unmatched_variant += right.len().saturating_sub(left.len());
        for (baseline_observation, variant_observation) in left.iter().zip(right) {
            if pairs.len() == 100 {
                return Err("trial comparison exceeds 100 pairs; use observation diff on a smaller selection".into());
            }
            let diff = diff_observations(state, &baseline_observation.id, &variant_observation.id)?;
            for range in &diff.changed_ranges {
                for offset in range.start..range.end {
                    *changed_counts.entry(offset).or_default() += 1;
                }
            }
            pairs.push(diff);
        }
    }
    let changed_positions = changed_counts
        .into_iter()
        .map(|(offset, pairs_changed)| ChangedPosition {
            offset,
            pairs_changed,
        })
        .collect();
    Ok(TrialComparison {
        revision: state.revision,
        baseline_trial_id: &baseline.id,
        variant_trial_id: &variant.id,
        pairing: "same_direction_then_source_order",
        pair_count: pairs.len(),
        unmatched_baseline,
        unmatched_variant,
        changed_positions,
        pairs,
    })
}
