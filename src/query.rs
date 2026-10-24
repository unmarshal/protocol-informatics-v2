//! Bounded, stable navigation over a replayed investigation state.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::reassembly::SourceSpan;
use crate::workflow::{
    Capture, CaptureRunStatus, KnownValue, Observation, State, Tag, from_hex, to_hex,
};

const MAX_SUMMARY_GROUPS: usize = 20;

#[derive(Debug, Serialize)]
pub struct CorpusCounts {
    pub experiments: usize,
    pub trials: usize,
    pub captures: usize,
    pub observations: usize,
    pub observation_bytes: u64,
    pub framing_runs: usize,
    pub frames: usize,
    pub hypotheses: usize,
    pub actions: usize,
    pub tags: usize,
    pub tagged_observations: usize,
    pub window_tags: usize,
    pub known_values: usize,
    pub frame_known_values: usize,
    pub analyses: usize,
    pub decisions: usize,
    pub reserved_capture_runs: usize,
    pub completed_capture_runs: usize,
    pub failed_capture_runs: usize,
}

#[derive(Debug, Serialize)]
pub struct ObservationLengths {
    pub min: Option<usize>,
    pub median: Option<usize>,
    pub p90: Option<usize>,
    pub max: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct FormatCount {
    pub format: String,
    pub captures: usize,
    pub observations: usize,
}

#[derive(Debug, Serialize)]
pub struct DirectionCount {
    pub direction: String,
    pub observations: usize,
}

#[derive(Debug, Serialize)]
pub struct RecentTrial {
    pub id: String,
    pub role: String,
    pub role_truncated: bool,
    pub captures: usize,
    pub observations: usize,
    pub frames: usize,
    pub actions: usize,
    pub tagged_observations: usize,
}

#[derive(Debug, Serialize)]
pub struct CorpusSummary {
    pub schema_version: u32,
    pub revision: u64,
    pub question: String,
    pub question_truncated: bool,
    pub counts: CorpusCounts,
    pub observation_lengths_bytes: ObservationLengths,
    pub timestamp_range_ns: Option<[String; 2]>,
    pub missing_timestamp_observations: usize,
    pub stream_gap_observations: usize,
    pub formats: Vec<FormatCount>,
    pub top_directions: Vec<DirectionCount>,
    pub directions_omitted: usize,
    pub other_direction_observations: usize,
    pub recent_trials: Vec<RecentTrial>,
    pub older_trials_omitted: usize,
    pub reserved_capture_keys: Vec<String>,
    pub reserved_capture_keys_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct TrialPreview {
    pub id: String,
    pub experiment_id: String,
    pub role: String,
    pub role_truncated: bool,
    pub changed_factor: String,
    pub changed_factor_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct TrialPage {
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub order: &'static str,
    pub trials: Vec<TrialPreview>,
}

pub fn list_trials(state: &State, offset: usize, limit: usize) -> Result<TrialPage, String> {
    if limit == 0 || limit > 100 {
        return Err("limit must be between 1 and 100".into());
    }
    let total = state.trials.len();
    let trials = state
        .trials
        .iter()
        .rev()
        .skip(offset)
        .take(limit)
        .map(|trial| TrialPreview {
            id: trial.id.clone(),
            experiment_id: trial.experiment_id.clone(),
            role: trial.role.chars().take(80).collect(),
            role_truncated: trial.role.chars().count() > 80,
            changed_factor: trial.changed_factor.chars().take(200).collect(),
            changed_factor_truncated: trial.changed_factor.chars().count() > 200,
        })
        .collect();
    Ok(TrialPage {
        revision: state.revision,
        total,
        offset,
        next_offset: (offset.saturating_add(limit) < total).then_some(offset + limit),
        order: "newest_first",
        trials,
    })
}

pub fn corpus_summary(state: &State) -> CorpusSummary {
    let question: String = state.question.chars().take(200).collect();
    let capture_trials: BTreeMap<_, _> = state
        .captures
        .iter()
        .map(|capture| (capture.id.as_str(), capture.trial_id.as_str()))
        .collect();
    let observation_trials: BTreeMap<_, _> = state
        .observations
        .iter()
        .filter_map(|observation| {
            capture_trials
                .get(observation.capture_id.as_str())
                .map(|trial_id| (observation.id.as_str(), *trial_id))
        })
        .collect();

    let mut lengths: Vec<_> = state
        .observations
        .iter()
        .map(|observation| observation.bytes_hex.len() / 2)
        .collect();
    lengths.sort_unstable();
    let nearest_rank = |percent: usize| {
        let rank = lengths.len().saturating_mul(percent).saturating_add(99) / 100;
        lengths.get(rank.saturating_sub(1)).copied()
    };
    let observation_lengths_bytes = ObservationLengths {
        min: lengths.first().copied(),
        median: nearest_rank(50),
        p90: nearest_rank(90),
        max: lengths.last().copied(),
    };
    let timestamps: Vec<_> = state
        .observations
        .iter()
        .filter_map(|observation| observation.timestamp_ns)
        .collect();
    let timestamp_range_ns = timestamps
        .iter()
        .min()
        .zip(timestamps.iter().max())
        .map(|(min, max)| [min.to_string(), max.to_string()]);
    let mut format_counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for capture in &state.captures {
        let entry = format_counts.entry(capture.format.clone()).or_default();
        entry.0 += 1;
        entry.1 += capture.observation_count;
    }
    let formats = format_counts
        .into_iter()
        .map(|(format, (captures, observations))| FormatCount {
            format,
            captures,
            observations,
        })
        .collect();
    let mut direction_counts: BTreeMap<String, usize> = BTreeMap::new();
    for observation in &state.observations {
        *direction_counts
            .entry(
                observation
                    .direction
                    .clone()
                    .unwrap_or_else(|| "<unknown>".into()),
            )
            .or_default() += 1;
    }
    let mut directions: Vec<_> = direction_counts
        .into_iter()
        .map(|(direction, observations)| DirectionCount {
            direction,
            observations,
        })
        .collect();
    directions.sort_by(|a, b| {
        b.observations
            .cmp(&a.observations)
            .then_with(|| a.direction.cmp(&b.direction))
    });
    let other_direction_observations = directions
        .iter()
        .skip(MAX_SUMMARY_GROUPS)
        .map(|item| item.observations)
        .sum();
    let directions_omitted = directions.len().saturating_sub(MAX_SUMMARY_GROUPS);
    directions.truncate(MAX_SUMMARY_GROUPS);

    let mut trial_captures: BTreeMap<&str, usize> = BTreeMap::new();
    let mut trial_observations: BTreeMap<&str, usize> = BTreeMap::new();
    let mut trial_frames: BTreeMap<&str, usize> = BTreeMap::new();
    let mut trial_actions: BTreeMap<&str, usize> = BTreeMap::new();
    let mut trial_tagged: BTreeMap<&str, usize> = BTreeMap::new();
    for capture in &state.captures {
        *trial_captures.entry(&capture.trial_id).or_default() += 1;
    }
    for trial_id in observation_trials.values() {
        *trial_observations.entry(trial_id).or_default() += 1;
    }
    for run in &state.framing_runs {
        if let Some(trial_id) = observation_trials.get(run.observation_id.as_str()) {
            *trial_frames.entry(trial_id).or_default() += run.records.len();
        }
    }
    for action in &state.actions {
        *trial_actions.entry(&action.trial_id).or_default() += 1;
    }
    let tagged_observations: BTreeSet<_> = state
        .tags
        .iter()
        .map(|tag| tag.observation_id.as_str())
        .collect();
    for observation_id in &tagged_observations {
        if let Some(trial_id) = observation_trials.get(observation_id) {
            *trial_tagged.entry(trial_id).or_default() += 1;
        }
    }
    let recent_trials = state
        .trials
        .iter()
        .rev()
        .take(MAX_SUMMARY_GROUPS)
        .map(|trial| RecentTrial {
            id: trial.id.clone(),
            role: trial.role.chars().take(80).collect(),
            role_truncated: trial.role.chars().count() > 80,
            captures: trial_captures.get(trial.id.as_str()).copied().unwrap_or(0),
            observations: trial_observations
                .get(trial.id.as_str())
                .copied()
                .unwrap_or(0),
            frames: trial_frames.get(trial.id.as_str()).copied().unwrap_or(0),
            actions: trial_actions.get(trial.id.as_str()).copied().unwrap_or(0),
            tagged_observations: trial_tagged.get(trial.id.as_str()).copied().unwrap_or(0),
        })
        .collect();
    let reserved_capture_keys: Vec<_> = state
        .capture_runs
        .iter()
        .filter(|run| run.status == CaptureRunStatus::Reserved)
        .map(|run| run.key.clone())
        .collect();
    let reserved_capture_keys_omitted = reserved_capture_keys
        .len()
        .saturating_sub(MAX_SUMMARY_GROUPS);
    CorpusSummary {
        schema_version: state.schema_version,
        revision: state.revision,
        question,
        question_truncated: state.question.chars().count() > 200,
        counts: CorpusCounts {
            experiments: state.experiments.len(),
            trials: state.trials.len(),
            captures: state.captures.len(),
            observations: state.observations.len(),
            observation_bytes: lengths.iter().map(|length| *length as u64).sum(),
            framing_runs: state.framing_runs.len(),
            frames: state.framing_runs.iter().map(|run| run.records.len()).sum(),
            hypotheses: state.hypotheses.len(),
            actions: state.actions.len(),
            tags: state.tags.len(),
            tagged_observations: tagged_observations.len(),
            window_tags: state.window_tags.len(),
            known_values: state.known_values.len(),
            frame_known_values: state.frame_known_values.len(),
            analyses: state.analyses.len(),
            decisions: state.decisions.len(),
            reserved_capture_runs: state
                .capture_runs
                .iter()
                .filter(|run| run.status == CaptureRunStatus::Reserved)
                .count(),
            completed_capture_runs: state
                .capture_runs
                .iter()
                .filter(|run| run.status == CaptureRunStatus::Completed)
                .count(),
            failed_capture_runs: state
                .capture_runs
                .iter()
                .filter(|run| run.status == CaptureRunStatus::Failed)
                .count(),
        },
        observation_lengths_bytes,
        timestamp_range_ns,
        missing_timestamp_observations: state.observations.len().saturating_sub(timestamps.len()),
        stream_gap_observations: state
            .observations
            .iter()
            .filter(|observation| observation.stream_gap_before)
            .count(),
        formats,
        top_directions: directions,
        directions_omitted,
        other_direction_observations,
        recent_trials,
        older_trials_omitted: state.trials.len().saturating_sub(MAX_SUMMARY_GROUPS),
        reserved_capture_keys: reserved_capture_keys
            .into_iter()
            .take(MAX_SUMMARY_GROUPS)
            .collect(),
        reserved_capture_keys_omitted,
    }
}

#[derive(Debug, Serialize)]
pub struct ObservationPreview<'a> {
    pub id: &'a str,
    pub capture_id: &'a str,
    pub trial_id: &'a str,
    pub source_index: usize,
    pub source_offset: Option<usize>,
    pub timestamp_ns: Option<u64>,
    pub direction: Option<&'a str>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub tcp_sequence: Option<u32>,
    pub stream_gap_before: bool,
    pub source_span_count: usize,
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
    pub source_spans: Vec<SourceSpan>,
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
            source_port: observation.source_port,
            destination_port: observation.destination_port,
            tcp_sequence: observation.tcp_sequence,
            stream_gap_before: observation.stream_gap_before,
            source_span_count: observation.source_spans.len(),
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
        source_spans: observation
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
            .collect(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{Capture, Tag, Trial};

    #[test]
    fn summary_caps_groups_and_counts_distinct_tagged_observations() {
        let mut state = crate::workflow::create_test_state();
        state.question = "x".repeat(250);
        for index in 0..25 {
            let trial_id = format!("trial-{index:02}");
            let capture_id = format!("cap-{index:02}");
            let observation_id = format!("obs-{index:02}");
            state.trials.push(Trial {
                id: trial_id.clone(),
                experiment_id: "exp".into(),
                role: format!("role-{index}"),
                changed_factor: "factor".into(),
            });
            state.captures.push(Capture {
                id: capture_id.clone(),
                trial_id,
                format: "binary".into(),
                source: "fixture".into(),
                sha256: String::new(),
                artifact: String::new(),
                observation_count: 1,
                run_key: None,
            });
            state.observations.push(Observation {
                id: observation_id,
                capture_id,
                source_index: 0,
                source_offset: Some(0),
                timestamp_ns: Some(index as u64),
                direction: Some(format!("direction-{index:02}")),
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: Vec::new(),
                bytes_hex: to_hex(&vec![0; index + 1]),
            });
        }
        for index in 0..2 {
            state.tags.push(Tag {
                id: format!("tag-{index}"),
                observation_id: "obs-00".into(),
                label: "same observation".into(),
                phase: "stimulus".into(),
                action_id: None,
            });
        }
        let summary = corpus_summary(&state);
        assert_eq!(summary.question.chars().count(), 200);
        assert!(summary.question_truncated);
        assert_eq!(summary.counts.tags, 2);
        assert_eq!(summary.counts.tagged_observations, 1);
        assert_eq!(summary.counts.observation_bytes, 325);
        assert_eq!(summary.observation_lengths_bytes.min, Some(1));
        assert_eq!(summary.observation_lengths_bytes.median, Some(13));
        assert_eq!(summary.observation_lengths_bytes.p90, Some(23));
        assert_eq!(summary.observation_lengths_bytes.max, Some(25));
        assert_eq!(summary.timestamp_range_ns, Some(["0".into(), "24".into()]));
        assert_eq!(summary.top_directions.len(), 20);
        assert_eq!(summary.directions_omitted, 5);
        assert_eq!(summary.other_direction_observations, 5);
        assert_eq!(summary.recent_trials.len(), 20);
        assert_eq!(summary.recent_trials[0].id, "trial-24");
        assert_eq!(summary.older_trials_omitted, 5);
        let page = list_trials(&state, 20, 5).unwrap();
        assert_eq!(page.order, "newest_first");
        assert_eq!(page.total, 25);
        assert_eq!(page.trials[0].id, "trial-04");
        assert_eq!(page.trials[4].id, "trial-00");
        assert_eq!(page.next_offset, None);
    }
}
