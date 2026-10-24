//! Bounded, stable navigation over a replayed investigation state.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
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
    pub varint_runs: usize,
    pub delimiter_runs: usize,
    pub frames: usize,
    pub hypotheses: usize,
    pub actions: usize,
    pub tags: usize,
    pub tagged_observations: usize,
    pub window_tags: usize,
    pub capture_tag_batches: usize,
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
    pub schema_version: u32,
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
        schema_version: state.schema_version,
        revision: state.revision,
        total,
        offset,
        next_offset: (offset.saturating_add(limit) < total).then_some(offset + limit),
        order: "newest_first",
        trials,
    })
}

#[derive(Debug, Serialize)]
pub struct HypothesisPreview {
    pub id: String,
    pub claim: String,
    pub claim_truncated: bool,
    pub score: Option<f64>,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub evidence_ids_omitted: usize,
    pub counterexample_count: usize,
    pub counterexample_ids: Vec<String>,
    pub counterexample_ids_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct HypothesisPage {
    pub schema_version: u32,
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub order: &'static str,
    pub hypotheses: Vec<HypothesisPreview>,
}

#[derive(Debug, Serialize)]
pub struct ExperimentPreview {
    pub id: String,
    pub question: String,
    pub question_truncated: bool,
    pub prediction: String,
    pub prediction_truncated: bool,
    pub hypothesis_count: usize,
    pub hypothesis_ids: Vec<String>,
    pub hypothesis_ids_omitted: usize,
    pub trial_count: usize,
    pub capture_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ExperimentPage {
    pub schema_version: u32,
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub order: &'static str,
    pub experiments: Vec<ExperimentPreview>,
}

#[derive(Debug, Serialize)]
pub struct DecisionPreview {
    pub id: String,
    pub text: String,
    pub text_truncated: bool,
    pub evidence_count: usize,
    pub evidence_ids: Vec<String>,
    pub evidence_ids_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct DecisionPage {
    pub schema_version: u32,
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub order: &'static str,
    pub decisions: Vec<DecisionPreview>,
}

fn valid_page_limit(limit: usize) -> Result<(), String> {
    if limit == 0 || limit > 100 {
        Err("limit must be between 1 and 100".into())
    } else {
        Ok(())
    }
}

fn preview_text(text: &str) -> (String, bool) {
    (text.chars().take(200).collect(), text.chars().count() > 200)
}

pub fn list_hypotheses(
    state: &State,
    offset: usize,
    limit: usize,
) -> Result<HypothesisPage, String> {
    valid_page_limit(limit)?;
    let total = state.hypotheses.len();
    let hypotheses = state
        .hypotheses
        .iter()
        .rev()
        .skip(offset)
        .take(limit)
        .map(|hypothesis| {
            let (claim, claim_truncated) = preview_text(&hypothesis.claim);
            HypothesisPreview {
                id: hypothesis.id.clone(),
                claim,
                claim_truncated,
                score: hypothesis.score,
                evidence_count: hypothesis.evidence.len(),
                evidence_ids: hypothesis.evidence.iter().take(10).cloned().collect(),
                evidence_ids_omitted: hypothesis.evidence.len().saturating_sub(10),
                counterexample_count: hypothesis.counterexamples.len(),
                counterexample_ids: hypothesis
                    .counterexamples
                    .iter()
                    .take(10)
                    .cloned()
                    .collect(),
                counterexample_ids_omitted: hypothesis.counterexamples.len().saturating_sub(10),
            }
        })
        .collect();
    Ok(HypothesisPage {
        schema_version: state.schema_version,
        revision: state.revision,
        total,
        offset,
        next_offset: (offset.saturating_add(limit) < total).then_some(offset + limit),
        order: "newest_first",
        hypotheses,
    })
}

pub fn list_experiments(
    state: &State,
    offset: usize,
    limit: usize,
) -> Result<ExperimentPage, String> {
    valid_page_limit(limit)?;
    let total = state.experiments.len();
    let mut trial_counts = BTreeMap::<&str, usize>::new();
    let mut capture_counts = BTreeMap::<&str, usize>::new();
    let trial_experiments: BTreeMap<_, _> = state
        .trials
        .iter()
        .map(|trial| {
            *trial_counts
                .entry(trial.experiment_id.as_str())
                .or_default() += 1;
            (trial.id.as_str(), trial.experiment_id.as_str())
        })
        .collect();
    for capture in &state.captures {
        if let Some(experiment_id) = trial_experiments.get(capture.trial_id.as_str()) {
            *capture_counts.entry(experiment_id).or_default() += 1;
        }
    }
    let experiments = state
        .experiments
        .iter()
        .rev()
        .skip(offset)
        .take(limit)
        .map(|experiment| {
            let (question, question_truncated) = preview_text(&experiment.question);
            let (prediction, prediction_truncated) = preview_text(&experiment.prediction);
            ExperimentPreview {
                id: experiment.id.clone(),
                question,
                question_truncated,
                prediction,
                prediction_truncated,
                hypothesis_count: experiment.hypothesis_ids.len(),
                hypothesis_ids: experiment.hypothesis_ids.iter().take(10).cloned().collect(),
                hypothesis_ids_omitted: experiment.hypothesis_ids.len().saturating_sub(10),
                trial_count: *trial_counts.get(experiment.id.as_str()).unwrap_or(&0),
                capture_count: *capture_counts.get(experiment.id.as_str()).unwrap_or(&0),
            }
        })
        .collect();
    Ok(ExperimentPage {
        schema_version: state.schema_version,
        revision: state.revision,
        total,
        offset,
        next_offset: (offset.saturating_add(limit) < total).then_some(offset + limit),
        order: "newest_first",
        experiments,
    })
}

pub fn list_decisions(state: &State, offset: usize, limit: usize) -> Result<DecisionPage, String> {
    valid_page_limit(limit)?;
    let total = state.decisions.len();
    let decisions = state
        .decisions
        .iter()
        .rev()
        .skip(offset)
        .take(limit)
        .map(|decision| {
            let (text, text_truncated) = preview_text(&decision.text);
            DecisionPreview {
                id: decision.id.clone(),
                text,
                text_truncated,
                evidence_count: decision.evidence_ids.len(),
                evidence_ids: decision.evidence_ids.iter().take(10).cloned().collect(),
                evidence_ids_omitted: decision.evidence_ids.len().saturating_sub(10),
            }
        })
        .collect();
    Ok(DecisionPage {
        schema_version: state.schema_version,
        revision: state.revision,
        total,
        offset,
        next_offset: (offset.saturating_add(limit) < total).then_some(offset + limit),
        order: "newest_first",
        decisions,
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
    for run in &state.varint_runs {
        if let Some(trial_id) = observation_trials.get(run.observation_id.as_str()) {
            *trial_frames.entry(trial_id).or_default() += run.records.len();
        }
    }
    for run in &state.delimiter_runs {
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
            varint_runs: state.varint_runs.len(),
            delimiter_runs: state.delimiter_runs.len(),
            frames: state
                .framing_runs
                .iter()
                .map(|run| run.records.len())
                .sum::<usize>()
                + state
                    .varint_runs
                    .iter()
                    .map(|run| run.records.len())
                    .sum::<usize>()
                + state
                    .delimiter_runs
                    .iter()
                    .map(|run| run.records.len())
                    .sum::<usize>(),
            hypotheses: state.hypotheses.len(),
            actions: state.actions.len(),
            tags: state.tags.len(),
            tagged_observations: tagged_observations.len(),
            window_tags: state.window_tags.len(),
            capture_tag_batches: state.capture_tag_batches.len(),
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
    pub schema_version: u32,
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub observations: Vec<ObservationPreview<'a>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ObservationSearch {
    pub trial_id: Option<String>,
    pub experiment_id: Option<String>,
    pub capture_id: Option<String>,
    pub framing_key: Option<String>,
    pub format: Option<String>,
    pub direction: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub timestamp_start_ns: Option<String>,
    pub timestamp_end_ns: Option<String>,
    pub min_bytes: Option<usize>,
    pub max_bytes: Option<usize>,
    pub tag_phase: Option<String>,
    pub tag_label: Option<String>,
    pub stream_gap_before: Option<bool>,
    pub offset: usize,
    pub limit: usize,
}

impl Default for ObservationSearch {
    fn default() -> Self {
        Self {
            trial_id: None,
            experiment_id: None,
            capture_id: None,
            framing_key: None,
            format: None,
            direction: None,
            source_port: None,
            destination_port: None,
            timestamp_start_ns: None,
            timestamp_end_ns: None,
            min_bytes: None,
            max_bytes: None,
            tag_phase: None,
            tag_label: None,
            stream_gap_before: None,
            offset: 0,
            limit: 50,
        }
    }
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
    search_observations(
        state,
        &ObservationSearch {
            trial_id: trial_id.map(str::to_owned),
            offset,
            limit,
            ..ObservationSearch::default()
        },
    )
}

pub fn search_observations<'a>(
    state: &'a State,
    query: &ObservationSearch,
) -> Result<ObservationPage<'a>, String> {
    if query.limit == 0 || query.limit > 100 {
        return Err("limit must be between 1 and 100".into());
    }
    if let Some(id) = &query.trial_id
        && !state.trials.iter().any(|trial| trial.id == *id)
    {
        return Err(format!("unknown trial {id}"));
    }
    if let Some(id) = &query.experiment_id
        && !state
            .experiments
            .iter()
            .any(|experiment| experiment.id == *id)
    {
        return Err(format!("unknown experiment {id}"));
    }
    if let Some(id) = &query.capture_id
        && !state.captures.iter().any(|capture| capture.id == *id)
    {
        return Err(format!("unknown capture {id}"));
    }
    let framing_observation_id = if let Some(key) = &query.framing_key {
        Some(
            state
                .framing_runs
                .iter()
                .find(|run| run.key == *key)
                .map(|run| run.observation_id.as_str())
                .or_else(|| {
                    state
                        .varint_runs
                        .iter()
                        .find(|run| run.key == *key)
                        .map(|run| run.observation_id.as_str())
                })
                .or_else(|| {
                    state
                        .delimiter_runs
                        .iter()
                        .find(|run| run.key == *key)
                        .map(|run| run.observation_id.as_str())
                })
                .ok_or_else(|| format!("unknown frame run key {key}"))?,
        )
    } else {
        None
    };
    let parse_ns = |value: Option<&str>, name: &str| -> Result<Option<u64>, String> {
        value
            .map(|text| {
                text.parse::<u64>()
                    .map_err(|_| format!("{name} must be a decimal UTC nanosecond string"))
            })
            .transpose()
    };
    let timestamp_start_ns = parse_ns(query.timestamp_start_ns.as_deref(), "timestamp_start_ns")?;
    let timestamp_end_ns = parse_ns(query.timestamp_end_ns.as_deref(), "timestamp_end_ns")?;
    if timestamp_start_ns
        .zip(timestamp_end_ns)
        .is_some_and(|(start, end)| start >= end)
    {
        return Err("timestamp range must be half-open with start before end".into());
    }
    if query
        .min_bytes
        .zip(query.max_bytes)
        .is_some_and(|(min, max)| min > max)
    {
        return Err("min_bytes must not exceed max_bytes".into());
    }
    let capture_by_id: BTreeMap<_, _> = state
        .captures
        .iter()
        .map(|capture| (capture.id.as_str(), capture))
        .collect();
    let trial_by_id: BTreeMap<_, _> = state
        .trials
        .iter()
        .map(|trial| (trial.id.as_str(), trial))
        .collect();
    let mut tags_by_observation: BTreeMap<&str, Vec<&Tag>> = BTreeMap::new();
    for tag in &state.tags {
        tags_by_observation
            .entry(&tag.observation_id)
            .or_default()
            .push(tag);
    }
    let mut total = 0;
    let mut selected = Vec::new();
    for observation in &state.observations {
        let capture = capture_by_id
            .get(observation.capture_id.as_str())
            .expect("replayed state has valid capture references");
        if query
            .trial_id
            .as_ref()
            .is_some_and(|id| capture.trial_id != *id)
            || query
                .capture_id
                .as_ref()
                .is_some_and(|id| capture.id != *id)
            || query
                .format
                .as_ref()
                .is_some_and(|format| capture.format != *format)
            || query.experiment_id.as_ref().is_some_and(|id| {
                trial_by_id
                    .get(capture.trial_id.as_str())
                    .is_none_or(|trial| trial.experiment_id != *id)
            })
            || framing_observation_id.is_some_and(|id| observation.id != id)
            || query.direction.as_ref().is_some_and(|direction| {
                if direction == "<unknown>" {
                    observation.direction.is_some()
                } else {
                    observation.direction.as_deref() != Some(direction.as_str())
                }
            })
            || query
                .source_port
                .is_some_and(|port| observation.source_port != Some(port))
            || query
                .destination_port
                .is_some_and(|port| observation.destination_port != Some(port))
            || query
                .stream_gap_before
                .is_some_and(|gap| observation.stream_gap_before != gap)
            || query
                .min_bytes
                .is_some_and(|min| observation.bytes_hex.len() / 2 < min)
            || query
                .max_bytes
                .is_some_and(|max| observation.bytes_hex.len() / 2 > max)
            || timestamp_start_ns.is_some_and(|start| {
                observation
                    .timestamp_ns
                    .is_none_or(|timestamp| timestamp < start)
            })
            || timestamp_end_ns.is_some_and(|end| {
                observation
                    .timestamp_ns
                    .is_none_or(|timestamp| timestamp >= end)
            })
        {
            continue;
        }
        if query.tag_phase.is_some() || query.tag_label.is_some() {
            let matching_tag = tags_by_observation
                .get(observation.id.as_str())
                .is_some_and(|tags| {
                    tags.iter().any(|tag| {
                        query
                            .tag_phase
                            .as_ref()
                            .is_none_or(|phase| tag.phase == *phase)
                            && query
                                .tag_label
                                .as_ref()
                                .is_none_or(|label| tag.label == *label)
                    })
                });
            if !matching_tag {
                continue;
            }
        }
        if total >= query.offset && selected.len() < query.limit {
            selected.push(observation);
        }
        total += 1;
    }
    let observations = selected
        .into_iter()
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
        schema_version: state.schema_version,
        revision: state.revision,
        total,
        offset: query.offset,
        next_offset: (query.offset.saturating_add(query.limit) < total)
            .then_some(query.offset + query.limit),
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
    use crate::workflow::{Capture, Decision, Experiment, Hypothesis, Tag, Trial};

    #[test]
    fn record_pages_bound_unicode_text_and_evidence_lists() {
        let mut state = crate::workflow::create_test_state();
        state.hypotheses.push(Hypothesis {
            id: "hyp-1".into(),
            claim: "🦀".repeat(201),
            score: Some(0.4),
            evidence: (0..12).map(|index| format!("obs-{index}")).collect(),
            counterexamples: vec!["obs-counterexample".into()],
        });
        state.experiments.push(Experiment {
            id: "exp-1".into(),
            question: "Q".repeat(201),
            hypothesis_ids: vec!["hyp-1".into()],
            prediction: "P".repeat(201),
        });
        state.trials.push(Trial {
            id: "trial-1".into(),
            experiment_id: "exp-1".into(),
            role: "discovery".into(),
            changed_factor: "sequence".into(),
        });
        state.captures.push(Capture {
            id: "cap-1".into(),
            trial_id: "trial-1".into(),
            format: "pcap-icmp".into(),
            source: "test".into(),
            sha256: String::new(),
            artifact: String::new(),
            observation_count: 0,
            run_key: None,
        });
        state.decisions.push(Decision {
            id: "decision-1".into(),
            text: "D".repeat(201),
            evidence_ids: (0..12).map(|index| format!("obs-{index}")).collect(),
        });
        let hypotheses = list_hypotheses(&state, 0, 1).unwrap();
        assert_eq!(hypotheses.hypotheses[0].claim.chars().count(), 200);
        assert!(hypotheses.hypotheses[0].claim_truncated);
        assert_eq!(hypotheses.hypotheses[0].evidence_ids.len(), 10);
        assert_eq!(hypotheses.hypotheses[0].evidence_ids_omitted, 2);
        let experiments = list_experiments(&state, 0, 1).unwrap();
        assert_eq!(experiments.experiments[0].trial_count, 1);
        assert_eq!(experiments.experiments[0].capture_count, 1);
        assert!(experiments.experiments[0].prediction_truncated);
        let decisions = list_decisions(&state, 0, 1).unwrap();
        assert_eq!(decisions.decisions[0].evidence_ids_omitted, 2);
        assert!(decisions.decisions[0].text_truncated);
        assert!(list_hypotheses(&state, 0, 0).is_err());
        assert!(list_experiments(&state, 0, 101).is_err());
    }

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
                label: if index == 0 { "alpha" } else { "beta" }.into(),
                phase: if index == 0 { "stimulus" } else { "response" }.into(),
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
        let matching = ObservationSearch {
            tag_phase: Some("stimulus".into()),
            tag_label: Some("alpha".into()),
            ..ObservationSearch::default()
        };
        assert_eq!(search_observations(&state, &matching).unwrap().total, 1);
        let crossed = ObservationSearch {
            tag_phase: Some("stimulus".into()),
            tag_label: Some("beta".into()),
            ..ObservationSearch::default()
        };
        assert_eq!(search_observations(&state, &crossed).unwrap().total, 0);
    }
}
