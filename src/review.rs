//! Bounded evidence review for one controlled discovery/validation trial pair.
//! It suggests next checks without assigning probabilities or approving a grammar.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::workflow::{ExperimentAssessment, State};
use crate::{clustering, delimiter, framing, tlv, varint};

const MAX_REPORTED_CANDIDATES: usize = 3;
const MAX_EVIDENCE_IDS: usize = 8;

#[derive(Debug, Serialize)]
pub struct CandidateSummary {
    pub config: Value,
    pub validation_matches: usize,
    pub validation_total: usize,
    pub counterexample_observation_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MethodReview {
    pub method: &'static str,
    pub status: &'static str,
    pub error: Option<String>,
    pub candidate_count: Option<usize>,
    pub reported_candidate_count: usize,
    pub fully_validated_reported_count: usize,
    pub best_reported_validation_matches: Option<usize>,
    pub validation_total: usize,
    pub candidates_truncated: bool,
    pub candidate_summaries: Vec<CandidateSummary>,
    pub candidate_summaries_omitted: usize,
    pub counterexample_observation_ids: Vec<String>,
    pub reported_counterexample_ids_omitted: usize,
    pub counterexample_ids_partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifiability: Option<Value>,
}

impl MethodReview {
    fn unavailable(method: &'static str, validation_total: usize, error: String) -> Self {
        Self {
            method,
            status: "unavailable",
            error: Some(error),
            candidate_count: None,
            reported_candidate_count: 0,
            fully_validated_reported_count: 0,
            best_reported_validation_matches: None,
            validation_total,
            candidates_truncated: false,
            candidate_summaries: Vec::new(),
            candidate_summaries_omitted: 0,
            counterexample_observation_ids: Vec::new(),
            reported_counterexample_ids_omitted: 0,
            counterexample_ids_partial: false,
            identifiability: None,
        }
    }

    fn from_result<T: Serialize>(
        method: &'static str,
        validation_total: usize,
        result: Result<T, String>,
    ) -> Self {
        let report = match result {
            Ok(report) => match serde_json::to_value(report) {
                Ok(value) => value,
                Err(error) => {
                    return Self::unavailable(method, validation_total, error.to_string());
                }
            },
            Err(error) => return Self::unavailable(method, validation_total, error),
        };
        let Some(candidate_count) = report["candidate_count"].as_u64() else {
            return Self::unavailable(
                method,
                validation_total,
                "inference result has no candidate count".into(),
            );
        };
        let Some(candidates) = report["candidates"].as_array() else {
            return Self::unavailable(
                method,
                validation_total,
                "inference result has no candidate list".into(),
            );
        };
        let candidate_count = candidate_count as usize;
        let mut summaries = Vec::new();
        let mut all_counterexamples = BTreeSet::new();
        let mut counterexample_ids_partial = candidate_count > candidates.len();
        for candidate in candidates {
            let Some(config) = candidate.get("config") else {
                return Self::unavailable(
                    method,
                    validation_total,
                    "inference candidate has no configuration".into(),
                );
            };
            let Some(validation_matches) = candidate["validation_matches"].as_u64() else {
                return Self::unavailable(
                    method,
                    validation_total,
                    "inference candidate has no validation match count".into(),
                );
            };
            if validation_matches as usize > validation_total {
                return Self::unavailable(
                    method,
                    validation_total,
                    "inference candidate reports more matches than validation observations".into(),
                );
            }
            let Some(failures) = candidate["validation_counterexamples"].as_array() else {
                return Self::unavailable(
                    method,
                    validation_total,
                    "inference candidate has no counterexample list".into(),
                );
            };
            counterexample_ids_partial |= candidate["validation_counterexamples_omitted"]
                .as_u64()
                .is_some_and(|count| count > 0);
            let counterexamples: Vec<String> = failures
                .iter()
                .filter_map(|item| item["observation_id"].as_str().map(str::to_owned))
                .collect();
            if counterexamples.len() != failures.len() {
                return Self::unavailable(
                    method,
                    validation_total,
                    "inference counterexample has no observation ID".into(),
                );
            }
            all_counterexamples.extend(counterexamples.iter().cloned());
            summaries.push(CandidateSummary {
                config: config.clone(),
                validation_matches: validation_matches as usize,
                validation_total,
                counterexample_observation_ids: counterexamples
                    .into_iter()
                    .take(MAX_EVIDENCE_IDS)
                    .collect(),
            });
        }
        let reported_candidate_count = summaries.len();
        let fully_validated_reported_count = summaries
            .iter()
            .filter(|candidate| candidate.validation_matches == validation_total)
            .count();
        let best_reported_validation_matches = summaries
            .iter()
            .map(|candidate| candidate.validation_matches)
            .max();
        summaries.sort_by(|left, right| {
            right
                .validation_matches
                .cmp(&left.validation_matches)
                .then_with(|| left.config.to_string().cmp(&right.config.to_string()))
        });
        summaries.truncate(MAX_REPORTED_CANDIDATES);
        let candidate_summaries_omitted = reported_candidate_count.saturating_sub(summaries.len());
        let reported_counterexample_ids_omitted =
            all_counterexamples.len().saturating_sub(MAX_EVIDENCE_IDS);
        Self {
            method,
            status: "evaluated",
            error: None,
            candidate_count: Some(candidate_count),
            reported_candidate_count,
            fully_validated_reported_count,
            best_reported_validation_matches,
            validation_total,
            candidates_truncated: candidate_count > reported_candidate_count,
            candidate_summaries: summaries,
            candidate_summaries_omitted,
            counterexample_observation_ids: all_counterexamples
                .into_iter()
                .take(MAX_EVIDENCE_IDS)
                .collect(),
            reported_counterexample_ids_omitted,
            counterexample_ids_partial,
            identifiability: report.get("identifiability").cloned(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GroupReview {
    pub status: &'static str,
    pub error: Option<String>,
    pub cluster_count: Option<usize>,
    pub eligible_cluster_count: Option<usize>,
    pub assigned_count: usize,
    pub ambiguous_count: usize,
    pub unassigned_count: usize,
    pub counterexample_observation_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NextAction {
    pub kind: &'static str,
    pub tool_hint: &'static str,
    pub reason: String,
    pub target_trial_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_length_value: Option<u64>,
    pub observation_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TrialReview {
    pub revision: u64,
    pub method: &'static str,
    pub provisional: bool,
    pub maximum_candidate_summaries_per_method: usize,
    pub maximum_evidence_ids_per_action: usize,
    pub experiment_id: String,
    pub question: String,
    pub prediction: String,
    pub prediction_assessed: bool,
    pub latest_experiment_assessment: Option<ExperimentAssessment>,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub discovery_capture_count: usize,
    pub validation_capture_count: usize,
    pub discovery_observation_count: usize,
    pub validation_observation_count: usize,
    pub methods: Vec<MethodReview>,
    pub grouping: GroupReview,
    pub next_actions: Vec<NextAction>,
}

pub fn review_trials(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
) -> Result<TrialReview, String> {
    let discovery = state
        .trials
        .iter()
        .find(|trial| trial.id == discovery_trial_id)
        .ok_or_else(|| format!("unknown trial {discovery_trial_id}"))?;
    let validation = state
        .trials
        .iter()
        .find(|trial| trial.id == validation_trial_id)
        .ok_or_else(|| format!("unknown trial {validation_trial_id}"))?;
    if discovery_trial_id == validation_trial_id
        || discovery.experiment_id != validation.experiment_id
        || discovery.role != "discovery"
        || validation.role != "validation"
    {
        return Err(
            "review needs distinct discovery and validation trials of one experiment".into(),
        );
    }
    let experiment = state
        .experiments
        .iter()
        .find(|experiment| experiment.id == discovery.experiment_id)
        .ok_or_else(|| format!("unknown experiment {}", discovery.experiment_id))?;
    let discovery_captures: BTreeSet<_> = state
        .captures
        .iter()
        .filter(|capture| capture.trial_id == discovery_trial_id)
        .map(|capture| capture.id.as_str())
        .collect();
    let validation_captures: BTreeSet<_> = state
        .captures
        .iter()
        .filter(|capture| capture.trial_id == validation_trial_id)
        .map(|capture| capture.id.as_str())
        .collect();
    let discovery_observations: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| discovery_captures.contains(observation.capture_id.as_str()))
        .collect();
    let validation_observations: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| validation_captures.contains(observation.capture_id.as_str()))
        .collect();
    let validation_total = validation_observations.len();
    let methods = vec![
        MethodReview::from_result(
            "length_prefix",
            validation_total,
            framing::infer_length_prefix(state, discovery_trial_id, validation_trial_id),
        ),
        MethodReview::from_result(
            "length_adjusted_chunk",
            validation_total,
            framing::infer_chunk_framing(state, discovery_trial_id, validation_trial_id),
        ),
        MethodReview::from_result(
            "typed_length_value",
            validation_total,
            tlv::infer_tlv(state, discovery_trial_id, validation_trial_id),
        ),
        MethodReview::from_result(
            "unsigned_leb128",
            validation_total,
            varint::infer_varint(state, discovery_trial_id, validation_trial_id),
        ),
        MethodReview::from_result(
            "delimiter",
            validation_total,
            delimiter::infer_delimiter(state, discovery_trial_id, validation_trial_id),
        ),
    ];
    let grouping =
        match clustering::validate_clusters(state, discovery_trial_id, validation_trial_id, true) {
            Ok(check) => {
                let eligible_cluster_count = check
                    .clusters
                    .iter()
                    .filter(|cluster| cluster.member_count >= clustering::MIN_CHILD_SIZE)
                    .count();
                GroupReview {
                status: if eligible_cluster_count == 0 {
                    "insufficient_discovery_members"
                } else {
                    "evaluated"
                },
                error: (eligible_cluster_count == 0).then(|| {
                    format!(
                        "No discovered group has the {} members needed for held-out assignment.",
                        clustering::MIN_CHILD_SIZE
                    )
                }),
                cluster_count: Some(check.cluster_count),
                eligible_cluster_count: Some(eligible_cluster_count),
                assigned_count: check.assigned_count,
                ambiguous_count: check.ambiguous_count,
                unassigned_count: check.unassigned_count,
                counterexample_observation_ids: if eligible_cluster_count == 0 {
                    Vec::new()
                } else {
                    check
                        .observations
                        .iter()
                        .filter(|item| item.status != clustering::ValidationStatus::Assigned)
                        .map(|item| item.observation_id.clone())
                        .take(MAX_EVIDENCE_IDS)
                        .collect()
                },
            }
            }
            Err(error) => GroupReview {
                status: "unavailable",
                error: Some(error),
                cluster_count: None,
                eligible_cluster_count: None,
                assigned_count: 0,
                ambiguous_count: 0,
                unassigned_count: 0,
                counterexample_observation_ids: Vec::new(),
            },
        };
    let mut next_actions = Vec::new();
    let distinct_discovery_messages = discovery_observations
        .iter()
        .map(|observation| observation.bytes_hex.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    if distinct_discovery_messages < 2 {
        next_actions.push(NextAction {
            kind: "capture_distinct_discovery",
            tool_hint: "capture_step",
            reason: "Structural inference needs at least two different discovery messages in this trial.".into(),
            target_trial_ids: vec![discovery_trial_id.into()],
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    }
    if validation_observations.is_empty() {
        next_actions.push(NextAction {
            kind: "capture_held_out_validation",
            tool_hint: "capture_step",
            reason: "The validation trial has no observations to challenge discovery candidates."
                .into(),
            target_trial_ids: vec![validation_trial_id.into()],
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    }
    let mut model_counterexamples = BTreeSet::new();
    for method in &methods {
        model_counterexamples.extend(method.counterexample_observation_ids.iter().cloned());
    }
    if !model_counterexamples.is_empty() {
        next_actions.push(NextAction {
            kind: "inspect_model_counterexamples",
            tool_hint: "span",
            reason:
                "At least one discovery-fitted structural candidate fails a held-out observation."
                    .into(),
            target_trial_ids: vec![validation_trial_id.into()],
            minimum_length_value: None,
            observation_ids: model_counterexamples
                .into_iter()
                .take(MAX_EVIDENCE_IDS)
                .collect(),
        });
    }
    for method in &methods {
        if method.candidates_truncated
            || method.counterexample_ids_partial
            || method.reported_counterexample_ids_omitted > 0
        {
            let tool_hint = match method.method {
                "length_prefix" => "infer_framing",
                "length_adjusted_chunk" => "infer_chunk_framing",
                "typed_length_value" => "infer_tlv",
                "unsigned_leb128" => "infer_varint",
                "delimiter" => "infer_delimiter",
                _ => unreachable!(),
            };
            next_actions.push(NextAction {
                kind: "inspect_full_inference",
                tool_hint,
                reason: format!(
                    "The {} review omits candidate or counterexample detail; inspect that method's full result.",
                    method.method
                ),
                target_trial_ids: vec![discovery_trial_id.into(), validation_trial_id.into()],
                minimum_length_value: None,
                observation_ids: Vec::new(),
            });
        }
    }
    if distinct_discovery_messages >= 2
        && !validation_observations.is_empty()
        && methods
            .iter()
            .all(|method| method.status == "evaluated" && method.candidate_count == Some(0))
    {
        next_actions.push(NextAction {
            kind: "inspect_unmodeled_structure",
            tool_hint: "span",
            reason: "None of the five bounded record models fits this trial pair; inspect raw bytes before changing the capture condition.".into(),
            target_trial_ids: vec![discovery_trial_id.into(), validation_trial_id.into()],
            minimum_length_value: None,
            observation_ids: discovery_observations
                .iter()
                .chain(validation_observations.iter())
                .map(|observation| observation.id.clone())
                .take(MAX_EVIDENCE_IDS)
                .collect(),
        });
    }
    if methods.iter().all(|method| method.status == "unavailable")
        && distinct_discovery_messages >= 2
        && !validation_observations.is_empty()
    {
        next_actions.push(NextAction {
            kind: "narrow_trial_for_bounded_inference",
            tool_hint: "search_observations",
            reason: "All structural checks are unavailable for this trial pair; inspect their errors and choose a smaller controlled trial.".into(),
            target_trial_ids: vec![discovery_trial_id.into(), validation_trial_id.into()],
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    }
    let chunk_identifiability = methods
        .iter()
        .find(|method| method.method == "length_adjusted_chunk")
        .and_then(|method| method.identifiability.as_ref());
    if let Some(next) = chunk_identifiability.and_then(|value| value.get("next_experiment"))
        && next["kind"] == "cross_length_width_boundary"
        && let Some(minimum) = next["minimum_length_value"].as_u64()
    {
        next_actions.push(NextAction {
            kind: "cross_length_width_boundary",
            tool_hint: "capture_step",
            reason: format!("Capture a record with a length value of at least {minimum} in discovery and validation trials to challenge a shorter length-field width."),
            target_trial_ids: vec![discovery_trial_id.into(), validation_trial_id.into()],
            minimum_length_value: Some(minimum),
            observation_ids: Vec::new(),
        });
    }
    if let Some(value) = chunk_identifiability
        && value["fully_validated_candidate_count"]
            .as_u64()
            .is_some_and(|count| count > 1)
        && value["distinct_boundary_rule_count"] == 1
    {
        next_actions.push(NextAction {
            kind: "inspect_equivalent_descriptions",
            tool_hint: "infer_chunk_framing",
            reason: "Multiple validated descriptions compute the same boundary rule; changing only record lengths cannot distinguish them. Inspect the full models before testing field meaning.".into(),
            target_trial_ids: vec![discovery_trial_id.into(), validation_trial_id.into()],
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    }
    let fully_validated: usize = methods
        .iter()
        .filter(|method| method.method != "length_adjusted_chunk")
        .map(|method| method.fully_validated_reported_count)
        .sum::<usize>()
        + chunk_identifiability
            .and_then(|value| value["distinct_boundary_rule_count"].as_u64())
            .unwrap_or(0) as usize;
    if fully_validated > 1
        && !next_actions
            .iter()
            .any(|action| action.kind == "cross_length_width_boundary")
    {
        next_actions.push(NextAction {
            kind: "distinguish_remaining_models",
            tool_hint: "capture_step",
            reason: format!(
                "{fully_validated} reported candidates still fit all held-out observations; vary one payload length, type, or terminator condition in a fresh trial."
            ),
            target_trial_ids: Vec::new(),
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    }
    if grouping.status == "insufficient_discovery_members" {
        next_actions.push(NextAction {
            kind: "capture_grouping_support",
            tool_hint: "capture_step",
            reason: format!("Format-group validation needs at least {} discovery members in one group; capture another controlled example before interpreting grouping failures.", clustering::MIN_CHILD_SIZE),
            target_trial_ids: vec![discovery_trial_id.into()],
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    } else if grouping.unassigned_count + grouping.ambiguous_count > 0 {
        next_actions.push(NextAction {
            kind: "inspect_grouping_counterexamples",
            tool_hint: "span",
            reason: format!(
                "{} held-out observations are unassigned or ambiguous under discovered format groups.",
                grouping.unassigned_count + grouping.ambiguous_count
            ),
            target_trial_ids: vec![validation_trial_id.into()],
            minimum_length_value: None,
            observation_ids: grouping.counterexample_observation_ids.clone(),
        });
    }
    if next_actions.is_empty() {
        next_actions.push(NextAction {
            kind: "repeat_with_new_condition",
            tool_hint: "capture_step",
            reason: "No immediate counterexample is reported; repeat with a fresh controlled condition before treating a structural fit as a grammar.".into(),
            target_trial_ids: Vec::new(),
            minimum_length_value: None,
            observation_ids: Vec::new(),
        });
    }
    Ok(TrialReview {
        revision: state.revision,
        method: "controlled_trial_evidence_review_v1",
        provisional: true,
        maximum_candidate_summaries_per_method: MAX_REPORTED_CANDIDATES,
        maximum_evidence_ids_per_action: MAX_EVIDENCE_IDS,
        experiment_id: experiment.id.clone(),
        question: experiment.question.clone(),
        prediction: experiment.prediction.clone(),
        prediction_assessed: state
            .experiment_assessments
            .iter()
            .any(|assessment| assessment.experiment_id == experiment.id),
        latest_experiment_assessment: state
            .experiment_assessments
            .iter()
            .rev()
            .find(|assessment| assessment.experiment_id == experiment.id)
            .cloned(),
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        discovery_capture_count: discovery_captures.len(),
        validation_capture_count: validation_captures.len(),
        discovery_observation_count: discovery_observations.len(),
        validation_observation_count: validation_total,
        methods,
        grouping,
        next_actions,
    })
}
