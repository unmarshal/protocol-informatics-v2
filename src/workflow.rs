//! Durable, append-only investigation records for iterative analysis.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::delimiter::{DelimiterConfig, DelimiterStatus, probe_observation as probe_delimiter};
use crate::framing::{FramingConfig, FramingStatus, probe_observation};
use crate::pcap::{
    extract_icmp_messages, extract_icmpv6_messages, extract_pcapng_icmp_messages,
    extract_pcapng_icmpv6_messages, extract_pcapng_tcp_segments, extract_pcapng_udp_messages,
    extract_tcp_segments, extract_udp_messages,
};
use crate::reassembly::{SourceSpan, reassemble_tcp_segments};
use crate::varint::{VarintConfig, probe_varint};

const SCHEMA_VERSION: u32 = 20;
const MAX_BINARY_OBSERVATION_BYTES: usize = 1024 * 1024;
const MAX_RECOVERY_TAIL_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub claim: String,
    pub score: Option<f64>,
    pub evidence: Vec<String>,
    pub counterexamples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experiment {
    pub id: String,
    pub question: String,
    pub hypothesis_ids: Vec<String>,
    pub prediction: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentVerdict {
    Supported,
    Contradicted,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentAssessment {
    pub id: String,
    pub experiment_id: String,
    pub key: String,
    pub verdict: AssessmentVerdict,
    pub explanation: String,
    pub evidence_ids: Vec<String>,
    pub basis_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trial {
    pub id: String,
    pub experiment_id: String,
    pub role: String,
    pub changed_factor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    pub id: String,
    pub trial_id: String,
    pub format: String,
    pub source: String,
    pub sha256: String,
    pub artifact: String,
    pub observation_count: usize,
    #[serde(default)]
    pub run_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<crate::capture::CaptureConditions>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRunStatus {
    Reserved,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRun {
    pub id: String,
    pub key: String,
    pub trial_id: String,
    pub format: String,
    pub command_fingerprint: String,
    pub timeout_ms: u64,
    pub status: CaptureRunStatus,
    pub capture_id: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub stop_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: String,
    pub capture_id: String,
    pub source_index: usize,
    pub source_offset: Option<usize>,
    pub timestamp_ns: Option<u64>,
    pub direction: Option<String>,
    #[serde(default)]
    pub source_port: Option<u16>,
    #[serde(default)]
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub tcp_sequence: Option<u32>,
    #[serde(default)]
    pub stream_gap_before: bool,
    #[serde(default)]
    pub source_spans: Vec<SourceSpan>,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FramingRecord {
    pub id: String,
    pub index: usize,
    pub start: usize,
    pub logical_end: usize,
    pub end: usize,
    pub length_field_start: usize,
    pub length_field_end: usize,
    pub length_value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FramingRun {
    pub id: String,
    pub key: String,
    pub observation_id: String,
    pub config: FramingConfig,
    pub records: Vec<FramingRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarintRun {
    pub id: String,
    pub key: String,
    pub observation_id: String,
    pub config: VarintConfig,
    pub records: Vec<FramingRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelimiterFrameRecord {
    pub id: String,
    pub index: usize,
    pub start: usize,
    pub logical_end: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelimiterRun {
    pub id: String,
    pub key: String,
    pub observation_id: String,
    pub config: DelimiterConfig,
    pub records: Vec<DelimiterFrameRecord>,
}

pub fn delimiter_run_from_probe(
    key: String,
    observation_id: String,
    config: DelimiterConfig,
    state: &State,
) -> Result<DelimiterRun, String> {
    let probe = probe_delimiter(state, &observation_id, config)?;
    if probe.status != DelimiterStatus::Complete || probe.records.len() < 2 {
        return Err(format!(
            "delimiter model must consume the observation with at least two records; stopped at {} ({:?})",
            probe.next_offset, probe.status
        ));
    }
    Ok(DelimiterRun {
        id: String::new(),
        key,
        observation_id,
        config: probe.config,
        records: probe
            .records
            .into_iter()
            .map(|record| DelimiterFrameRecord {
                id: String::new(),
                index: record.index,
                start: record.start,
                logical_end: record.payload_end,
                end: record.end,
            })
            .collect(),
    })
}

pub fn varint_run_from_probe(
    key: String,
    observation_id: String,
    config: VarintConfig,
    state: &State,
) -> Result<VarintRun, String> {
    let probe = probe_varint(state, &observation_id, config)?;
    if probe.status != FramingStatus::Complete || probe.records.len() < 2 {
        return Err(format!(
            "varint model must consume the observation with at least two records; stopped at {} ({:?})",
            probe.next_offset, probe.status
        ));
    }
    Ok(VarintRun {
        id: String::new(),
        key,
        observation_id,
        config,
        records: probe
            .records
            .into_iter()
            .map(|record| FramingRecord {
                id: String::new(),
                index: record.index,
                start: record.start,
                logical_end: record.logical_end,
                end: record.end,
                length_field_start: record.length_field_start,
                length_field_end: record.length_field_end,
                length_value: record.length_value,
            })
            .collect(),
    })
}

pub fn framing_run_from_probe(
    key: String,
    observation_id: String,
    config: FramingConfig,
    state: &State,
) -> Result<FramingRun, String> {
    let probe = probe_observation(state, &observation_id, config)?;
    if probe.status != FramingStatus::Complete || probe.records.len() < 2 {
        return Err(format!(
            "framing must consume the observation with at least two records; stopped at {} ({:?})",
            probe.next_offset, probe.status
        ));
    }
    Ok(FramingRun {
        id: String::new(),
        key,
        observation_id,
        config,
        records: probe
            .records
            .into_iter()
            .map(|record| FramingRecord {
                id: String::new(),
                index: record.index,
                start: record.start,
                logical_end: record.logical_end,
                end: record.end,
                length_field_start: record.length_field_start,
                length_field_end: record.length_field_end,
                length_value: record.length_value,
            })
            .collect(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRetraction {
    pub key: String,
    pub reason: String,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub observation_id: String,
    pub label: String,
    pub phase: String,
    #[serde(default)]
    pub action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retraction: Option<TagRetraction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowTag {
    pub id: String,
    pub key: String,
    pub action_id: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub phase: String,
    pub label: String,
    pub observation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTagBatch {
    pub id: String,
    pub key: String,
    pub action_id: String,
    pub capture_id: String,
    pub phase: String,
    pub label: String,
    #[serde(default)]
    pub start_index: usize,
    pub observation_ids: Vec<String>,
    pub tag_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueSet {
    Discovery,
    Validation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownValue {
    pub id: String,
    pub observation_id: String,
    pub variable: String,
    pub value: u64,
    pub set: ValueSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameKnownValue {
    pub id: String,
    pub frame_id: String,
    pub variable: String,
    pub value: u64,
    pub set: ValueSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStepScope {
    pub phase: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub trial_id: String,
    pub kind: String,
    pub detail: String,
    #[serde(default)]
    pub timestamp_ns: Option<u64>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_scope: Option<CaptureStepScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnalysisScope {
    All,
    Trial {
        trial_id: String,
    },
    Cluster {
        cluster_id: String,
        trial_id: Option<String>,
        direction_mode: String,
    },
    FrameCluster {
        cluster_id: String,
        model: String,
        trial_id: Option<String>,
        direction_mode: String,
        run_keys: Vec<String>,
        source_revision: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRecord {
    pub id: String,
    pub observation_ids: Vec<String>,
    #[serde(default)]
    pub frame_ids: Vec<String>,
    pub artifact: String,
    pub aligned_width: usize,
    #[serde(default)]
    pub scope: Option<AnalysisScope>,
    #[serde(default)]
    pub method_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub id: String,
    pub text: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Created {
        question: String,
    },
    HypothesisAdded {
        hypothesis: Hypothesis,
    },
    HypothesisEvaluated {
        hypothesis_id: String,
        score: f64,
        evidence: Vec<String>,
        counterexamples: Vec<String>,
    },
    ExperimentCreated {
        experiment: Experiment,
    },
    ExperimentAssessed {
        assessment: ExperimentAssessment,
    },
    TrialCreated {
        trial: Trial,
    },
    CaptureImported {
        capture: Capture,
        observations: Vec<Observation>,
    },
    FramingCommitted {
        run: FramingRun,
    },
    VarintCommitted {
        run: VarintRun,
    },
    DelimiterCommitted {
        run: DelimiterRun,
    },
    CaptureRunReserved {
        run: CaptureRun,
    },
    CaptureRunFailed {
        key: String,
        error: String,
    },
    CaptureRunStopRequested {
        key: String,
    },
    ActionMarked {
        action: Action,
    },
    ObservationTagged {
        tag: Tag,
    },
    ObservationTagRetracted {
        tag_id: String,
        key: String,
        reason: String,
    },
    ObservationWindowTagged {
        window: WindowTag,
        tags: Vec<Tag>,
    },
    CaptureTagged {
        batch: CaptureTagBatch,
        tags: Vec<Tag>,
    },
    ValueAnnotated {
        known_value: KnownValue,
    },
    FrameValueAnnotated {
        known_value: FrameKnownValue,
    },
    AnalysisRecorded {
        analysis: AnalysisRecord,
    },
    DecisionRecorded {
        decision: Decision,
    },
}

impl Event {
    /// IDs are assigned at commit time so concurrent writers cannot reuse a
    /// revision they observed before acquiring the event-file lock.
    fn assign_ids(&mut self, revision: u64) {
        match self {
            Self::Created { .. }
            | Self::HypothesisEvaluated { .. }
            | Self::CaptureRunFailed { .. }
            | Self::CaptureRunStopRequested { .. }
            | Self::ObservationTagRetracted { .. } => {}
            Self::HypothesisAdded { hypothesis } => {
                hypothesis.id = format!("hyp-{revision:06}");
            }
            Self::ExperimentCreated { experiment } => {
                experiment.id = format!("exp-{revision:06}");
            }
            Self::ExperimentAssessed { assessment } => {
                assessment.id = format!("assessment-{revision:06}");
                assessment.basis_revision = revision - 1;
            }
            Self::TrialCreated { trial } => {
                trial.id = format!("trial-{revision:06}");
            }
            Self::CaptureImported {
                capture,
                observations,
            } => {
                capture.id = format!("cap-{revision:06}");
                for (index, observation) in observations.iter_mut().enumerate() {
                    observation.id = format!("obs-{revision:06}-{index:04}");
                    observation.capture_id = capture.id.clone();
                }
            }
            Self::FramingCommitted { run } => {
                run.id = format!("framing-{revision:06}");
                for (index, record) in run.records.iter_mut().enumerate() {
                    record.id = format!("frame-{revision:06}-{index:04}");
                }
            }
            Self::VarintCommitted { run } => {
                run.id = format!("varint-{revision:06}");
                for (index, record) in run.records.iter_mut().enumerate() {
                    record.id = format!("frame-{revision:06}-{index:04}");
                }
            }
            Self::DelimiterCommitted { run } => {
                run.id = format!("delimiter-{revision:06}");
                for (index, record) in run.records.iter_mut().enumerate() {
                    record.id = format!("frame-{revision:06}-{index:04}");
                }
            }
            Self::CaptureRunReserved { run } => {
                run.id = format!("run-{revision:06}");
            }
            Self::ActionMarked { action } => {
                action.id = format!("action-{revision:06}");
            }
            Self::ObservationTagged { tag } => {
                tag.id = format!("tag-{revision:06}");
            }
            Self::ObservationWindowTagged { window, tags } => {
                window.id = format!("window-{revision:06}");
                for (index, tag) in tags.iter_mut().enumerate() {
                    tag.id = format!("tag-{revision:06}-{index:04}");
                }
            }
            Self::CaptureTagged { batch, tags } => {
                batch.id = format!("capture-tags-{revision:06}");
                for (index, tag) in tags.iter_mut().enumerate() {
                    tag.id = format!("tag-{revision:06}-{index:04}");
                }
                batch.tag_ids = tags.iter().map(|tag| tag.id.clone()).collect();
            }
            Self::ValueAnnotated { known_value } => {
                known_value.id = format!("value-{revision:06}");
            }
            Self::FrameValueAnnotated { known_value } => {
                known_value.id = format!("frame-value-{revision:06}");
            }
            Self::AnalysisRecorded { analysis } => {
                analysis.id = format!("analysis-{revision:06}");
            }
            Self::DecisionRecorded { decision } => {
                decision.id = format!("decision-{revision:06}");
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub schema_version: u32,
    pub revision: u64,
    pub timestamp_ms: u64,
    pub event: Event,
}

#[derive(Debug, Clone, Serialize)]
pub struct State {
    pub schema_version: u32,
    pub revision: u64,
    pub question: String,
    pub hypotheses: Vec<Hypothesis>,
    pub experiments: Vec<Experiment>,
    pub experiment_assessments: Vec<ExperimentAssessment>,
    pub trials: Vec<Trial>,
    pub captures: Vec<Capture>,
    /// Reconstructed from import events; kept out of the portable state view.
    #[serde(skip_serializing)]
    pub capture_import_revisions: BTreeMap<String, u64>,
    pub capture_runs: Vec<CaptureRun>,
    pub observations: Vec<Observation>,
    pub framing_runs: Vec<FramingRun>,
    pub varint_runs: Vec<VarintRun>,
    pub delimiter_runs: Vec<DelimiterRun>,
    pub actions: Vec<Action>,
    pub tags: Vec<Tag>,
    pub window_tags: Vec<WindowTag>,
    pub capture_tag_batches: Vec<CaptureTagBatch>,
    pub known_values: Vec<KnownValue>,
    pub frame_known_values: Vec<FrameKnownValue>,
    pub analyses: Vec<AnalysisRecord>,
    pub decisions: Vec<Decision>,
}

#[derive(Debug, Clone, Copy)]
pub struct FrameBounds<'a> {
    pub id: &'a str,
    pub start: usize,
    pub logical_end: usize,
    pub end: usize,
}

impl State {
    pub fn frame_by_id(&self, frame_id: &str) -> Option<(&str, &str, FrameBounds<'_>)> {
        self.framing_runs
            .iter()
            .find_map(|run| {
                run.records
                    .iter()
                    .find(|record| record.id == frame_id)
                    .map(|record| {
                        (
                            run.id.as_str(),
                            run.observation_id.as_str(),
                            FrameBounds {
                                id: &record.id,
                                start: record.start,
                                logical_end: record.logical_end,
                                end: record.end,
                            },
                        )
                    })
            })
            .or_else(|| {
                self.varint_runs.iter().find_map(|run| {
                    run.records
                        .iter()
                        .find(|record| record.id == frame_id)
                        .map(|record| {
                            (
                                run.id.as_str(),
                                run.observation_id.as_str(),
                                FrameBounds {
                                    id: &record.id,
                                    start: record.start,
                                    logical_end: record.logical_end,
                                    end: record.end,
                                },
                            )
                        })
                })
            })
            .or_else(|| {
                self.delimiter_runs.iter().find_map(|run| {
                    run.records
                        .iter()
                        .find(|record| record.id == frame_id)
                        .map(|record| {
                            (
                                run.id.as_str(),
                                run.observation_id.as_str(),
                                FrameBounds {
                                    id: &record.id,
                                    start: record.start,
                                    logical_end: record.logical_end,
                                    end: record.end,
                                },
                            )
                        })
                })
            })
    }

    fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            question: String::new(),
            hypotheses: Vec::new(),
            experiments: Vec::new(),
            experiment_assessments: Vec::new(),
            trials: Vec::new(),
            captures: Vec::new(),
            capture_import_revisions: BTreeMap::new(),
            capture_runs: Vec::new(),
            observations: Vec::new(),
            framing_runs: Vec::new(),
            varint_runs: Vec::new(),
            delimiter_runs: Vec::new(),
            actions: Vec::new(),
            tags: Vec::new(),
            window_tags: Vec::new(),
            capture_tag_batches: Vec::new(),
            known_values: Vec::new(),
            frame_known_values: Vec::new(),
            analyses: Vec::new(),
            decisions: Vec::new(),
        }
    }

    fn apply(&mut self, record: &EventRecord) -> Result<(), String> {
        if !(1..=SCHEMA_VERSION).contains(&record.schema_version)
            || record.revision != self.revision + 1
        {
            return Err(format!(
                "invalid event version or revision at {}",
                record.revision
            ));
        }
        match &record.event {
            Event::Created { question } => {
                if self.revision != 0 || question.trim().is_empty() {
                    return Err("invalid investigation creation".into());
                }
                self.question = question.clone();
            }
            Event::HypothesisAdded { hypothesis } => {
                self.require_created()?;
                if hypothesis.claim.trim().is_empty()
                    || self.hypotheses.iter().any(|h| h.id == hypothesis.id)
                {
                    return Err("empty or duplicate hypothesis".into());
                }
                self.hypotheses.push(hypothesis.clone());
            }
            Event::HypothesisEvaluated {
                hypothesis_id,
                score,
                evidence,
                counterexamples,
            } => {
                if !score.is_finite() || !(0.0..=1.0).contains(score) {
                    return Err("hypothesis score must be in [0, 1]".into());
                }
                for id in evidence.iter().chain(counterexamples) {
                    if !self
                        .observations
                        .iter()
                        .any(|observation| &observation.id == id)
                    {
                        return Err(format!("unknown evidence observation {id}"));
                    }
                }
                let hypothesis = self
                    .hypotheses
                    .iter_mut()
                    .find(|h| &h.id == hypothesis_id)
                    .ok_or_else(|| format!("unknown hypothesis {hypothesis_id}"))?;
                hypothesis.score = Some(*score);
                hypothesis.evidence = evidence.clone();
                hypothesis.counterexamples = counterexamples.clone();
            }
            Event::ExperimentCreated { experiment } => {
                if experiment.question.trim().is_empty()
                    || self.experiments.iter().any(|e| e.id == experiment.id)
                {
                    return Err("empty or duplicate experiment".into());
                }
                for id in &experiment.hypothesis_ids {
                    if !self.hypotheses.iter().any(|h| &h.id == id) {
                        return Err(format!("unknown hypothesis {id}"));
                    }
                }
                self.experiments.push(experiment.clone());
            }
            Event::ExperimentAssessed { assessment } => {
                if record.schema_version < 19
                    || assessment.id.is_empty()
                    || assessment.key.is_empty()
                    || assessment.key.len() > 128
                    || assessment.key.chars().any(char::is_control)
                    || assessment.explanation.trim().is_empty()
                    || assessment.explanation.len() > 2048
                    || assessment.evidence_ids.len() > 100
                    || (assessment.verdict != AssessmentVerdict::Inconclusive
                        && assessment.evidence_ids.is_empty())
                    || assessment.basis_revision != record.revision - 1
                    || self
                        .experiment_assessments
                        .iter()
                        .any(|prior| prior.id == assessment.id || prior.key == assessment.key)
                {
                    return Err("invalid or duplicate experiment assessment".into());
                }
                if !self
                    .experiments
                    .iter()
                    .any(|experiment| experiment.id == assessment.experiment_id)
                {
                    return Err(format!("unknown experiment {}", assessment.experiment_id));
                }
                let mut evidence = std::collections::BTreeSet::new();
                for id in &assessment.evidence_ids {
                    if !evidence.insert(id) {
                        return Err(format!("duplicate evidence observation {id}"));
                    }
                    let observation = self
                        .observations
                        .iter()
                        .find(|observation| observation.id == *id)
                        .ok_or_else(|| format!("unknown evidence observation {id}"))?;
                    let capture = self
                        .captures
                        .iter()
                        .find(|capture| capture.id == observation.capture_id)
                        .ok_or_else(|| format!("unknown capture {}", observation.capture_id))?;
                    if !self.trials.iter().any(|trial| {
                        trial.id == capture.trial_id
                            && trial.experiment_id == assessment.experiment_id
                    }) {
                        return Err(format!(
                            "evidence observation {id} is outside experiment {}",
                            assessment.experiment_id
                        ));
                    }
                }
                self.experiment_assessments.push(assessment.clone());
            }
            Event::TrialCreated { trial } => {
                if !self.experiments.iter().any(|e| e.id == trial.experiment_id) {
                    return Err(format!("unknown experiment {}", trial.experiment_id));
                }
                if trial.role.trim().is_empty() || self.trials.iter().any(|t| t.id == trial.id) {
                    return Err("empty or duplicate trial".into());
                }
                self.trials.push(trial.clone());
            }
            Event::CaptureImported {
                capture,
                observations,
            } => {
                if !self.trials.iter().any(|t| t.id == capture.trial_id) {
                    return Err(format!("unknown trial {}", capture.trial_id));
                }
                if self.captures.iter().any(|c| c.id == capture.id)
                    || capture.observation_count != observations.len()
                {
                    return Err("duplicate capture or observation count mismatch".into());
                }
                for observation in observations {
                    if observation.capture_id != capture.id
                        || observation.bytes_hex.is_empty()
                        || self.observations.iter().any(|o| o.id == observation.id)
                    {
                        return Err("invalid or duplicate observation".into());
                    }
                    if capture.format.ends_with("tcp-stream") {
                        let mut covered = 0;
                        for span in &observation.source_spans {
                            if span.message_start != covered || span.message_end <= covered {
                                return Err("invalid TCP stream source spans".into());
                            }
                            covered = span.message_end;
                        }
                        if observation.source_offset.is_some()
                            || covered.checked_mul(2) != Some(observation.bytes_hex.len())
                        {
                            return Err(
                                "TCP stream source spans do not cover the observation".into()
                            );
                        }
                    }
                }
                let run_index = if let Some(key) = &capture.run_key {
                    let index = self
                        .capture_runs
                        .iter()
                        .position(|run| &run.key == key)
                        .ok_or_else(|| format!("unknown capture run key {key}"))?;
                    let run = &self.capture_runs[index];
                    if run.status != CaptureRunStatus::Reserved
                        || run.trial_id != capture.trial_id
                        || run.format != capture.format
                    {
                        return Err(format!("capture run {key} is not reserved for this import"));
                    }
                    Some(index)
                } else {
                    None
                };
                self.captures.push(capture.clone());
                self.capture_import_revisions
                    .insert(capture.id.clone(), record.revision);
                self.observations.extend(observations.clone());
                if let Some(index) = run_index {
                    self.capture_runs[index].status = CaptureRunStatus::Completed;
                    self.capture_runs[index].capture_id = Some(capture.id.clone());
                }
            }
            Event::FramingCommitted { run } => {
                if run.key.is_empty()
                    || run.key.len() > 128
                    || run.key.chars().any(char::is_control)
                    || run.id != format!("framing-{:06}", record.revision)
                    || self
                        .framing_runs
                        .iter()
                        .any(|old| old.key == run.key || old.id == run.id)
                    || self.varint_runs.iter().any(|old| old.key == run.key)
                    || self.delimiter_runs.iter().any(|old| old.key == run.key)
                    || (run.config.length_adjustment > 0 && record.schema_version < 15)
                    || run.config.validate()? != run.config
                {
                    return Err("invalid or duplicate framing run".into());
                }
                let expected = framing_run_from_probe(
                    run.key.clone(),
                    run.observation_id.clone(),
                    run.config,
                    self,
                )?;
                if expected.records.len() != run.records.len() {
                    return Err("committed frame count does not match source bytes".into());
                }
                for (actual, expected) in run.records.iter().zip(&expected.records) {
                    if actual.id != format!("frame-{:06}-{:04}", record.revision, expected.index)
                        || self
                            .framing_runs
                            .iter()
                            .any(|old| old.records.iter().any(|record| record.id == actual.id))
                        || actual.index != expected.index
                        || actual.start != expected.start
                        || actual.logical_end != expected.logical_end
                        || actual.end != expected.end
                        || actual.length_field_start != expected.length_field_start
                        || actual.length_field_end != expected.length_field_end
                        || actual.length_value != expected.length_value
                    {
                        return Err("committed frame does not match source bytes".into());
                    }
                }
                self.framing_runs.push(run.clone());
            }
            Event::VarintCommitted { run } => {
                if record.schema_version < 10 {
                    return Err("varint commits require schema version 10".into());
                }
                if run.key.is_empty()
                    || run.key.len() > 128
                    || run.key.chars().any(char::is_control)
                    || run.id != format!("varint-{:06}", record.revision)
                    || self
                        .varint_runs
                        .iter()
                        .any(|old| old.key == run.key || old.id == run.id)
                    || self.framing_runs.iter().any(|old| old.key == run.key)
                    || self.delimiter_runs.iter().any(|old| old.key == run.key)
                    || run.config.validate()? != run.config
                {
                    return Err("invalid or duplicate varint run".into());
                }
                let expected = varint_run_from_probe(
                    run.key.clone(),
                    run.observation_id.clone(),
                    run.config,
                    self,
                )?;
                if expected.records.len() != run.records.len() {
                    return Err("committed varint frame count does not match source bytes".into());
                }
                for (actual, expected) in run.records.iter().zip(&expected.records) {
                    if actual.id != format!("frame-{:06}-{:04}", record.revision, expected.index)
                        || actual.index != expected.index
                        || actual.start != expected.start
                        || actual.logical_end != expected.logical_end
                        || actual.end != expected.end
                        || actual.length_field_start != expected.length_field_start
                        || actual.length_field_end != expected.length_field_end
                        || actual.length_value != expected.length_value
                    {
                        return Err("committed varint frame does not match source bytes".into());
                    }
                }
                self.varint_runs.push(run.clone());
            }
            Event::DelimiterCommitted { run } => {
                if record.schema_version < 13 {
                    return Err("delimiter commits require schema version 13".into());
                }
                if run.key.is_empty()
                    || run.key.len() > 128
                    || run.key.chars().any(char::is_control)
                    || run.id != format!("delimiter-{:06}", record.revision)
                    || self
                        .delimiter_runs
                        .iter()
                        .any(|old| old.key == run.key || old.id == run.id)
                    || self.framing_runs.iter().any(|old| old.key == run.key)
                    || self.varint_runs.iter().any(|old| old.key == run.key)
                    || run.config.clone().validate()? != run.config
                {
                    return Err("invalid or duplicate delimiter run".into());
                }
                let expected = delimiter_run_from_probe(
                    run.key.clone(),
                    run.observation_id.clone(),
                    run.config.clone(),
                    self,
                )?;
                if expected.records.len() != run.records.len() {
                    return Err(
                        "committed delimiter frame count does not match source bytes".into(),
                    );
                }
                for (actual, expected) in run.records.iter().zip(&expected.records) {
                    if actual.id != format!("frame-{:06}-{:04}", record.revision, expected.index)
                        || actual.index != expected.index
                        || actual.start != expected.start
                        || actual.logical_end != expected.logical_end
                        || actual.end != expected.end
                    {
                        return Err("committed delimiter frame does not match source bytes".into());
                    }
                }
                self.delimiter_runs.push(run.clone());
            }
            Event::CaptureRunReserved { run } => {
                if !self.trials.iter().any(|trial| trial.id == run.trial_id) {
                    return Err(format!("unknown trial {}", run.trial_id));
                }
                if run.key.is_empty()
                    || run.key.len() > 128
                    || run.key.chars().any(char::is_control)
                    || run.command_fingerprint.len() != 64
                    || !run
                        .command_fingerprint
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    || run.timeout_ms == 0
                    || run.timeout_ms > 600_000
                    || !valid_capture_format(&run.format)
                    || run.status != CaptureRunStatus::Reserved
                    || run.capture_id.is_some()
                    || run.error.is_some()
                    || run.stop_requested
                    || self
                        .capture_runs
                        .iter()
                        .any(|existing| existing.key == run.key)
                    || self
                        .capture_runs
                        .iter()
                        .any(|existing| existing.id == run.id)
                {
                    return Err("invalid or duplicate capture run reservation".into());
                }
                self.capture_runs.push(run.clone());
            }
            Event::CaptureRunFailed { key, error } => {
                if error.trim().is_empty() {
                    return Err("capture failure reason must not be empty".into());
                }
                let run = self
                    .capture_runs
                    .iter_mut()
                    .find(|run| &run.key == key)
                    .ok_or_else(|| format!("unknown capture run key {key}"))?;
                if run.status != CaptureRunStatus::Reserved {
                    return Err(format!("capture run {key} is not reserved"));
                }
                run.status = CaptureRunStatus::Failed;
                run.error = Some(error.clone());
            }
            Event::CaptureRunStopRequested { key } => {
                let run = self
                    .capture_runs
                    .iter_mut()
                    .find(|run| &run.key == key)
                    .ok_or_else(|| format!("unknown capture run key {key}"))?;
                if run.status != CaptureRunStatus::Reserved || run.stop_requested {
                    return Err(format!("capture run {key} cannot be stopped"));
                }
                run.stop_requested = true;
            }
            Event::ActionMarked { action } => {
                if !self.trials.iter().any(|t| t.id == action.trial_id) {
                    return Err(format!("unknown trial {}", action.trial_id));
                }
                if action.kind.trim().is_empty() || self.actions.iter().any(|a| a.id == action.id) {
                    return Err("empty or duplicate action".into());
                }
                if let Some(key) = &action.key
                    && (record.schema_version < 11
                        || key.is_empty()
                        || key.len() > 128
                        || key.chars().any(char::is_control)
                        || action.timestamp_ns.is_none()
                        || self.actions.iter().any(|old| old.key.as_ref() == Some(key)))
                {
                    return Err("invalid or duplicate keyed action".into());
                }
                if let Some(scope) = &action.capture_scope
                    && (record.schema_version < 16
                        || scope.phase.trim().is_empty()
                        || scope.label.trim().is_empty()
                        || action.key.as_deref().is_none_or(|key| {
                            !key.ends_with(":action") || key.len() <= ":action".len()
                        }))
                {
                    return Err("invalid capture step scope".into());
                }
                self.actions.push(action.clone());
            }
            Event::ObservationTagged { tag } => {
                let observation = self
                    .observations
                    .iter()
                    .find(|o| o.id == tag.observation_id)
                    .ok_or_else(|| format!("unknown observation {}", tag.observation_id))?;
                if tag.label.trim().is_empty()
                    || tag.phase.trim().is_empty()
                    || tag.retraction.is_some()
                    || self.tags.iter().any(|t| t.id == tag.id)
                {
                    return Err("empty or duplicate tag".into());
                }
                if let Some(key) = &tag.key
                    && (record.schema_version < 17
                        || key.is_empty()
                        || key.len() > 128
                        || key.chars().any(char::is_control)
                        || self.tags.iter().any(|old| old.key.as_ref() == Some(key)))
                {
                    return Err("invalid or duplicate keyed observation tag".into());
                }
                if let Some(action_id) = &tag.action_id {
                    if tag.key.is_none() {
                        return Err("an action-linked observation tag needs a key".into());
                    }
                    let action = self
                        .actions
                        .iter()
                        .find(|action| action.id == *action_id)
                        .ok_or_else(|| format!("unknown action {action_id}"))?;
                    let capture = self
                        .captures
                        .iter()
                        .find(|capture| capture.id == observation.capture_id)
                        .ok_or_else(|| format!("unknown capture {}", observation.capture_id))?;
                    if action.trial_id != capture.trial_id {
                        return Err(
                            "tag action and observation must belong to the same trial".into()
                        );
                    }
                }
                self.tags.push(tag.clone());
            }
            Event::ObservationTagRetracted {
                tag_id,
                key,
                reason,
            } => {
                if record.schema_version < 18
                    || key.is_empty()
                    || key.len() > 128
                    || key.chars().any(char::is_control)
                    || reason.trim().is_empty()
                    || reason.len() > 1024
                    || self.tags.iter().any(|tag| {
                        tag.retraction
                            .as_ref()
                            .is_some_and(|retraction| retraction.key == *key)
                    })
                {
                    return Err("invalid or duplicate tag retraction".into());
                }
                let tag = self
                    .tags
                    .iter_mut()
                    .find(|tag| tag.id == *tag_id)
                    .ok_or_else(|| format!("unknown tag {tag_id}"))?;
                if tag.retraction.is_some() {
                    return Err(format!("tag {tag_id} is already retracted"));
                }
                tag.retraction = Some(TagRetraction {
                    key: key.clone(),
                    reason: reason.clone(),
                    revision: record.revision,
                });
            }
            Event::ObservationWindowTagged { window, tags } => {
                let action = self
                    .actions
                    .iter()
                    .find(|action| action.id == window.action_id)
                    .ok_or_else(|| format!("unknown action {}", window.action_id))?;
                let start_ns = action
                    .timestamp_ns
                    .ok_or_else(|| format!("action {} has no timestamp", action.id))?;
                if window.key.is_empty()
                    || window.key.len() > 128
                    || window.key.chars().any(char::is_control)
                    || self
                        .window_tags
                        .iter()
                        .any(|old| old.key == window.key || old.id == window.id)
                    || window.start_ns != start_ns
                    || window.end_ns <= start_ns
                    || window.phase.trim().is_empty()
                    || window.label.trim().is_empty()
                    || tags.is_empty()
                    || tags.len() > 1000
                    || tags.len() != window.observation_ids.len()
                {
                    return Err("invalid or duplicate observation window".into());
                }
                let selected: Vec<_> = eligible_window_observations(
                    self,
                    action,
                    window.end_ns,
                    &window.phase,
                    &window.label,
                )?
                .into_iter()
                .map(|observation| observation.id.clone())
                .collect();
                if selected != window.observation_ids {
                    return Err(
                        "observation window selection changed; retry with the same key".into(),
                    );
                }
                for (index, tag) in tags.iter().enumerate() {
                    if tag.observation_id != selected[index]
                        || tag.phase != window.phase
                        || tag.label != window.label
                        || tag.action_id.as_deref() != Some(window.action_id.as_str())
                        || tag.key.is_some()
                        || tag.retraction.is_some()
                        || self.tags.iter().any(|old| old.id == tag.id)
                        || tags[..index].iter().any(|old| old.id == tag.id)
                    {
                        return Err("invalid observation window tag".into());
                    }
                }
                self.window_tags.push(window.clone());
                self.tags.extend(tags.clone());
            }
            Event::CaptureTagged { batch, tags } => {
                if record.schema_version < 11 {
                    return Err("capture tags require schema version 11".into());
                }
                let action = self
                    .actions
                    .iter()
                    .find(|action| action.id == batch.action_id)
                    .ok_or_else(|| format!("unknown action {}", batch.action_id))?;
                let capture = self
                    .captures
                    .iter()
                    .find(|capture| capture.id == batch.capture_id)
                    .ok_or_else(|| format!("unknown capture {}", batch.capture_id))?;
                let end_index = batch
                    .start_index
                    .checked_add(batch.observation_ids.len())
                    .ok_or("capture tag range overflows")?;
                if capture.trial_id != action.trial_id
                    || batch.id != format!("capture-tags-{:06}", record.revision)
                    || batch.key.is_empty()
                    || batch.key.len() > 128
                    || batch.key.chars().any(char::is_control)
                    || batch.phase.trim().is_empty()
                    || batch.label.trim().is_empty()
                    || self.capture_tag_batches.iter().any(|old| {
                        old.key == batch.key
                            || old.id == batch.id
                            || (old.action_id == batch.action_id
                                && old.capture_id == batch.capture_id
                                && old.phase == batch.phase
                                && old.label == batch.label
                                && batch.start_index < old.start_index + old.observation_ids.len()
                                && old.start_index < end_index)
                    })
                    || tags.is_empty()
                    || tags.len() > 1000
                    || tags.len() != batch.observation_ids.len()
                    || batch.tag_ids.len() != tags.len()
                {
                    return Err("invalid or duplicate capture tag batch".into());
                }
                let all_observations: Vec<_> = self
                    .observations
                    .iter()
                    .filter(|observation| observation.capture_id == batch.capture_id)
                    .map(|observation| observation.id.clone())
                    .collect();
                if end_index > all_observations.len()
                    || (record.schema_version < 12
                        && (batch.start_index != 0 || end_index != all_observations.len()))
                {
                    return Err("invalid capture tag range".into());
                }
                let selected = &all_observations[batch.start_index..end_index];
                if selected != batch.observation_ids.as_slice() {
                    return Err("capture tag selection does not match source observations".into());
                }
                for (index, tag) in tags.iter().enumerate() {
                    if tag.id != format!("tag-{:06}-{index:04}", record.revision)
                        || tag.observation_id != selected[index]
                        || batch.tag_ids[index] != tag.id
                        || tag.phase != batch.phase
                        || tag.label != batch.label
                        || tag.action_id.as_deref() != Some(batch.action_id.as_str())
                        || tag.key.is_some()
                        || tag.retraction.is_some()
                        || self.tags.iter().any(|old| old.id == tag.id)
                    {
                        return Err("invalid capture tag".into());
                    }
                }
                self.capture_tag_batches.push(batch.clone());
                self.tags.extend(tags.clone());
            }
            Event::ValueAnnotated { known_value } => {
                if !self
                    .observations
                    .iter()
                    .any(|observation| observation.id == known_value.observation_id)
                {
                    return Err(format!(
                        "unknown observation {}",
                        known_value.observation_id
                    ));
                }
                if known_value.variable.trim().is_empty() {
                    return Err("known-value variable must not be empty".into());
                }
                if let Some(existing) = self.known_values.iter_mut().find(|existing| {
                    existing.observation_id == known_value.observation_id
                        && existing.variable == known_value.variable
                }) {
                    *existing = known_value.clone();
                } else {
                    self.known_values.push(known_value.clone());
                }
            }
            Event::FrameValueAnnotated { known_value } => {
                if record.schema_version < 9 {
                    return Err("frame values require schema version 9".into());
                }
                if self.frame_by_id(&known_value.frame_id).is_none() {
                    return Err(format!("unknown frame {}", known_value.frame_id));
                }
                if known_value.variable.trim().is_empty()
                    || known_value.variable.len() > 128
                    || known_value.variable.chars().any(char::is_control)
                {
                    return Err(
                        "frame-value variable must be 1 to 128 bytes without control characters"
                            .into(),
                    );
                }
                if let Some(existing) = self.frame_known_values.iter_mut().find(|existing| {
                    existing.frame_id == known_value.frame_id
                        && existing.variable == known_value.variable
                }) {
                    *existing = known_value.clone();
                } else {
                    self.frame_known_values.push(known_value.clone());
                }
            }
            Event::AnalysisRecorded { analysis } => {
                let frame_scope =
                    matches!(analysis.scope, Some(AnalysisScope::FrameCluster { .. }));
                let frame_analysis = !analysis.frame_ids.is_empty();
                if self.analyses.iter().any(|a| a.id == analysis.id)
                    || analysis.aligned_width == 0
                    || frame_analysis != analysis.observation_ids.is_empty()
                    || frame_analysis != frame_scope
                    || (frame_analysis && record.schema_version < 14)
                {
                    return Err("empty or duplicate analysis".into());
                }
                for id in &analysis.observation_ids {
                    if !self.observations.iter().any(|o| &o.id == id) {
                        return Err(format!("unknown observation {id}"));
                    }
                }
                if let Some(AnalysisScope::FrameCluster {
                    cluster_id,
                    model,
                    trial_id,
                    direction_mode,
                    run_keys,
                    source_revision,
                }) = &analysis.scope
                {
                    if cluster_id.is_empty()
                        || !["fixed_width", "unsigned_leb128", "delimiter"]
                            .contains(&model.as_str())
                        || !["respect", "ignore"].contains(&direction_mode.as_str())
                        || run_keys.is_empty()
                        || analysis.frame_ids.len() > 32
                        || *source_revision >= record.revision
                        || trial_id
                            .as_ref()
                            .is_some_and(|id| !self.trials.iter().any(|trial| &trial.id == id))
                    {
                        return Err("invalid frame analysis scope".into());
                    }
                    let mut seen = std::collections::BTreeSet::new();
                    let mut seen_run_keys = std::collections::BTreeSet::new();
                    for id in &analysis.frame_ids {
                        let (run_id, observation_id, _) = self
                            .frame_by_id(id)
                            .ok_or_else(|| format!("unknown frame {id}"))?;
                        let run_key = match model.as_str() {
                            "fixed_width" => self
                                .framing_runs
                                .iter()
                                .find(|run| run.id == run_id)
                                .map(|run| run.key.as_str()),
                            "unsigned_leb128" => self
                                .varint_runs
                                .iter()
                                .find(|run| run.id == run_id)
                                .map(|run| run.key.as_str()),
                            "delimiter" => self
                                .delimiter_runs
                                .iter()
                                .find(|run| run.id == run_id)
                                .map(|run| run.key.as_str()),
                            _ => None,
                        };
                        if !seen.insert(id)
                            || run_key
                                .is_none_or(|key| !run_keys.iter().any(|wanted| wanted == key))
                        {
                            return Err(format!("invalid frame analysis member {id}"));
                        }
                        seen_run_keys.insert(run_key.expect("validated above"));
                        if let Some(trial) = trial_id {
                            let observation = self
                                .observations
                                .iter()
                                .find(|observation| observation.id == observation_id)
                                .ok_or_else(|| format!("unknown observation {observation_id}"))?;
                            if !self.captures.iter().any(|capture| {
                                capture.id == observation.capture_id && capture.trial_id == *trial
                            }) {
                                return Err(format!("frame {id} is outside trial {trial}"));
                            }
                        }
                    }
                    if seen_run_keys.len() != run_keys.len() {
                        return Err("frame analysis run keys do not match members".into());
                    }
                }
                self.analyses.push(analysis.clone());
            }
            Event::DecisionRecorded { decision } => {
                if decision.text.trim().is_empty()
                    || self.decisions.iter().any(|d| d.id == decision.id)
                {
                    return Err("empty or duplicate decision".into());
                }
                for id in &decision.evidence_ids {
                    if !self
                        .observations
                        .iter()
                        .any(|observation| &observation.id == id)
                    {
                        return Err(format!("unknown evidence observation {id}"));
                    }
                }
                self.decisions.push(decision.clone());
            }
        }
        self.revision = record.revision;
        Ok(())
    }

    fn require_created(&self) -> Result<(), String> {
        if self.revision == 0 {
            Err("investigation does not exist".into())
        } else {
            Ok(())
        }
    }
}

pub fn eligible_window_observations<'a>(
    state: &'a State,
    action: &Action,
    end_ns: u64,
    phase: &str,
    label: &str,
) -> Result<Vec<&'a Observation>, String> {
    let start_ns = action
        .timestamp_ns
        .ok_or_else(|| format!("action {} has no timestamp", action.id))?;
    if end_ns <= start_ns {
        return Err("window end must be after the action timestamp".into());
    }
    Ok(state
        .observations
        .iter()
        .filter(|observation| {
            observation
                .timestamp_ns
                .is_some_and(|timestamp| timestamp >= start_ns && timestamp < end_ns)
        })
        .filter(|observation| {
            state.captures.iter().any(|capture| {
                capture.id == observation.capture_id && capture.trial_id == action.trial_id
            })
        })
        .filter(|observation| {
            !state.tags.iter().any(|tag| {
                tag.observation_id == observation.id
                    && tag.retraction.is_none()
                    && tag.action_id.as_deref() == Some(action.id.as_str())
                    && tag.phase == phase
                    && tag.label == label
            })
        })
        .collect())
}

fn event_path(root: &Path) -> PathBuf {
    root.join(".pi").join("events.jsonl")
}
fn artifact_dir(root: &Path) -> PathBuf {
    root.join(".pi").join("artifacts")
}

pub fn valid_capture_format(format: &str) -> bool {
    matches!(
        format,
        "hex"
            | "binary"
            | "pcap-icmp"
            | "pcapng-icmp"
            | "pcap-icmpv6"
            | "pcapng-icmpv6"
            | "pcap-udp"
            | "pcapng-udp"
            | "pcap-tcp"
            | "pcapng-tcp"
            | "pcap-tcp-stream"
            | "pcapng-tcp-stream"
    )
}

pub fn capture_run_fingerprint(
    trial_id: &str,
    format: &str,
    timeout_ms: u64,
    argv: &[String],
) -> Result<String, String> {
    let current_dir = std::env::current_dir().map_err(|error| error.to_string())?;
    let encoded = serde_json::to_vec(&(
        trial_id,
        format,
        timeout_ms,
        current_dir.to_string_lossy(),
        argv,
    ))
    .map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

pub fn capture_run_lock(root: &Path, key: &str) -> Result<Option<fs::File>, String> {
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err("capture key must be 1 to 128 printable characters".into());
    }
    let directory = root.join(".pi").join("run-locks");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let digest = format!("{:x}", Sha256::digest(key.as_bytes()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(format!("{digest}.lock")))
        .map_err(|error| error.to_string())?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(error)) => Err(error.to_string()),
    }
}

pub fn create(root: &Path, question: &str) -> Result<EventRecord, String> {
    let path = event_path(root);
    if path.exists() {
        return Err("investigation already exists".into());
    }
    fs::create_dir_all(artifact_dir(root)).map_err(|error| error.to_string())?;
    let record = EventRecord {
        schema_version: SCHEMA_VERSION,
        revision: 1,
        timestamp_ms: now_ms()?,
        event: Event::Created {
            question: question.into(),
        },
    };
    let mut state = State::empty();
    state.apply(&record)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.lock().map_err(|error| error.to_string())?;
    write_record(&mut file, &record)?;
    Ok(record)
}

pub fn load(root: &Path) -> Result<State, String> {
    let path = event_path(root);
    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot open investigation: {error}"))?;
    file.lock_shared().map_err(|error| error.to_string())?;
    load_from_file(&mut file)
}

fn load_from_file(file: &mut fs::File) -> Result<State, String> {
    require_newline_terminated(file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    replay_lines(BufReader::new(file))
}

fn replay_lines(reader: impl BufRead) -> Result<State, String> {
    let mut state = State::empty();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        let record: EventRecord = serde_json::from_str(&line)
            .map_err(|error| format!("event line {}: {error}", index + 1))?;
        state.apply(&record)?;
    }
    if state.revision == 0 {
        return Err("investigation is empty".into());
    }
    Ok(state)
}

fn require_newline_terminated(file: &mut fs::File) -> Result<(), String> {
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    if length == 0 {
        return Err("investigation is empty".into());
    }
    file.seek(SeekFrom::End(-1))
        .map_err(|error| error.to_string())?;
    let mut last = [0];
    file.read_exact(&mut last)
        .map_err(|error| error.to_string())?;
    if last[0] != b'\n' {
        return Err("event log has an unterminated final line; inspect recover-tail".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailRecoveryAction {
    Clean,
    AppendNewline,
    TruncatePartialTail,
}

#[derive(Debug, Serialize)]
pub struct TailRecoveryReport {
    pub action: TailRecoveryAction,
    pub applied: bool,
    pub event_log_bytes_before: u64,
    pub event_log_bytes_after: u64,
    pub last_valid_revision: u64,
    pub recovered_revision: u64,
    pub tail_bytes: usize,
    pub tail_sha256: Option<String>,
    pub backup_path: Option<String>,
}

pub fn recover_tail(root: &Path, apply: bool) -> Result<TailRecoveryReport, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(event_path(root))
        .map_err(|error| error.to_string())?;
    file.lock().map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    if length == 0 {
        return Err("investigation is empty".into());
    }
    file.seek(SeekFrom::End(-1))
        .map_err(|error| error.to_string())?;
    let mut last = [0];
    file.read_exact(&mut last)
        .map_err(|error| error.to_string())?;
    if last[0] == b'\n' {
        let state = load_from_file(&mut file)?;
        return Ok(TailRecoveryReport {
            action: TailRecoveryAction::Clean,
            applied: false,
            event_log_bytes_before: length,
            event_log_bytes_after: length,
            last_valid_revision: state.revision,
            recovered_revision: state.revision,
            tail_bytes: 0,
            tail_sha256: None,
            backup_path: None,
        });
    }
    let scan_length = length.min(MAX_RECOVERY_TAIL_BYTES);
    let scan_start = length - scan_length;
    file.seek(SeekFrom::Start(scan_start))
        .map_err(|error| error.to_string())?;
    let mut scanned = vec![0; usize::try_from(scan_length).map_err(|error| error.to_string())?];
    file.read_exact(&mut scanned)
        .map_err(|error| error.to_string())?;
    let (prefix_end, tail, mut prefix_state) = if let Some(last_newline) =
        scanned.iter().rposition(|byte| *byte == b'\n')
    {
        let prefix_end = scan_start + last_newline as u64 + 1;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let prefix_state = replay_lines(BufReader::new((&mut file).take(prefix_end)))?;
        (prefix_end, &scanned[last_newline + 1..], prefix_state)
    } else if scan_start == 0 {
        (0, scanned.as_slice(), State::empty())
    } else {
        return Err(format!(
            "no complete event line found within the last {MAX_RECOVERY_TAIL_BYTES} bytes; refusing recovery"
        ));
    };
    let last_valid_revision = prefix_state.revision;
    let tail_sha256 = format!("{:x}", Sha256::digest(tail));
    let parsed = serde_json::from_slice::<EventRecord>(tail);
    let (action, recovered_revision, event_log_bytes_after) = match parsed {
        Ok(record) => {
            prefix_state.apply(&record).map_err(|error| {
                format!("unterminated event is invalid ({error}); refusing recovery")
            })?;
            (
                TailRecoveryAction::AppendNewline,
                record.revision,
                length + 1,
            )
        }
        Err(_) if prefix_end == 0 => {
            return Err("first event is incomplete; refusing to discard the investigation".into());
        }
        Err(_) => (
            TailRecoveryAction::TruncatePartialTail,
            last_valid_revision,
            prefix_end,
        ),
    };
    let mut backup_path = None;
    if apply {
        match action {
            TailRecoveryAction::Clean => unreachable!(),
            TailRecoveryAction::AppendNewline => {
                file.seek(SeekFrom::End(0))
                    .map_err(|error| error.to_string())?;
                file.write_all(b"\n").map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
            }
            TailRecoveryAction::TruncatePartialTail => {
                let directory = root.join(".pi").join("recovery");
                fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
                let path =
                    directory.join(format!("tail-{last_valid_revision:06}-{tail_sha256}.bin"));
                if path.exists() {
                    if fs::read(&path).map_err(|error| error.to_string())? != tail {
                        return Err("existing recovery backup has different bytes".into());
                    }
                } else {
                    let temporary = directory.join(format!(
                        ".tail-{last_valid_revision:06}-{tail_sha256}-{}-{}.tmp",
                        std::process::id(),
                        now_ns()?
                    ));
                    let mut backup = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&temporary)
                        .map_err(|error| error.to_string())?;
                    backup.write_all(tail).map_err(|error| error.to_string())?;
                    backup.sync_all().map_err(|error| error.to_string())?;
                    drop(backup);
                    if path.exists() {
                        if fs::read(&path).map_err(|error| error.to_string())? != tail {
                            return Err("existing recovery backup has different bytes".into());
                        }
                        fs::remove_file(&temporary).map_err(|error| error.to_string())?;
                    } else {
                        fs::rename(&temporary, &path).map_err(|error| error.to_string())?;
                    }
                }
                if let Ok(directory_file) = fs::File::open(&directory) {
                    let _ = directory_file.sync_all();
                }
                file.set_len(prefix_end)
                    .map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
                backup_path = Some(path.display().to_string());
            }
        }
        let recovered = load_from_file(&mut file)?;
        if recovered.revision != recovered_revision {
            return Err("recovered event log revision changed unexpectedly".into());
        }
    }
    Ok(TailRecoveryReport {
        action,
        applied: apply,
        event_log_bytes_before: length,
        event_log_bytes_after,
        last_valid_revision,
        recovered_revision,
        tail_bytes: tail.len(),
        tail_sha256: Some(tail_sha256),
        backup_path,
    })
}

pub fn changes_since(root: &Path, revision: u64, limit: usize) -> Result<Vec<EventRecord>, String> {
    let mut file = fs::File::open(event_path(root)).map_err(|error| error.to_string())?;
    file.lock_shared().map_err(|error| error.to_string())?;
    require_newline_terminated(&mut file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut state = State::empty();
    let mut changes = Vec::new();
    for (index, line) in BufReader::new(&file).lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        let record: EventRecord = serde_json::from_str(&line)
            .map_err(|error| format!("event line {}: {error}", index + 1))?;
        state.apply(&record)?;
        if record.revision > revision && changes.len() < limit {
            changes.push(record);
        }
    }
    if revision > state.revision {
        return Err("revision is newer than investigation".into());
    }
    Ok(changes)
}

#[derive(Debug, Serialize)]
pub struct ActivityPreview {
    pub revision: u64,
    pub timestamp_ms: u64,
    pub kind: &'static str,
    pub subject_id: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ActivityPage {
    pub schema_version: u32,
    pub current_revision: u64,
    pub through_revision: u64,
    pub after_revision: u64,
    pub next_after_revision: Option<u64>,
    pub events: Vec<ActivityPreview>,
}

fn activity_text_preview(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(80).collect();
    (preview, chars.next().is_some())
}

fn activity_preview(record: &EventRecord) -> ActivityPreview {
    use serde_json::json;
    let (kind, subject_id, details) = match &record.event {
        Event::Created { .. } => ("created", None, json!({})),
        Event::HypothesisAdded { hypothesis } => {
            ("hypothesis_added", Some(hypothesis.id.clone()), json!({}))
        }
        Event::HypothesisEvaluated {
            hypothesis_id,
            evidence,
            counterexamples,
            ..
        } => (
            "hypothesis_evaluated",
            Some(hypothesis_id.clone()),
            json!({"evidence_count":evidence.len(),"counterexample_count":counterexamples.len(),
                "first_evidence_ids":evidence.iter().take(3).collect::<Vec<_>>(),
                "first_counterexample_ids":counterexamples.iter().take(3).collect::<Vec<_>>() }),
        ),
        Event::ExperimentCreated { experiment } => (
            "experiment_created",
            Some(experiment.id.clone()),
            json!({"hypothesis_count":experiment.hypothesis_ids.len()}),
        ),
        Event::TrialCreated { trial } => (
            "trial_created",
            Some(trial.id.clone()),
            json!({"experiment_id":trial.experiment_id,
                "role_preview":activity_text_preview(&trial.role).0,
                "role_truncated":activity_text_preview(&trial.role).1}),
        ),
        Event::CaptureImported {
            capture,
            observations,
        } => (
            "capture_imported",
            Some(capture.id.clone()),
            json!({"trial_id":capture.trial_id,"format":capture.format,
                "observation_count":observations.len(), "conditions":capture.conditions,
                "first_observation_ids":observations.iter().take(3).map(|item| &item.id).collect::<Vec<_>>(),
                "observation_ids_omitted":observations.len().saturating_sub(3) }),
        ),
        Event::FramingCommitted { run } => (
            "framing_committed",
            Some(run.id.clone()),
            json!({"observation_id":run.observation_id,"record_count":run.records.len()}),
        ),
        Event::VarintCommitted { run } => (
            "varint_committed",
            Some(run.id.clone()),
            json!({"observation_id":run.observation_id,"record_count":run.records.len()}),
        ),
        Event::DelimiterCommitted { run } => (
            "delimiter_committed",
            Some(run.id.clone()),
            json!({"observation_id":run.observation_id,"record_count":run.records.len()}),
        ),
        Event::CaptureRunReserved { run } => (
            "capture_run_reserved",
            Some(run.id.clone()),
            json!({"trial_id":run.trial_id,"key":run.key,"format":run.format}),
        ),
        Event::CaptureRunFailed { key, .. } => ("capture_run_failed", None, json!({"key":key})),
        Event::CaptureRunStopRequested { key } => {
            ("capture_run_stop_requested", None, json!({"key":key}))
        }
        Event::ActionMarked { action } => (
            "action_marked",
            Some(action.id.clone()),
            json!({"trial_id":action.trial_id,
                "kind_preview":activity_text_preview(&action.kind).0,
                "kind_truncated":activity_text_preview(&action.kind).1}),
        ),
        Event::ObservationTagged { tag } => (
            "observation_tagged",
            Some(tag.id.clone()),
            json!({"observation_id":tag.observation_id,"action_id":tag.action_id}),
        ),
        Event::ObservationTagRetracted {
            tag_id,
            key,
            reason,
        } => (
            "observation_tag_retracted",
            Some(tag_id.clone()),
            json!({"key":key,"reason_preview":activity_text_preview(reason).0,
                "reason_truncated":activity_text_preview(reason).1}),
        ),
        Event::ObservationWindowTagged { window, .. } => (
            "observation_window_tagged",
            Some(window.id.clone()),
            json!({"action_id":window.action_id,"observation_count":window.observation_ids.len(),
                "first_observation_ids":window.observation_ids.iter().take(3).collect::<Vec<_>>(),
                "observation_ids_omitted":window.observation_ids.len().saturating_sub(3) }),
        ),
        Event::CaptureTagged { batch, .. } => (
            "capture_tagged",
            Some(batch.id.clone()),
            json!({"capture_id":batch.capture_id,"action_id":batch.action_id,
                "start_index":batch.start_index,"observation_count":batch.observation_ids.len(),
                "first_observation_ids":batch.observation_ids.iter().take(3).collect::<Vec<_>>(),
                "observation_ids_omitted":batch.observation_ids.len().saturating_sub(3) }),
        ),
        Event::ValueAnnotated { known_value } => (
            "value_annotated",
            Some(known_value.id.clone()),
            json!({"observation_id":known_value.observation_id,
                "variable_preview":activity_text_preview(&known_value.variable).0,
                "variable_truncated":activity_text_preview(&known_value.variable).1}),
        ),
        Event::FrameValueAnnotated { known_value } => (
            "frame_value_annotated",
            Some(known_value.id.clone()),
            json!({"frame_id":known_value.frame_id,
                "variable_preview":activity_text_preview(&known_value.variable).0,
                "variable_truncated":activity_text_preview(&known_value.variable).1}),
        ),
        Event::AnalysisRecorded { analysis } => (
            "analysis_recorded",
            Some(analysis.id.clone()),
            json!({"kind":if analysis.frame_ids.is_empty(){"observation"}else{"frame"},
                "entity_count":analysis.observation_ids.len()+analysis.frame_ids.len(),
                "aligned_width":analysis.aligned_width}),
        ),
        Event::DecisionRecorded { decision } => (
            "decision_recorded",
            Some(decision.id.clone()),
            json!({"evidence_count":decision.evidence_ids.len(),
                "first_evidence_ids":decision.evidence_ids.iter().take(3).collect::<Vec<_>>() }),
        ),
        Event::ExperimentAssessed { assessment } => (
            "experiment_assessed",
            Some(assessment.id.clone()),
            json!({"experiment_id":assessment.experiment_id,"verdict":assessment.verdict,
                "evidence_count":assessment.evidence_ids.len(),"basis_revision":assessment.basis_revision}),
        ),
    };
    ActivityPreview {
        revision: record.revision,
        timestamp_ms: record.timestamp_ms,
        kind,
        subject_id,
        details,
    }
}

/// Compact, validated event pages for agents resuming after a capture.
pub fn activity_since(
    root: &Path,
    after_revision: u64,
    limit: usize,
    through_revision: Option<u64>,
) -> Result<ActivityPage, String> {
    if limit == 0 || limit > 100 {
        return Err("activity limit must be between 1 and 100".into());
    }
    let mut file = fs::File::open(event_path(root)).map_err(|error| error.to_string())?;
    file.lock_shared().map_err(|error| error.to_string())?;
    require_newline_terminated(&mut file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut state = State::empty();
    let mut events = Vec::new();
    for (index, line) in BufReader::new(&file).lines().enumerate() {
        let line = line.map_err(|error| error.to_string())?;
        let record: EventRecord = serde_json::from_str(&line)
            .map_err(|error| format!("event line {}: {error}", index + 1))?;
        state.apply(&record)?;
        if record.revision > after_revision
            && through_revision.is_none_or(|through| record.revision <= through)
            && events.len() < limit
        {
            events.push(activity_preview(&record));
        }
    }
    let through_revision = through_revision.unwrap_or(state.revision);
    if after_revision > through_revision || through_revision > state.revision {
        return Err("activity revision range is outside the investigation".into());
    }
    let last_revision = events.last().map_or(after_revision, |event| event.revision);
    Ok(ActivityPage {
        schema_version: SCHEMA_VERSION,
        current_revision: state.revision,
        through_revision,
        after_revision,
        next_after_revision: (last_revision < through_revision).then_some(last_revision),
        events,
    })
}

pub fn append(root: &Path, mut event: Event) -> Result<EventRecord, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(event_path(root))
        .map_err(|error| error.to_string())?;
    file.lock().map_err(|error| error.to_string())?;
    let state = load_from_file(&mut file)?;
    event.assign_ids(state.revision + 1);
    let record = EventRecord {
        schema_version: SCHEMA_VERSION,
        revision: state.revision + 1,
        timestamp_ms: now_ms()?,
        event,
    };
    let mut prospective = state;
    prospective.apply(&record)?;
    write_record(&mut file, &record)?;
    Ok(record)
}

fn write_record(file: &mut fs::File, record: &EventRecord) -> Result<(), String> {
    let mut line = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    line.push(b'\n');
    file.write_all(&line).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn now_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    u64::try_from(duration.as_millis()).map_err(|error| error.to_string())
}

pub fn now_ns() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    u64::try_from(duration.as_nanos()).map_err(|error| error.to_string())
}

pub fn next_id(root: &Path, prefix: &str) -> Result<String, String> {
    Ok(format!("{prefix}-{:06}", load(root)?.revision + 1))
}

pub fn store_artifact(
    root: &Path,
    bytes: &[u8],
    extension: &str,
) -> Result<(String, String), String> {
    let digest = format!("{:x}", Sha256::digest(bytes));
    let relative = format!(".pi/artifacts/{digest}.{extension}");
    let path = root.join(&relative);
    if path.exists() {
        let existing = fs::read(&path).map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(&existing)) != digest {
            return Err(format!("stored artifact has invalid digest: {relative}"));
        }
    } else {
        fs::create_dir_all(artifact_dir(root)).map_err(|error| error.to_string())?;
        // Stage inside the same directory so a reader sees either no artifact
        // or the complete content-addressed file after rename.
        let mut staged = None;
        for attempt in 0..100 {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| error.to_string())?
                .as_nanos();
            let candidate = artifact_dir(root)
                .join(format!(".pending-{}-{nonce}-{attempt}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => {
                    staged = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        let (staged_path, mut file) = staged.ok_or("could not stage artifact")?;
        let result = (|| {
            file.write_all(bytes).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            fs::rename(&staged_path, &path).map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staged_path);
        }
        result?;
    }
    Ok((digest, relative))
}

pub fn import_capture(
    root: &Path,
    trial_id: &str,
    source: &str,
    format: &str,
    raw: &[u8],
) -> Result<EventRecord, String> {
    import_capture_for_run(root, trial_id, source, format, raw, None)
}

pub fn import_capture_for_run(
    root: &Path,
    trial_id: &str,
    source: &str,
    format: &str,
    raw: &[u8],
    run_key: Option<&str>,
) -> Result<EventRecord, String> {
    import_capture_with_conditions(root, trial_id, source, format, raw, run_key, None)
}

pub fn import_capture_with_conditions(
    root: &Path,
    trial_id: &str,
    source: &str,
    format: &str,
    raw: &[u8],
    run_key: Option<&str>,
    conditions: Option<crate::capture::CaptureConditions>,
) -> Result<EventRecord, String> {
    let revision = load(root)?.revision + 1;
    let capture_id = format!("cap-{revision:06}");
    let observations = match format {
        "hex" => parse_hex_observations(raw, &capture_id)?,
        "binary" => {
            if raw.is_empty() || raw.len() > MAX_BINARY_OBSERVATION_BYTES {
                return Err(format!(
                    "binary file must contain 1 to {MAX_BINARY_OBSERVATION_BYTES} bytes"
                ));
            }
            vec![Observation {
                id: format!("obs-{revision:06}-0000"),
                capture_id: capture_id.clone(),
                source_index: 0,
                source_offset: Some(0),
                timestamp_ns: None,
                direction: None,
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: Vec::new(),
                bytes_hex: to_hex(raw),
            }]
        }
        "pcap-tcp-stream" | "pcapng-tcp-stream" => {
            let segments = if format == "pcap-tcp-stream" {
                extract_tcp_segments(raw)?
            } else {
                extract_pcapng_tcp_segments(raw)?
            };
            reassemble_tcp_segments(&segments)?
                .into_iter()
                .enumerate()
                .map(|(index, message)| Observation {
                    id: format!("obs-{revision:06}-{index:04}"),
                    capture_id: capture_id.clone(),
                    source_index: message.first_packet_index,
                    source_offset: None,
                    timestamp_ns: Some(message.first_timestamp_ns),
                    direction: Some(ip_direction(message.source_ip, message.destination_ip)),
                    source_port: Some(message.source_port),
                    destination_port: Some(message.destination_port),
                    tcp_sequence: Some(message.tcp_sequence),
                    stream_gap_before: message.gap_before,
                    source_spans: message.source_spans,
                    bytes_hex: to_hex(&message.bytes),
                })
                .collect()
        }
        "pcap-icmp" | "pcapng-icmp" | "pcap-icmpv6" | "pcapng-icmpv6" | "pcap-udp"
        | "pcapng-udp" | "pcap-tcp" | "pcapng-tcp" => {
            let messages = match format {
                "pcap-icmp" => extract_icmp_messages(raw)?,
                "pcapng-icmp" => extract_pcapng_icmp_messages(raw)?,
                "pcap-icmpv6" => extract_icmpv6_messages(raw)?,
                "pcapng-icmpv6" => extract_pcapng_icmpv6_messages(raw)?,
                "pcap-udp" => extract_udp_messages(raw)?,
                "pcapng-udp" => extract_pcapng_udp_messages(raw)?,
                "pcap-tcp" => extract_tcp_segments(raw)?,
                "pcapng-tcp" => extract_pcapng_tcp_segments(raw)?,
                _ => unreachable!(),
            };
            messages
                .into_iter()
                .enumerate()
                .map(|(index, message)| Observation {
                    id: format!("obs-{revision:06}-{index:04}"),
                    capture_id: capture_id.clone(),
                    source_index: message.packet_index,
                    source_offset: Some(message.source_offset),
                    timestamp_ns: Some(message.timestamp_ns),
                    direction: Some(ip_direction(message.source_ip, message.destination_ip)),
                    source_port: message.source_port,
                    destination_port: message.destination_port,
                    tcp_sequence: message.tcp_sequence,
                    stream_gap_before: false,
                    source_spans: Vec::new(),
                    bytes_hex: to_hex(&message.bytes),
                })
                .collect()
        }
        _ => {
            return Err("unknown capture format; use --help for supported formats".into());
        }
    };
    if observations.is_empty() {
        return Err("capture produced no supported messages".into());
    }
    let extension = match format {
        "hex" => "hex",
        "binary" => "bin",
        "pcap-icmp" | "pcap-icmpv6" | "pcap-udp" | "pcap-tcp" | "pcap-tcp-stream" => "pcap",
        "pcapng-icmp" | "pcapng-icmpv6" | "pcapng-udp" | "pcapng-tcp" | "pcapng-tcp-stream" => {
            "pcapng"
        }
        _ => unreachable!("format validated above"),
    };
    let (sha256, artifact) = store_artifact(root, raw, extension)?;
    let capture = Capture {
        id: capture_id,
        trial_id: trial_id.into(),
        format: format.into(),
        source: source.into(),
        sha256,
        artifact,
        observation_count: observations.len(),
        run_key: run_key.map(str::to_owned),
        conditions,
    };
    append(
        root,
        Event::CaptureImported {
            capture,
            observations,
        },
    )
}

fn parse_hex_observations(raw: &[u8], capture_id: &str) -> Result<Vec<Observation>, String> {
    let text = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
    let revision = capture_id.trim_start_matches("cap-");
    let mut observations = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let samples = crate::parse_hex_samples(line)
            .map_err(|error| format!("line {}: {error}", line_index + 1))?;
        let index = observations.len();
        observations.push(Observation {
            id: format!("obs-{revision}-{index:04}"),
            capture_id: capture_id.into(),
            source_index: line_index + 1,
            source_offset: None,
            timestamp_ns: None,
            direction: None,
            source_port: None,
            destination_port: None,
            tcp_sequence: None,
            stream_gap_before: false,
            source_spans: Vec::new(),
            bytes_hex: to_hex(&samples[0]),
        });
    }
    Ok(observations)
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn ip_direction(source: IpAddr, destination: IpAddr) -> String {
    format!("{source} -> {destination}")
}

pub fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    crate::parse_hex_samples(text)
        .map_err(|error| error.to_string())
        .and_then(|samples| samples.into_iter().next().ok_or("empty hex".into()))
}

#[derive(Debug, Serialize)]
pub struct Verification {
    pub revision: u64,
    pub captures: usize,
    pub observations: usize,
    pub analyses: usize,
    pub frame_analyses: usize,
    pub artifacts_verified: usize,
}

/// Check artifact hashes and replay extracted messages against the original bytes.
pub fn verify(root: &Path) -> Result<Verification, String> {
    let state = load(root)?;
    let mut artifacts_verified = 0;
    for capture in &state.captures {
        let raw = fs::read(root.join(&capture.artifact))
            .map_err(|error| format!("capture {}: {error}", capture.id))?;
        if format!("{:x}", Sha256::digest(&raw)) != capture.sha256 {
            return Err(format!("capture {} has a SHA-256 mismatch", capture.id));
        }
        if let Some(conditions) = &capture.conditions {
            let quality = crate::pcap::pcapng_quality(&raw)?;
            if serde_json::to_value(&quality).map_err(|e| e.to_string())?
                != serde_json::to_value(&conditions.quality).map_err(|e| e.to_string())?
                || raw.len() >= conditions.output_byte_limit
                || conditions.ended_at_ns < conditions.started_at_ns
            {
                return Err(format!("capture {} conditions mismatch", capture.id));
            }
        }
        let actual: Vec<_> = state
            .observations
            .iter()
            .filter(|observation| observation.capture_id == capture.id)
            .collect();
        if actual.len() != capture.observation_count {
            return Err(format!("capture {} observation count mismatch", capture.id));
        }
        match capture.format.as_str() {
            "binary" => {
                if actual.len() != 1
                    || actual[0].source_offset != Some(0)
                    || actual[0].source_index != 0
                    || actual[0].stream_gap_before
                    || !actual[0].source_spans.is_empty()
                    || actual[0].bytes_hex != to_hex(&raw)
                {
                    return Err(format!(
                        "capture {} binary observation mismatch",
                        capture.id
                    ));
                }
            }
            "hex" => {
                let expected = parse_hex_observations(&raw, &capture.id)?;
                for (expected, actual) in expected.iter().zip(actual) {
                    if expected.id != actual.id
                        || expected.bytes_hex != actual.bytes_hex
                        || expected.source_index != actual.source_index
                        || expected.source_offset != actual.source_offset
                        || actual.stream_gap_before
                        || !actual.source_spans.is_empty()
                    {
                        return Err(format!("capture {} observation mismatch", capture.id));
                    }
                }
            }
            "pcap-tcp-stream" | "pcapng-tcp-stream" => {
                let segments = if capture.format == "pcap-tcp-stream" {
                    extract_tcp_segments(&raw)?
                } else {
                    extract_pcapng_tcp_segments(&raw)?
                };
                let expected = reassemble_tcp_segments(&segments)?;
                if expected.len() != actual.len() {
                    return Err(format!("capture {} stream count mismatch", capture.id));
                }
                for (expected, actual) in expected.iter().zip(actual) {
                    if to_hex(&expected.bytes) != actual.bytes_hex
                        || expected.first_packet_index != actual.source_index
                        || actual.source_offset.is_some()
                        || Some(expected.first_timestamp_ns) != actual.timestamp_ns
                        || Some(expected.source_port) != actual.source_port
                        || Some(expected.destination_port) != actual.destination_port
                        || Some(expected.tcp_sequence) != actual.tcp_sequence
                        || expected.gap_before != actual.stream_gap_before
                        || expected.source_spans != actual.source_spans
                        || Some(ip_direction(expected.source_ip, expected.destination_ip))
                            != actual.direction
                    {
                        return Err(format!(
                            "capture {} stream observation mismatch",
                            capture.id
                        ));
                    }
                }
            }
            "pcap-icmp" | "pcapng-icmp" | "pcap-icmpv6" | "pcapng-icmpv6" | "pcap-udp"
            | "pcapng-udp" | "pcap-tcp" | "pcapng-tcp" => {
                let expected = match capture.format.as_str() {
                    "pcap-icmp" => extract_icmp_messages(&raw)?,
                    "pcapng-icmp" => extract_pcapng_icmp_messages(&raw)?,
                    "pcap-icmpv6" => extract_icmpv6_messages(&raw)?,
                    "pcapng-icmpv6" => extract_pcapng_icmpv6_messages(&raw)?,
                    "pcap-udp" => extract_udp_messages(&raw)?,
                    "pcapng-udp" => extract_pcapng_udp_messages(&raw)?,
                    "pcap-tcp" => extract_tcp_segments(&raw)?,
                    "pcapng-tcp" => extract_pcapng_tcp_segments(&raw)?,
                    _ => unreachable!(),
                };
                if expected.len() != actual.len() {
                    return Err(format!("capture {} extraction count mismatch", capture.id));
                }
                for (expected, actual) in expected.iter().zip(actual) {
                    if to_hex(&expected.bytes) != actual.bytes_hex
                        || expected.packet_index != actual.source_index
                        || Some(expected.source_offset) != actual.source_offset
                        || Some(expected.timestamp_ns) != actual.timestamp_ns
                        || expected.source_port != actual.source_port
                        || expected.destination_port != actual.destination_port
                        || expected.tcp_sequence != actual.tcp_sequence
                        || actual.stream_gap_before
                        || !actual.source_spans.is_empty()
                        || Some(ip_direction(expected.source_ip, expected.destination_ip))
                            != actual.direction
                    {
                        return Err(format!("capture {} observation mismatch", capture.id));
                    }
                }
            }
            other => return Err(format!("unknown capture format {other}")),
        }
        artifacts_verified += 1;
    }
    for analysis in &state.analyses {
        let expected_digest = Path::new(&analysis.artifact)
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.split_once('.'))
            .map(|(digest, _)| digest)
            .ok_or_else(|| format!("invalid analysis artifact path: {}", analysis.artifact))?;
        let bytes = fs::read(root.join(&analysis.artifact))
            .map_err(|error| format!("analysis {}: {error}", analysis.id))?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected_digest {
            return Err(format!("analysis {} has a SHA-256 mismatch", analysis.id));
        }
        if let Some(AnalysisScope::FrameCluster {
            cluster_id,
            model,
            trial_id,
            direction_mode,
            run_keys,
            source_revision,
        }) = &analysis.scope
        {
            let stored: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("analysis {}: {error}", analysis.id))?;
            if stored["cluster_id"] != *cluster_id
                || stored["source_model"] != *model
                || stored["trial_id"] != serde_json::json!(trial_id)
                || stored["direction_mode"] != *direction_mode
                || stored["revision"] != *source_revision
                || stored["frame_ids"] != serde_json::json!(analysis.frame_ids)
                || stored["run_keys"] != serde_json::json!(run_keys)
                || stored["analysis"]["aligned_width"] != analysis.aligned_width
            {
                return Err(format!(
                    "analysis {} metadata does not match its artifact",
                    analysis.id
                ));
            }
        }
        artifacts_verified += 1;
    }
    Ok(Verification {
        revision: state.revision,
        captures: state.captures.len(),
        observations: state.observations.len(),
        analyses: state.analyses.len(),
        frame_analyses: state
            .analyses
            .iter()
            .filter(|analysis| !analysis.frame_ids.is_empty())
            .count(),
        artifacts_verified,
    })
}

#[cfg(test)]
pub(crate) fn create_test_state() -> State {
    let mut state = State::empty();
    state.question = "test".into();
    state.revision = 1;
    state
}
