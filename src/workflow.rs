//! Durable, append-only investigation records for iterative analysis.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pcap::extract_icmp_messages;

const SCHEMA_VERSION: u32 = 1;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: String,
    pub capture_id: String,
    pub source_index: usize,
    pub source_offset: Option<usize>,
    pub timestamp_ns: Option<u64>,
    pub direction: Option<String>,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub observation_id: String,
    pub label: String,
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub trial_id: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRecord {
    pub id: String,
    pub observation_ids: Vec<String>,
    pub artifact: String,
    pub aligned_width: usize,
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
    TrialCreated {
        trial: Trial,
    },
    CaptureImported {
        capture: Capture,
        observations: Vec<Observation>,
    },
    ActionMarked {
        action: Action,
    },
    ObservationTagged {
        tag: Tag,
    },
    AnalysisRecorded {
        analysis: AnalysisRecord,
    },
    DecisionRecorded {
        decision: Decision,
    },
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
    pub trials: Vec<Trial>,
    pub captures: Vec<Capture>,
    pub observations: Vec<Observation>,
    pub actions: Vec<Action>,
    pub tags: Vec<Tag>,
    pub analyses: Vec<AnalysisRecord>,
    pub decisions: Vec<Decision>,
}

impl State {
    fn empty() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            revision: 0,
            question: String::new(),
            hypotheses: Vec::new(),
            experiments: Vec::new(),
            trials: Vec::new(),
            captures: Vec::new(),
            observations: Vec::new(),
            actions: Vec::new(),
            tags: Vec::new(),
            analyses: Vec::new(),
            decisions: Vec::new(),
        }
    }

    fn apply(&mut self, record: &EventRecord) -> Result<(), String> {
        if record.schema_version != SCHEMA_VERSION || record.revision != self.revision + 1 {
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
                }
                self.captures.push(capture.clone());
                self.observations.extend(observations.clone());
            }
            Event::ActionMarked { action } => {
                if !self.trials.iter().any(|t| t.id == action.trial_id) {
                    return Err(format!("unknown trial {}", action.trial_id));
                }
                if action.kind.trim().is_empty() || self.actions.iter().any(|a| a.id == action.id) {
                    return Err("empty or duplicate action".into());
                }
                self.actions.push(action.clone());
            }
            Event::ObservationTagged { tag } => {
                if !self.observations.iter().any(|o| o.id == tag.observation_id) {
                    return Err(format!("unknown observation {}", tag.observation_id));
                }
                if tag.label.trim().is_empty()
                    || tag.phase.trim().is_empty()
                    || self.tags.iter().any(|t| t.id == tag.id)
                {
                    return Err("empty or duplicate tag".into());
                }
                self.tags.push(tag.clone());
            }
            Event::AnalysisRecorded { analysis } => {
                if analysis.observation_ids.is_empty()
                    || self.analyses.iter().any(|a| a.id == analysis.id)
                {
                    return Err("empty or duplicate analysis".into());
                }
                for id in &analysis.observation_ids {
                    if !self.observations.iter().any(|o| &o.id == id) {
                        return Err(format!("unknown observation {id}"));
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

fn event_path(root: &Path) -> PathBuf {
    root.join(".pi").join("events.jsonl")
}
fn artifact_dir(root: &Path) -> PathBuf {
    root.join(".pi").join("artifacts")
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
    write_record(&mut file, &record)?;
    Ok(record)
}

pub fn load(root: &Path) -> Result<State, String> {
    let path = event_path(root);
    let file =
        fs::File::open(path).map_err(|error| format!("cannot open investigation: {error}"))?;
    let mut state = State::empty();
    for (index, line) in BufReader::new(file).lines().enumerate() {
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

pub fn changes_since(root: &Path, revision: u64, limit: usize) -> Result<Vec<EventRecord>, String> {
    let current = load(root)?.revision;
    if revision > current {
        return Err("revision is newer than investigation".into());
    }
    let file = fs::File::open(event_path(root)).map_err(|error| error.to_string())?;
    BufReader::new(file)
        .lines()
        .skip(revision as usize)
        .take(limit)
        .map(|line| {
            let line = line.map_err(|error| error.to_string())?;
            serde_json::from_str(&line).map_err(|error| error.to_string())
        })
        .collect()
}

pub fn append(root: &Path, event: Event) -> Result<EventRecord, String> {
    let state = load(root)?;
    let record = EventRecord {
        schema_version: SCHEMA_VERSION,
        revision: state.revision + 1,
        timestamp_ms: now_ms()?,
        event,
    };
    let mut prospective = state;
    prospective.apply(&record)?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(event_path(root))
        .map_err(|error| error.to_string())?;
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
        fs::write(&path, bytes).map_err(|error| error.to_string())?;
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
    let revision = load(root)?.revision + 1;
    let capture_id = format!("cap-{revision:06}");
    let observations = match format {
        "hex" => parse_hex_observations(raw, &capture_id)?,
        "pcap-icmp" => extract_icmp_messages(raw)?
            .into_iter()
            .enumerate()
            .map(|(index, message)| Observation {
                id: format!("obs-{revision:06}-{index:04}"),
                capture_id: capture_id.clone(),
                source_index: message.packet_index,
                source_offset: Some(message.source_offset),
                timestamp_ns: Some(message.timestamp_ns),
                direction: Some(ipv4_direction(
                    message.source_ipv4,
                    message.destination_ipv4,
                )),
                bytes_hex: to_hex(&message.bytes),
            })
            .collect(),
        _ => return Err("format must be hex or pcap-icmp".into()),
    };
    if observations.is_empty() {
        return Err("capture produced no supported messages".into());
    }
    let extension = if format == "hex" { "hex" } else { "pcap" };
    let (sha256, artifact) = store_artifact(root, raw, extension)?;
    let capture = Capture {
        id: capture_id,
        trial_id: trial_id.into(),
        format: format.into(),
        source: source.into(),
        sha256,
        artifact,
        observation_count: observations.len(),
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

fn ipv4_direction(source: [u8; 4], destination: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{} -> {}.{}.{}.{}",
        source[0],
        source[1],
        source[2],
        source[3],
        destination[0],
        destination[1],
        destination[2],
        destination[3]
    )
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
        let actual: Vec<_> = state
            .observations
            .iter()
            .filter(|observation| observation.capture_id == capture.id)
            .collect();
        if actual.len() != capture.observation_count {
            return Err(format!("capture {} observation count mismatch", capture.id));
        }
        match capture.format.as_str() {
            "hex" => {
                let expected = parse_hex_observations(&raw, &capture.id)?;
                for (expected, actual) in expected.iter().zip(actual) {
                    if expected.id != actual.id
                        || expected.bytes_hex != actual.bytes_hex
                        || expected.source_index != actual.source_index
                        || expected.source_offset != actual.source_offset
                    {
                        return Err(format!("capture {} observation mismatch", capture.id));
                    }
                }
            }
            "pcap-icmp" => {
                let expected = extract_icmp_messages(&raw)?;
                if expected.len() != actual.len() {
                    return Err(format!("capture {} extraction count mismatch", capture.id));
                }
                for (expected, actual) in expected.iter().zip(actual) {
                    if to_hex(&expected.bytes) != actual.bytes_hex
                        || expected.packet_index != actual.source_index
                        || Some(expected.source_offset) != actual.source_offset
                        || Some(expected.timestamp_ns) != actual.timestamp_ns
                        || Some(ipv4_direction(
                            expected.source_ipv4,
                            expected.destination_ipv4,
                        )) != actual.direction
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
        if format!("{:x}", Sha256::digest(bytes)) != expected_digest {
            return Err(format!("analysis {} has a SHA-256 mismatch", analysis.id));
        }
        artifacts_verified += 1;
    }
    Ok(Verification {
        revision: state.revision,
        captures: state.captures.len(),
        observations: state.observations.len(),
        analyses: state.analyses.len(),
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
