//! Durable, append-only investigation records for iterative analysis.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pcap::{
    extract_icmp_messages, extract_pcapng_icmp_messages, extract_pcapng_tcp_segments,
    extract_pcapng_udp_messages, extract_tcp_segments, extract_udp_messages,
};
use crate::reassembly::{SourceSpan, reassemble_tcp_segments};

const SCHEMA_VERSION: u32 = 5;
const MAX_BINARY_OBSERVATION_BYTES: usize = 1024 * 1024;

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
    #[serde(default)]
    pub run_key: Option<String>,
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
pub struct Tag {
    pub id: String,
    pub observation_id: String,
    pub label: String,
    pub phase: String,
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
pub struct Action {
    pub id: String,
    pub trial_id: String,
    pub kind: String,
    pub detail: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRecord {
    pub id: String,
    pub observation_ids: Vec<String>,
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
    TrialCreated {
        trial: Trial,
    },
    CaptureImported {
        capture: Capture,
        observations: Vec<Observation>,
    },
    CaptureRunReserved {
        run: CaptureRun,
    },
    CaptureRunFailed {
        key: String,
        error: String,
    },
    ActionMarked {
        action: Action,
    },
    ObservationTagged {
        tag: Tag,
    },
    ValueAnnotated {
        known_value: KnownValue,
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
            | Self::CaptureRunFailed { .. } => {}
            Self::HypothesisAdded { hypothesis } => {
                hypothesis.id = format!("hyp-{revision:06}");
            }
            Self::ExperimentCreated { experiment } => {
                experiment.id = format!("exp-{revision:06}");
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
            Self::CaptureRunReserved { run } => {
                run.id = format!("run-{revision:06}");
            }
            Self::ActionMarked { action } => {
                action.id = format!("action-{revision:06}");
            }
            Self::ObservationTagged { tag } => {
                tag.id = format!("tag-{revision:06}");
            }
            Self::ValueAnnotated { known_value } => {
                known_value.id = format!("value-{revision:06}");
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
    pub trials: Vec<Trial>,
    pub captures: Vec<Capture>,
    pub capture_runs: Vec<CaptureRun>,
    pub observations: Vec<Observation>,
    pub actions: Vec<Action>,
    pub tags: Vec<Tag>,
    pub known_values: Vec<KnownValue>,
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
            capture_runs: Vec::new(),
            observations: Vec::new(),
            actions: Vec::new(),
            tags: Vec::new(),
            known_values: Vec::new(),
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
                self.observations.extend(observations.clone());
                if let Some(index) = run_index {
                    self.capture_runs[index].status = CaptureRunStatus::Completed;
                    self.capture_runs[index].capture_id = Some(capture.id.clone());
                }
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

pub fn valid_capture_format(format: &str) -> bool {
    matches!(
        format,
        "hex"
            | "binary"
            | "pcap-icmp"
            | "pcapng-icmp"
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
    let file = fs::File::open(event_path(root)).map_err(|error| error.to_string())?;
    file.lock_shared().map_err(|error| error.to_string())?;
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
                    direction: Some(ipv4_direction(
                        message.source_ipv4,
                        message.destination_ipv4,
                    )),
                    source_port: Some(message.source_port),
                    destination_port: Some(message.destination_port),
                    tcp_sequence: Some(message.tcp_sequence),
                    stream_gap_before: message.gap_before,
                    source_spans: message.source_spans,
                    bytes_hex: to_hex(&message.bytes),
                })
                .collect()
        }
        "pcap-icmp" | "pcapng-icmp" | "pcap-udp" | "pcapng-udp" | "pcap-tcp" | "pcapng-tcp" => {
            let messages = match format {
                "pcap-icmp" => extract_icmp_messages(raw)?,
                "pcapng-icmp" => extract_pcapng_icmp_messages(raw)?,
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
                    direction: Some(ipv4_direction(
                        message.source_ipv4,
                        message.destination_ipv4,
                    )),
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
        "pcap-icmp" | "pcap-udp" | "pcap-tcp" | "pcap-tcp-stream" => "pcap",
        "pcapng-icmp" | "pcapng-udp" | "pcapng-tcp" | "pcapng-tcp-stream" => "pcapng",
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
                        || Some(ipv4_direction(
                            expected.source_ipv4,
                            expected.destination_ipv4,
                        )) != actual.direction
                    {
                        return Err(format!(
                            "capture {} stream observation mismatch",
                            capture.id
                        ));
                    }
                }
            }
            "pcap-icmp" | "pcapng-icmp" | "pcap-udp" | "pcapng-udp" | "pcap-tcp" | "pcapng-tcp" => {
                let expected = match capture.format.as_str() {
                    "pcap-icmp" => extract_icmp_messages(&raw)?,
                    "pcapng-icmp" => extract_pcapng_icmp_messages(&raw)?,
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
