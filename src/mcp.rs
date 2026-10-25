//! Stdio MCP adapter. Investigation state and CLI semantics remain authoritative.

use std::path::{Path, PathBuf};

use protocol_informatics_v2::{
    checksum, clustering, delimiter, exchanges, framing, inference, query, review, tlv, varint,
    workflow,
};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::process::Command;

#[derive(Clone, Debug)]
struct InvestigationServer {
    root: PathBuf,
}

#[derive(Deserialize, JsonSchema)]
struct PageInput {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_page_limit")]
    limit: usize,
}

fn default_page_limit() -> usize {
    50
}

#[derive(Deserialize, JsonSchema)]
struct SpanInput {
    observation_id: String,
    start: usize,
    end: usize,
}

#[derive(Deserialize, JsonSchema)]
struct PairInput {
    capture_id: String,
    max_lag_ms: Option<u64>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_pair_limit")]
    limit: usize,
}

fn default_pair_limit() -> usize {
    20
}

#[derive(Deserialize, JsonSchema)]
struct ValidateExchangeInput {
    discovery_capture_id: String,
    validation_capture_id: String,
    max_lag_ms: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
struct ClusterInput {
    trial_id: Option<String>,
    #[serde(default = "default_true")]
    respect_direction: bool,
}

#[derive(Deserialize, JsonSchema)]
struct FrameClusterInput {
    model: String,
    trial_id: Option<String>,
    run_keys: Option<Vec<String>>,
    #[serde(default = "default_true")]
    respect_direction: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize, JsonSchema)]
struct ValidateClusterInput {
    discovery_trial_id: String,
    validation_trial_id: String,
    #[serde(default = "default_true")]
    respect_direction: bool,
}

#[derive(Deserialize, JsonSchema)]
struct ExperimentInput {
    question: String,
    #[serde(default)]
    hypothesis_ids: Vec<String>,
    prediction: String,
}

#[derive(Deserialize, JsonSchema)]
struct TrialInput {
    experiment_id: String,
    role: String,
    changed_factor: String,
}

#[derive(Deserialize, JsonSchema)]
struct HypothesisInput {
    claim: String,
}

#[derive(Deserialize, JsonSchema)]
struct EvaluateInput {
    hypothesis_id: String,
    /// Analyst or agent rating from 0 to 1; the engine does not calculate a probability.
    score: f64,
    #[serde(default)]
    evidence_ids: Vec<String>,
    #[serde(default)]
    counterexample_ids: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct DecisionInput {
    text: String,
    #[serde(default)]
    evidence_ids: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct ValueInput {
    observation_id: String,
    variable: String,
    /// Exact unsigned decimal or 0x-prefixed integer, supplied as text to preserve 64-bit values.
    value: String,
    /// Discovery or validation.
    set: String,
}

#[derive(Deserialize, JsonSchema)]
struct VariableInput {
    variable: String,
}

#[derive(Deserialize, JsonSchema)]
struct TrialPairInput {
    discovery_trial_id: String,
    validation_trial_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct DelimiterProbeInput {
    observation_id: String,
    start_offset: usize,
    delimiter_hex: String,
}

#[derive(Deserialize, JsonSchema)]
struct DelimiterCommitInput {
    observation_id: String,
    start_offset: usize,
    delimiter_hex: String,
    key: String,
}

#[derive(Deserialize, JsonSchema)]
struct FramingProbeInput {
    observation_id: String,
    start_offset: usize,
    prefix_offset: usize,
    prefix_width: usize,
    byte_order: String,
    length_mode: String,
    alignment: usize,
}

#[derive(Deserialize, JsonSchema)]
struct FramingCommitInput {
    observation_id: String,
    start_offset: usize,
    prefix_offset: usize,
    prefix_width: usize,
    byte_order: String,
    length_mode: String,
    alignment: usize,
    key: String,
}

#[derive(Deserialize, JsonSchema)]
struct TlvProbeInput {
    observation_id: String,
    start_offset: usize,
    type_width: usize,
    length_width: usize,
    byte_order: String,
    length_mode: String,
    alignment: usize,
}

#[derive(Deserialize, JsonSchema)]
struct VarintProbeInput {
    observation_id: String,
    start_offset: usize,
    field_offset: usize,
    length_mode: String,
    alignment: usize,
}

#[derive(Deserialize, JsonSchema)]
struct VarintCommitInput {
    observation_id: String,
    start_offset: usize,
    field_offset: usize,
    length_mode: String,
    alignment: usize,
    key: String,
}

#[derive(Deserialize, JsonSchema)]
struct FrameSpanInput {
    frame_id: String,
    start: usize,
    end: usize,
}

#[derive(Deserialize, JsonSchema)]
struct FramePageInput {
    key: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_page_limit")]
    limit: usize,
}

#[derive(Deserialize, JsonSchema)]
struct FrameRunPageInput {
    trial_id: Option<String>,
    model: Option<String>,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_page_limit")]
    limit: usize,
}

#[derive(Deserialize, JsonSchema)]
struct FrameValueInput {
    frame_id: String,
    variable: String,
    /// Exact unsigned decimal or 0x-prefixed integer, supplied as text to preserve 64-bit values.
    value: String,
    /// Discovery or validation.
    set: String,
}

#[derive(Deserialize, JsonSchema)]
struct ChecksumInput {
    discovery_trial_id: String,
    validation_trial_id: String,
    baseline_trial_id: String,
    variant_trial_id: String,
    controlled_variable: String,
}

#[derive(Deserialize, JsonSchema)]
struct MarkInput {
    trial_id: String,
    kind: String,
    detail: String,
    key: String,
    timestamp_ns: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
struct CaptureStepInput {
    trial_id: String,
    kind: String,
    detail: String,
    phase: String,
    label: String,
    step_key: String,
    format: String,
    timeout_ms: u64,
    /// Program and arguments as separate strings. No shell is inserted.
    command: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct CaptureStartInput {
    trial_id: String,
    format: String,
    key: String,
    timeout_ms: u64,
    /// Program and arguments as separate strings. No shell is inserted.
    command: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct KeyInput {
    key: String,
}

#[derive(Deserialize, JsonSchema)]
struct TagCaptureInput {
    action_id: String,
    capture_id: String,
    phase: String,
    label: String,
    key: String,
    offset: Option<usize>,
    count: Option<usize>,
}

impl InvestigationServer {
    fn load(&self) -> Result<workflow::State, String> {
        workflow::load(&self.root)
    }

    fn json<T: serde::Serialize>(value: T) -> Result<CallToolResult, String> {
        serde_json::to_value(value)
            .map(CallToolResult::structured)
            .map_err(|error| error.to_string())
    }

    async fn invoke_value(&self, command: &str, arguments: Vec<String>) -> Result<Value, String> {
        let binary = std::env::current_exe().map_err(|error| error.to_string())?;
        let output = Command::new(binary)
            .arg(command)
            .arg(&self.root)
            .args(arguments)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|error| format!("{command} could not start: {error}"))?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr);
            return Err(format!("{command} failed: {}", message.trim()));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("{command} returned invalid JSON: {error}"))
    }

    async fn invoke(
        &self,
        command: &str,
        arguments: Vec<String>,
    ) -> Result<CallToolResult, String> {
        Ok(CallToolResult::structured(
            self.invoke_value(command, arguments).await?,
        ))
    }
}

fn compact_batch(batch: &Value) -> Value {
    let ids = batch["observation_ids"].as_array();
    json!({
        "id":batch["id"],
        "key":batch["key"],
        "start_index":batch["start_index"],
        "observation_count":ids.map_or(0, Vec::len),
        "first_observation_ids":ids.map(|items| items.iter().take(20).cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "observation_ids_omitted":ids.map_or(0, |items| items.len().saturating_sub(20)),
    })
}

fn comma_ids(ids: &[String]) -> String {
    if ids.is_empty() {
        "-".into()
    } else {
        ids.join(",")
    }
}

#[tool_router]
impl InvestigationServer {
    #[tool(
        description = "Bounded overview of corpus, trials, formats, and reserved capture keys.",
        annotations(read_only_hint = true)
    )]
    fn summary(&self) -> Result<CallToolResult, String> {
        Self::json(query::corpus_summary(&self.load()?))
    }

    #[tool(
        description = "Page trial IDs and controlled-factor metadata, newest first.",
        annotations(read_only_hint = true)
    )]
    fn trials(&self, Parameters(input): Parameters<PageInput>) -> Result<CallToolResult, String> {
        Self::json(query::list_trials(
            &self.load()?,
            input.offset,
            input.limit,
        )?)
    }

    #[tool(
        description = "Page experiment questions, predictions, linked hypotheses, and trial counts, newest first.",
        annotations(read_only_hint = true)
    )]
    fn experiments(
        &self,
        Parameters(input): Parameters<PageInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(query::list_experiments(
            &self.load()?,
            input.offset,
            input.limit,
        )?)
    }

    #[tool(
        description = "Page hypothesis claims, current analyst or agent ratings, and bounded evidence IDs, newest first.",
        annotations(read_only_hint = true)
    )]
    fn hypotheses(
        &self,
        Parameters(input): Parameters<PageInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(query::list_hypotheses(
            &self.load()?,
            input.offset,
            input.limit,
        )?)
    }

    #[tool(
        description = "Page recorded decisions and bounded evidence IDs, newest first.",
        annotations(read_only_hint = true)
    )]
    fn decisions(
        &self,
        Parameters(input): Parameters<PageInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(query::list_decisions(
            &self.load()?,
            input.offset,
            input.limit,
        )?)
    }

    #[tool(
        description = "Search observations with exact filters; returns at most 100 previews and a next offset.",
        annotations(read_only_hint = true)
    )]
    fn search_observations(
        &self,
        Parameters(input): Parameters<query::ObservationSearch>,
    ) -> Result<CallToolResult, String> {
        Self::json(query::search_observations(&self.load()?, &input)?)
    }

    #[tool(
        description = "Read a half-open byte span and its original capture provenance.",
        annotations(read_only_hint = true)
    )]
    fn span(&self, Parameters(input): Parameters<SpanInput>) -> Result<CallToolResult, String> {
        Self::json(query::read_span(
            &self.load()?,
            &input.observation_id,
            input.start,
            input.end,
        )?)
    }

    #[tool(
        description = "Page provisional pairs based on reciprocal flow and timing; byte equality never chooses a pair.",
        annotations(read_only_hint = true)
    )]
    fn pair_exchanges(
        &self,
        Parameters(input): Parameters<PairInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(exchanges::pair_exchanges(
            &self.load()?,
            &input.capture_id,
            input.max_lag_ms,
            input.offset,
            input.limit,
        )?)
    }

    #[tool(
        description = "Test varying equal-byte candidates on a separate trial and return named counterexample pairs.",
        annotations(read_only_hint = true)
    )]
    fn validate_exchanges(
        &self,
        Parameters(input): Parameters<ValidateExchangeInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(exchanges::validate_exchanges(
            &self.load()?,
            &input.discovery_capture_id,
            &input.validation_capture_id,
            input.max_lag_ms,
        )?)
    }

    #[tool(
        description = "Discover provisional format groups in the corpus or one trial.",
        annotations(read_only_hint = true)
    )]
    fn cluster(
        &self,
        Parameters(input): Parameters<ClusterInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(clustering::cluster_observations(
            &self.load()?,
            input.trial_id.as_deref(),
            input.respect_direction,
        )?)
    }

    #[tool(
        description = "Discover provisional record groups in committed logical frames of one model, optionally within one trial.",
        annotations(read_only_hint = true)
    )]
    fn cluster_frames(
        &self,
        Parameters(input): Parameters<FrameClusterInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(clustering::cluster_frames(
            &self.load()?,
            &input.model,
            input.trial_id.as_deref(),
            input.respect_direction,
            input.run_keys.as_deref(),
        )?)
    }

    #[tool(
        description = "Check discovered groups against a distinct validation trial, prioritizing counterexamples.",
        annotations(read_only_hint = true)
    )]
    fn validate_clusters(
        &self,
        Parameters(input): Parameters<ValidateClusterInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(clustering::validate_clusters(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
            input.respect_direction,
        )?)
    }

    #[tool(
        description = "Infer exact unsigned field positions from separately annotated discovery and validation observations; returns bounded candidates, not field semantics.",
        annotations(read_only_hint = true)
    )]
    fn infer_value(
        &self,
        Parameters(input): Parameters<VariableInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(inference::infer_unsigned_field(
            &self.load()?,
            &input.variable,
        )?)
    }

    #[tool(
        description = "Test bounded length-prefix record models on distinct discovery and validation trials.",
        annotations(read_only_hint = true)
    )]
    fn infer_framing(
        &self,
        Parameters(input): Parameters<TrialPairInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(framing::infer_length_prefix(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
        )?)
    }

    #[tool(
        description = "Probe one candidate delimiter-terminated record layout with exact byte and source spans.",
        annotations(read_only_hint = true)
    )]
    fn probe_delimiter(
        &self,
        Parameters(input): Parameters<DelimiterProbeInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(delimiter::probe_observation(
            &self.load()?,
            &input.observation_id,
            delimiter::DelimiterConfig {
                start_offset: input.start_offset,
                delimiter_hex: input.delimiter_hex,
            },
        )?)
    }

    #[tool(
        description = "Test suffix-derived delimiter candidates on distinct trials and report held-out counterexamples.",
        annotations(read_only_hint = true)
    )]
    fn infer_delimiter(
        &self,
        Parameters(input): Parameters<TrialPairInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(delimiter::infer_delimiter(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
        )?)
    }

    #[tool(
        description = "Review one discovery/validation trial pair across structural models and held-out grouping; return bounded counterexamples and suggested next tool actions without assigning a probability.",
        annotations(read_only_hint = true)
    )]
    fn review_trials(
        &self,
        Parameters(input): Parameters<TrialPairInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(review::review_trials(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
        )?)
    }

    #[tool(
        description = "Test typed length-value record models on distinct discovery and validation trials.",
        annotations(read_only_hint = true)
    )]
    fn infer_tlv(
        &self,
        Parameters(input): Parameters<TrialPairInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(tlv::infer_tlv(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
        )?)
    }

    #[tool(
        description = "Test unsigned LEB128 length-prefix models on distinct discovery and validation trials.",
        annotations(read_only_hint = true)
    )]
    fn infer_varint(
        &self,
        Parameters(input): Parameters<TrialPairInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(varint::infer_varint(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
        )?)
    }

    #[tool(
        description = "Probe fixed-width length-prefix records on one observation; offsets and source spans are exact.",
        annotations(read_only_hint = true)
    )]
    async fn probe_framing(
        &self,
        Parameters(input): Parameters<FramingProbeInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "probe-framing",
            vec![
                input.observation_id,
                input.start_offset.to_string(),
                input.prefix_offset.to_string(),
                input.prefix_width.to_string(),
                input.byte_order,
                input.length_mode,
                input.alignment.to_string(),
            ],
        )
        .await
    }

    #[tool(
        description = "Probe typed length-value records on one observation with raw type recurrence and exact source spans.",
        annotations(read_only_hint = true)
    )]
    async fn probe_tlv(
        &self,
        Parameters(input): Parameters<TlvProbeInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "probe-tlv",
            vec![
                input.observation_id,
                input.start_offset.to_string(),
                input.type_width.to_string(),
                input.length_width.to_string(),
                input.byte_order,
                input.length_mode,
                input.alignment.to_string(),
            ],
        )
        .await
    }

    #[tool(
        description = "Probe unsigned LEB128 length-prefix records on one observation with exact source spans.",
        annotations(read_only_hint = true)
    )]
    async fn probe_varint(
        &self,
        Parameters(input): Parameters<VarintProbeInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "probe-varint",
            vec![
                input.observation_id,
                input.start_offset.to_string(),
                input.field_offset.to_string(),
                input.length_mode,
                input.alignment.to_string(),
            ],
        )
        .await
    }

    #[tool(
        description = "Commit complete fixed-width record boundaries with a retry-safe key and replay-checked frame IDs.",
        annotations(idempotent_hint = true)
    )]
    async fn commit_framing(
        &self,
        Parameters(input): Parameters<FramingCommitInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "commit-framing",
            vec![
                input.observation_id,
                input.start_offset.to_string(),
                input.prefix_offset.to_string(),
                input.prefix_width.to_string(),
                input.byte_order,
                input.length_mode,
                input.alignment.to_string(),
                input.key,
            ],
        )
        .await
    }

    #[tool(
        description = "Commit complete unsigned LEB128 record boundaries with a retry-safe key and replay-checked frame IDs.",
        annotations(idempotent_hint = true)
    )]
    async fn commit_varint(
        &self,
        Parameters(input): Parameters<VarintCommitInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "commit-varint",
            vec![
                input.observation_id,
                input.start_offset.to_string(),
                input.field_offset.to_string(),
                input.length_mode,
                input.alignment.to_string(),
                input.key,
            ],
        )
        .await
    }

    #[tool(
        description = "Commit complete delimiter-terminated record boundaries with a retry-safe key and replay-checked frame IDs.",
        annotations(idempotent_hint = true)
    )]
    async fn commit_delimiter(
        &self,
        Parameters(input): Parameters<DelimiterCommitInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "commit-delimiter",
            vec![
                input.observation_id,
                input.start_offset.to_string(),
                input.delimiter_hex,
                input.key,
            ],
        )
        .await
    }

    #[tool(
        description = "Inspect a committed fixed-width, unsigned LEB128, or delimiter frame run by retry key.",
        annotations(read_only_hint = true)
    )]
    fn frame_run_status(
        &self,
        Parameters(input): Parameters<KeyInput>,
    ) -> Result<CallToolResult, String> {
        let state = self.load()?;
        if let Some(run) = state.framing_runs.iter().find(|run| run.key == input.key) {
            return Self::json(json!({"revision":state.revision,"model":"fixed_width","run":run}));
        }
        if let Some(run) = state.varint_runs.iter().find(|run| run.key == input.key) {
            return Self::json(
                json!({"revision":state.revision,"model":"unsigned_leb128","run":run}),
            );
        }
        if let Some(run) = state.delimiter_runs.iter().find(|run| run.key == input.key) {
            return Self::json(json!({"revision":state.revision,"model":"delimiter","run":run}));
        }
        Err(format!("unknown frame run key {}", input.key))
    }

    #[tool(
        description = "Page committed frame runs across fixed-width, unsigned LEB128, and delimiter models; optionally filter by trial and model, newest first.",
        annotations(read_only_hint = true)
    )]
    fn frame_runs(
        &self,
        Parameters(input): Parameters<FrameRunPageInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(query::list_frame_runs(
            &self.load()?,
            input.trial_id.as_deref(),
            input.model.as_deref(),
            input.offset,
            input.limit,
        )?)
    }

    #[tool(
        description = "Page stable frame IDs and boundaries for a committed run.",
        annotations(read_only_hint = true)
    )]
    async fn frames(
        &self,
        Parameters(input): Parameters<FramePageInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "frames",
            vec![input.key, input.offset.to_string(), input.limit.to_string()],
        )
        .await
    }

    #[tool(
        description = "Read a half-open frame byte span (up to 4096 bytes) with parent observation offsets and original source provenance.",
        annotations(read_only_hint = true)
    )]
    async fn frame_span(
        &self,
        Parameters(input): Parameters<FrameSpanInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "frame-span",
            vec![
                input.frame_id,
                input.start.to_string(),
                input.end.to_string(),
            ],
        )
        .await
    }

    #[tool(
        description = "Annotate an externally known unsigned value on one committed frame for held-out field inference. This operation is not keyed."
    )]
    async fn annotate_frame_value(
        &self,
        Parameters(input): Parameters<FrameValueInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "frame-value",
            vec![input.frame_id, input.variable, input.value, input.set],
        )
        .await
    }

    #[tool(
        description = "Infer exact field offsets in committed frame bytes using separately annotated discovery and validation captures.",
        annotations(read_only_hint = true)
    )]
    fn infer_frame_value(
        &self,
        Parameters(input): Parameters<VariableInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(inference::infer_frame_unsigned_field(
            &self.load()?,
            &input.variable,
        )?)
    }

    #[tool(
        description = "Test Internet checksum candidates against independent examples and a controlled intervention.",
        annotations(read_only_hint = true)
    )]
    fn infer_checksum(
        &self,
        Parameters(input): Parameters<ChecksumInput>,
    ) -> Result<CallToolResult, String> {
        Self::json(checksum::infer_internet_checksum(
            &self.load()?,
            &input.discovery_trial_id,
            &input.validation_trial_id,
            &input.baseline_trial_id,
            &input.variant_trial_id,
            &input.controlled_variable,
        )?)
    }

    #[tool(
        description = "Verify event replay, artifact hashes, and extracted observations against capture bytes.",
        annotations(read_only_hint = true)
    )]
    fn verify(&self) -> Result<CallToolResult, String> {
        Self::json(workflow::verify(&self.root)?)
    }

    #[tool(
        description = "Create an experiment with a falsifiable question and prediction. This operation is not keyed."
    )]
    async fn create_experiment(
        &self,
        Parameters(input): Parameters<ExperimentInput>,
    ) -> Result<CallToolResult, String> {
        let ids = if input.hypothesis_ids.is_empty() {
            "-".into()
        } else {
            input.hypothesis_ids.join(",")
        };
        self.invoke("experiment", vec![input.question, ids, input.prediction])
            .await
    }

    #[tool(
        description = "Create a controlled trial inside an experiment. This operation is not keyed."
    )]
    async fn create_trial(
        &self,
        Parameters(input): Parameters<TrialInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "trial",
            vec![input.experiment_id, input.role, input.changed_factor],
        )
        .await
    }

    #[tool(
        description = "Create a claim for later evidence evaluation. This operation is not keyed."
    )]
    async fn create_hypothesis(
        &self,
        Parameters(input): Parameters<HypothesisInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke("hypothesis", vec![input.claim]).await
    }

    #[tool(
        description = "Record an analyst or agent supplied 0–1 rating with supporting and contradicting evidence IDs. This is not a calculated probability and is not keyed."
    )]
    async fn evaluate_hypothesis(
        &self,
        Parameters(input): Parameters<EvaluateInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "evaluate",
            vec![
                input.hypothesis_id,
                input.score.to_string(),
                comma_ids(&input.evidence_ids),
                comma_ids(&input.counterexample_ids),
            ],
        )
        .await
    }

    #[tool(
        description = "Annotate an externally known unsigned value on one observation for exact held-out field inference. This operation is not keyed."
    )]
    async fn annotate_value(
        &self,
        Parameters(input): Parameters<ValueInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke(
            "value",
            vec![input.observation_id, input.variable, input.value, input.set],
        )
        .await
    }

    #[tool(
        description = "Record a decision with evidence IDs in the append-only investigation. This operation is not keyed."
    )]
    async fn record_decision(
        &self,
        Parameters(input): Parameters<DecisionInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke("decide", vec![input.text, comma_ids(&input.evidence_ids)])
            .await
    }

    #[tool(
        description = "Record a retry-safe, timestamped action marker in a trial.",
        annotations(idempotent_hint = true)
    )]
    async fn mark_action(
        &self,
        Parameters(input): Parameters<MarkInput>,
    ) -> Result<CallToolResult, String> {
        let mut args = vec![input.trial_id, input.kind, input.detail, input.key];
        if let Some(timestamp_ns) = input.timestamp_ns {
            args.push(timestamp_ns.to_string());
        }
        self.invoke("mark-keyed", args).await
    }

    #[tool(
        description = "Run a bounded local capture command; replayably link a keyed action, capture, and capture-scope tags across all pages. The command executes as the server user.",
        annotations(idempotent_hint = true)
    )]
    async fn capture_step(
        &self,
        Parameters(input): Parameters<CaptureStepInput>,
    ) -> Result<CallToolResult, String> {
        if input.command.is_empty() {
            return Err("command must contain a program".into());
        }
        let mut args = vec![
            input.trial_id,
            input.kind,
            input.detail,
            input.phase,
            input.label,
            input.step_key,
            input.format,
            input.timeout_ms.to_string(),
            "--".into(),
        ];
        args.extend(input.command);
        let result = self.invoke_value("capture-step", args).await?;
        if result["status"] != "completed" {
            return Ok(CallToolResult::structured(result));
        }
        let ids = result["observation_ids"].as_array();
        let batches = result["tag_batches"]
            .as_array()
            .map(|items| items.iter().map(compact_batch).collect::<Vec<_>>())
            .unwrap_or_default();
        Ok(CallToolResult::structured(json!({
            "revision":result["revision"],
            "step_key":result["step_key"],
            "status":result["status"],
            "replayed":result["replayed"],
            "action":result["action"],
            "capture":result["capture"],
            "observation_count":ids.map_or(0, Vec::len),
            "first_observation_ids":ids.map(|items| items.iter().take(20).cloned().collect::<Vec<_>>()).unwrap_or_default(),
            "observation_ids_omitted":ids.map_or(0, |items| items.len().saturating_sub(20)),
            "tag_batches":batches,
        })))
    }

    #[tool(
        description = "Start a bounded local capture command in the background and return its durable key. The command executes as the server user.",
        annotations(idempotent_hint = true)
    )]
    async fn capture_start(
        &self,
        Parameters(input): Parameters<CaptureStartInput>,
    ) -> Result<CallToolResult, String> {
        if input.command.is_empty() {
            return Err("command must contain a program".into());
        }
        let mut args = vec![
            input.trial_id,
            input.format,
            input.key,
            input.timeout_ms.to_string(),
            "--".into(),
        ];
        args.extend(input.command);
        self.invoke("capture-start", args).await
    }

    #[tool(
        description = "Inspect the state of a keyed capture command.",
        annotations(read_only_hint = true)
    )]
    async fn capture_status(
        &self,
        Parameters(input): Parameters<KeyInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke("capture-status", vec![input.key]).await
    }

    #[tool(
        description = "Request that a running keyed capture command stop.",
        annotations(idempotent_hint = true)
    )]
    async fn capture_stop(
        &self,
        Parameters(input): Parameters<KeyInput>,
    ) -> Result<CallToolResult, String> {
        self.invoke("capture-stop", vec![input.key]).await
    }

    #[tool(
        description = "Retry-safe capture-scope tag page for an action and capture in the same trial; at most 1000 observations.",
        annotations(idempotent_hint = true)
    )]
    async fn tag_capture(
        &self,
        Parameters(input): Parameters<TagCaptureInput>,
    ) -> Result<CallToolResult, String> {
        let mut args = vec![
            input.action_id,
            input.capture_id,
            input.phase,
            input.label,
            input.key,
        ];
        match (input.offset, input.count) {
            (Some(offset), Some(count)) => {
                args.push(offset.to_string());
                args.push(count.to_string());
            }
            (None, None) => {}
            _ => return Err("offset and count must be supplied together".into()),
        }
        let result = self.invoke_value("tag-capture", args).await?;
        Ok(CallToolResult::structured(json!({
            "revision":result["revision"],
            "replayed":result["replayed"],
            "batch":compact_batch(&result["batch"]),
        })))
    }
}

#[tool_handler]
impl ServerHandler for InvestigationServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "protocol-informatics-v2",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Start with summary, then page trials and search observations. Read exact byte spans before making claims. Pairing, clustering, and record models are provisional. Check held-out captures before committing frames; use stable keys for mark, capture, and frame operations.",
            )
    }
}

pub fn serve(root: &Path) -> Result<(), String> {
    workflow::load(root)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        InvestigationServer {
            root: root.to_path_buf(),
        }
        .serve(stdio())
        .await
        .map_err(|error| error.to_string())?
        .waiting()
        .await
        .map_err(|error| error.to_string())?;
        Ok(())
    })
}
