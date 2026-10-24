//! Stdio MCP adapter. Investigation state and CLI semantics remain authoritative.

use std::path::{Path, PathBuf};

use protocol_informatics_v2::{clustering, exchanges, query, workflow};
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
                "Start with summary, then page trials and search observations. Read exact byte spans before making claims. Pairing and clustering are provisional. Use stable keys for mark and capture operations.",
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
