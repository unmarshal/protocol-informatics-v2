use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn workspace() -> PathBuf {
    for attempt in 0..1000 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pi-v2-mcp-test-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        if fs::create_dir(&root).is_ok() {
            return root;
        }
    }
    panic!("could not create isolated test workspace")
}

struct McpClient {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<Value>,
    next_id: u64,
}

impl McpClient {
    fn start(root: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
            .args(["mcp-stdio", root.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if let Ok(response) = serde_json::from_str(&line)
                    && sender.send(response).is_err()
                {
                    break;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            responses,
            next_id: 1,
        }
    }

    fn send(&mut self, value: Value) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let response = self
            .responses
            .recv_timeout(Duration::from_secs(20))
            .expect("MCP server did not respond");
        assert_eq!(response["id"], id);
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.request("tools/call", json!({"name":name,"arguments":arguments}));
        assert_eq!(result["isError"], false, "{result}");
        result["structuredContent"].clone()
    }

    fn stop(mut self) {
        self.input.take();
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.child.kill().unwrap();
        panic!("MCP server did not exit after stdin closed");
    }
}

#[test]
fn agent_can_capture_tag_and_inspect_held_out_evidence_over_mcp() {
    let root = workspace();
    let root_text = root.to_str().unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["init", root_text, "Are ICMP sequence bytes echoed?"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let mut client = McpClient::start(&root);
    let initialization = client.request(
        "initialize",
        json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"pi-test","version":"1"}}),
    );
    assert_eq!(
        initialization["serverInfo"]["name"],
        "protocol-informatics-v2"
    );
    client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let tools = client.request("tools/list", json!({}));
    let names: Vec<_> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"summary"));
    assert!(names.contains(&"capture_step"));
    assert!(names.contains(&"validate_exchanges"));
    let definitions = tools["tools"].as_array().unwrap();
    let search_tool = definitions
        .iter()
        .find(|tool| tool["name"] == "search_observations")
        .unwrap();
    assert_eq!(search_tool["annotations"]["readOnlyHint"], true);
    assert!(search_tool["inputSchema"]["properties"]["capture_id"].is_object());
    let capture_tool = definitions
        .iter()
        .find(|tool| tool["name"] == "capture_step")
        .unwrap();
    assert_eq!(capture_tool["annotations"]["idempotentHint"], true);

    let experiment = client.tool(
        "create_experiment",
        json!({"question":"Does an echo reply preserve sequence bytes?","prediction":"The bytes match in independent captures."}),
    );
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = client.tool(
        "create_trial",
        json!({"experiment_id":experiment_id,"role":"discovery","changed_factor":"three varied sequences"}),
    );
    let discovery_trial_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation = client.tool(
        "create_trial",
        json!({"experiment_id":experiment_id,"role":"validation","changed_factor":"one mismatched reply sequence"}),
    );
    let validation_trial_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let capture = |trial_id: &str, step_key: &str, filename: &str| {
        json!({
            "trial_id":trial_id,"kind":"fixture","detail":filename,
            "phase":"stimulus","label":"ICMP experiment","step_key":step_key,
            "format":"pcap-icmp","timeout_ms":5000,
            "command":["/bin/cat",fixtures.join(filename).to_str().unwrap()]
        })
    };
    let first = client.tool(
        "capture_step",
        capture(discovery_trial_id, "mcp-discovery", "icmp_holdout.pcap"),
    );
    assert_eq!(first["status"], "completed");
    assert_eq!(first["observation_count"], 6);
    assert_eq!(first["first_observation_ids"].as_array().unwrap().len(), 6);
    assert_eq!(first["tag_batches"][0]["observation_count"], 6);
    let first_replay = client.tool(
        "capture_step",
        capture(discovery_trial_id, "mcp-discovery", "icmp_holdout.pcap"),
    );
    assert_eq!(first_replay["replayed"], true);
    let second = client.tool(
        "capture_step",
        capture(
            validation_trial_id,
            "mcp-validation",
            "icmp_mismatched_reply.pcap",
        ),
    );
    let first_id = first["capture"]["id"].as_str().unwrap();
    let second_id = second["capture"]["id"].as_str().unwrap();
    let summary = client.tool("summary", json!({}));
    assert_eq!(summary["counts"]["captures"], 2);
    assert_eq!(summary["counts"]["observations"], 12);
    assert_eq!(summary["counts"]["tagged_observations"], 12);
    let search = client.tool(
        "search_observations",
        json!({"capture_id":first_id,"tag_label":"ICMP experiment","limit":2}),
    );
    assert_eq!(search["total"], 6);
    assert_eq!(search["observations"].as_array().unwrap().len(), 2);
    assert_eq!(search["next_offset"], 2);
    let span = client.tool(
        "span",
        json!({"observation_id":first["first_observation_ids"][0],"start":6,"end":8}),
    );
    assert_eq!(span["bytes_hex"], "0003");
    assert!(span["source_file_offset"].as_u64().is_some());
    let held_out = client.tool(
        "validate_exchanges",
        json!({"discovery_capture_id":first_id,"validation_capture_id":second_id}),
    );
    assert_eq!(held_out["discovery_pair_count"], 3);
    assert_eq!(held_out["validation_pair_count"], 3);
    assert_eq!(held_out["contradicted_offset_count"], 2);
    assert!(held_out["checks"].as_array().unwrap().iter().any(|check| {
        check["offset"] == 7 && check["counterexamples"][0]["reason"] == "bytes_differ"
    }));
    let stress = client.tool(
        "create_trial",
        json!({"experiment_id":experiment_id,"role":"stress","changed_factor":"512 sequence values"}),
    );
    let stress_trial_id = stress["event"]["trial"]["id"].as_str().unwrap();
    let large = client.tool(
        "capture_step",
        capture(stress_trial_id, "mcp-stress", "icmp_sweep_512.pcap"),
    );
    assert_eq!(large["observation_count"], 1024);
    assert_eq!(large["first_observation_ids"].as_array().unwrap().len(), 20);
    assert_eq!(large["observation_ids_omitted"], 1004);
    assert_eq!(large["tag_batches"].as_array().unwrap().len(), 2);
    assert_eq!(large["tag_batches"][0]["observation_count"], 1000);
    let large_search = client.tool(
        "search_observations",
        json!({"capture_id":large["capture"]["id"],"limit":1}),
    );
    assert_eq!(large_search["total"], 1024);
    let failed = client.request(
        "tools/call",
        json!({"name":"pair_exchanges","arguments":{"capture_id":"missing"}}),
    );
    assert_eq!(failed["isError"], true);
    client.stop();
    fs::remove_dir_all(root).unwrap();
}
