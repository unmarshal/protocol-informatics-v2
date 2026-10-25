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
    assert_eq!(names.len(), 50);
    assert!(names.contains(&"frame_runs"));
    assert!(names.contains(&"cluster_frames"));
    assert!(names.contains(&"align_frame_cluster"));
    assert!(names.contains(&"record_frame_alignment"));
    assert!(names.contains(&"analyses"));
    assert!(names.contains(&"analysis_result"));
    assert!(names.contains(&"validate_frame_clusters"));
    assert!(names.contains(&"summary"));
    assert!(names.contains(&"capture_step"));
    assert!(names.contains(&"validate_exchanges"));
    assert!(names.contains(&"annotate_value"));
    assert!(names.contains(&"infer_value"));
    assert!(names.contains(&"record_decision"));
    assert!(names.contains(&"verify"));
    assert!(names.contains(&"commit_framing"));
    assert!(names.contains(&"commit_varint"));
    assert!(names.contains(&"commit_delimiter"));
    assert!(names.contains(&"frame_span"));
    assert!(names.contains(&"infer_frame_value"));
    assert!(names.contains(&"review_trials"));
    assert!(names.contains(&"experiments"));
    assert!(names.contains(&"hypotheses"));
    assert!(names.contains(&"decisions"));
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
    for (index, value) in [(0, "3"), (2, "258"), (4, "4097")] {
        client.tool(
            "annotate_value",
            json!({"observation_id":first["first_observation_ids"][index],"variable":"icmp-sequence","value":value,"set":"discovery"}),
        );
        client.tool(
            "annotate_value",
            json!({"observation_id":second["first_observation_ids"][index],"variable":"icmp-sequence","value":value,"set":"validation"}),
        );
    }
    let inferred = client.tool("infer_value", json!({"variable":"icmp-sequence"}));
    assert_eq!(inferred["discovery_count"], 3);
    assert_eq!(inferred["validation_count"], 3);
    assert!(
        inferred["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| {
                candidate["start"] == 6
                    && candidate["end"] == 8
                    && candidate["validation_matches"] == 3
            })
    );
    let hypothesis = client.tool(
        "create_hypothesis",
        json!({"claim":"ICMP sequence bytes are echoed in replies"}),
    );
    let hypothesis_id = hypothesis["event"]["hypothesis"]["id"].as_str().unwrap();
    let counterexample = held_out["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["offset"] == 7)
        .unwrap()["counterexamples"][0]["later_observation_id"]
        .as_str()
        .unwrap();
    client.tool(
        "evaluate_hypothesis",
        json!({"hypothesis_id":hypothesis_id,"score":0.4,"evidence_ids":[first["first_observation_ids"][0]],"counterexample_ids":[counterexample]}),
    );
    client.tool(
        "record_decision",
        json!({"text":"Collect a second mismatched reply trial","evidence_ids":[counterexample]}),
    );
    let revised = client.tool("summary", json!({}));
    assert_eq!(revised["counts"]["hypotheses"], 1);
    assert_eq!(revised["counts"]["decisions"], 1);
    assert_eq!(revised["counts"]["known_values"], 6);
    let experiments = client.tool("experiments", json!({"limit":1}));
    assert_eq!(experiments["total"], 1);
    assert_eq!(experiments["experiments"][0]["trial_count"], 2);
    let hypotheses = client.tool("hypotheses", json!({"limit":1}));
    assert_eq!(hypotheses["hypotheses"][0]["score"], 0.4);
    assert_eq!(hypotheses["hypotheses"][0]["counterexample_count"], 1);
    let decisions = client.tool("decisions", json!({"limit":1}));
    assert_eq!(decisions["decisions"][0]["evidence_count"], 1);
    let verified = client.tool("verify", json!({}));
    assert_eq!(verified["captures"], 2);
    assert_eq!(verified["observations"], 12);
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

#[test]
fn agent_can_infer_framing_and_tlv_from_binary_trials_over_mcp() {
    let root = workspace();
    let root_text = root.to_str().unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["init", root_text, "How are these records framed?"])
        .output()
        .unwrap();
    assert!(init.status.success());
    let mut client = McpClient::start(&root);
    client.request(
        "initialize",
        json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"pi-test","version":"1"}}),
    );
    client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let experiment = client.tool(
        "create_experiment",
        json!({"question":"Which length prefix survives changed records?","prediction":"One model holds on validation records."}),
    );
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = client.tool(
        "create_trial",
        json!({"experiment_id":experiment_id,"role":"discovery","changed_factor":"two record sets"}),
    );
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation = client.tool(
        "create_trial",
        json!({"experiment_id":experiment_id,"role":"validation","changed_factor":"two unseen record sets"}),
    );
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut record_observations = Vec::new();
    for (trial_id, key, filename) in [
        (discovery_id, "mcp-record-d1", "records_discovery_a.bin"),
        (discovery_id, "mcp-record-d2", "records_discovery_b.bin"),
        (validation_id, "mcp-record-v1", "records_validation_a.bin"),
        (validation_id, "mcp-record-v2", "records_validation_b.bin"),
    ] {
        let capture = client.tool(
            "capture_step",
            json!({"trial_id":trial_id,"kind":"fixture","detail":filename,"phase":"stimulus","label":"record sample","step_key":key,"format":"binary","timeout_ms":5000,"command":["/bin/cat",fixtures.join(filename).to_str().unwrap()]}),
        );
        assert_eq!(capture["status"], "completed");
        assert_eq!(capture["observation_count"], 1);
        record_observations.push(
            capture["first_observation_ids"][0]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let framing = client.tool(
        "infer_framing",
        json!({"discovery_trial_id":discovery_id,"validation_trial_id":validation_id}),
    );
    assert_eq!(framing["discovery_count"], 2);
    assert_eq!(framing["validation_count"], 2);
    assert_eq!(framing["candidate_count"], 1);
    assert_eq!(framing["candidates"][0]["validation_matches"], 2);
    let tlv = client.tool(
        "infer_tlv",
        json!({"discovery_trial_id":discovery_id,"validation_trial_id":validation_id}),
    );
    assert_eq!(tlv["candidate_count"], 1);
    assert_eq!(
        tlv["candidates"][0]["validation_elements_with_seen_types"],
        6
    );
    let framing_config = |observation_id: &str, key: &str| json!({"observation_id":observation_id,"start_offset":4,"prefix_offset":1,"prefix_width":2,"byte_order":"big","length_mode":"payload","alignment":2,"key":key});
    let mut proposed_input = framing_config(&record_observations[0], "ignored");
    proposed_input.as_object_mut().unwrap().remove("key");
    let proposed = client.tool("probe_framing", proposed_input);
    assert_eq!(proposed["status"], "complete");
    assert_eq!(proposed["record_count"], 3);
    let typed = client.tool(
        "probe_tlv",
        json!({"observation_id":record_observations[0],"start_offset":4,"type_width":1,"length_width":2,"byte_order":"big","length_mode":"payload","alignment":2}),
    );
    assert_eq!(typed["status"], "complete");
    let discovery_commit = client.tool(
        "commit_framing",
        framing_config(&record_observations[0], "mcp-frames-discovery"),
    );
    let replayed = client.tool(
        "commit_framing",
        framing_config(&record_observations[0], "mcp-frames-discovery"),
    );
    assert_eq!(replayed["replayed"], true);
    assert_eq!(replayed["run"]["id"], discovery_commit["run"]["id"]);
    let validation_commit = client.tool(
        "commit_framing",
        framing_config(&record_observations[3], "mcp-frames-validation"),
    );
    let frame_validation = client.tool("validate_frame_clusters", json!({"model":"fixed_width","discovery_trial_id":discovery_id,"validation_trial_id":validation_id,"respect_direction":false}));
    assert_eq!(frame_validation["validation_count"], 3);
    assert_eq!(frame_validation["frames"].as_array().unwrap().len(), 3);
    assert_eq!(
        frame_validation["discovery_run_keys"][0],
        "mcp-frames-discovery"
    );
    let run_page = client.tool(
        "frame_runs",
        json!({"trial_id":discovery_id,"model":"fixed_width"}),
    );
    assert_eq!(run_page["total"], 1);
    assert_eq!(run_page["frame_runs"][0]["key"], "mcp-frames-discovery");
    assert_eq!(run_page["frame_runs"][0]["record_count"], 3);
    let frame_groups = client.tool(
        "cluster_frames",
        json!({"model":"fixed_width","trial_id":discovery_id,"respect_direction":false}),
    );
    assert_eq!(frame_groups["selected_frame_count"], 3);
    assert_eq!(frame_groups["clusters"][0]["member_count"], 3);
    let aligned_frames = client.tool(
        "align_frame_cluster",
        json!({"model":"fixed_width","cluster_id":frame_groups["clusters"][0]["id"],"trial_id":discovery_id,"respect_direction":false}),
    );
    assert_eq!(aligned_frames["aligned_frame_count"], 3);
    assert_eq!(aligned_frames["analysis"]["sample_count"], 3);
    let recorded_frames = client.tool(
        "record_frame_alignment",
        json!({"model":"fixed_width","cluster_id":frame_groups["clusters"][0]["id"],"trial_id":discovery_id,"respect_direction":false}),
    );
    assert_eq!(
        recorded_frames["event"]["analysis"]["scope"]["kind"],
        "frame_cluster"
    );
    let saved_analysis_id = recorded_frames["event"]["analysis"]["id"].as_str().unwrap();
    let saved_analyses = client.tool("analyses", json!({"limit":1}));
    assert_eq!(saved_analyses["analyses"][0]["id"], saved_analysis_id);
    let saved_rows = client.tool(
        "analysis_result",
        json!({"analysis_id":saved_analysis_id,"column_limit":2,"row_limit":1}),
    );
    assert_eq!(saved_rows["kind"], "frame");
    assert_eq!(saved_rows["rows"].as_array().unwrap().len(), 1);
    assert_eq!(saved_rows["columns"].as_array().unwrap().len(), 2);
    let status = client.tool("frame_run_status", json!({"key":"mcp-frames-discovery"}));
    assert_eq!(status["model"], "fixed_width");
    let page = client.tool("frames", json!({"key":"mcp-frames-discovery","limit":1}));
    assert_eq!(page["total"], 3);
    assert_eq!(page["frames"].as_array().unwrap().len(), 1);
    assert_eq!(page["next_offset"], 1);
    let first_frame = page["frames"][0]["id"].as_str().unwrap();
    let span = client.tool(
        "frame_span",
        json!({"frame_id":first_frame,"start":0,"end":4}),
    );
    assert_eq!(span["coordinate_system"], "frame_bytes");
    assert_eq!(span["bytes_hex"], "a0000130");
    for (set, run) in [
        ("discovery", &discovery_commit),
        ("validation", &validation_commit),
    ] {
        for (index, value) in [160, 161, 162].into_iter().enumerate() {
            client.tool(
                "annotate_frame_value",
                json!({"frame_id":run["run"]["records"][index]["id"],"variable":"mcp_record_type","value":value.to_string(),"set":set}),
            );
        }
    }
    let frame_field = client.tool("infer_frame_value", json!({"variable":"mcp_record_type"}));
    assert_eq!(frame_field["candidate_count"], 1);
    assert_eq!(frame_field["candidates"][0]["start"], 0);
    assert_eq!(frame_field["candidates"][0]["validation_matches"], 3);
    let delimiter_experiment = client.tool(
        "create_experiment",
        json!({"question":"Which delimiter survives changed line endings?","prediction":"LF validates both held-out files."}),
    );
    let delimiter_experiment_id = delimiter_experiment["event"]["experiment"]["id"]
        .as_str()
        .unwrap();
    let delimiter_discovery = client.tool(
        "create_trial",
        json!({"experiment_id":delimiter_experiment_id,"role":"discovery","changed_factor":"CRLF records"}),
    );
    let delimiter_discovery_id = delimiter_discovery["event"]["trial"]["id"]
        .as_str()
        .unwrap();
    let delimiter_validation = client.tool(
        "create_trial",
        json!({"experiment_id":delimiter_experiment_id,"role":"validation","changed_factor":"CRLF and LF records"}),
    );
    let delimiter_validation_id = delimiter_validation["event"]["trial"]["id"]
        .as_str()
        .unwrap();
    let mut first_delimiter_observation = String::new();
    let mut validation_delimiter_observation = String::new();
    for (trial_id, key, filename) in [
        (
            delimiter_discovery_id,
            "mcp-delimiter-d1",
            "delimiter_discovery_a.bin",
        ),
        (
            delimiter_discovery_id,
            "mcp-delimiter-d2",
            "delimiter_discovery_b.bin",
        ),
        (
            delimiter_validation_id,
            "mcp-delimiter-v1",
            "delimiter_validation_a.bin",
        ),
        (
            delimiter_validation_id,
            "mcp-delimiter-v2",
            "delimiter_validation_b.bin",
        ),
    ] {
        let capture = client.tool(
            "capture_step",
            json!({"trial_id":trial_id,"kind":"fixture","detail":filename,"phase":"stimulus","label":"delimiter sample","step_key":key,"format":"binary","timeout_ms":5000,"command":["/bin/cat",fixtures.join(filename).to_str().unwrap()]}),
        );
        if first_delimiter_observation.is_empty() {
            first_delimiter_observation = capture["first_observation_ids"][0]
                .as_str()
                .unwrap()
                .to_owned();
        }
        if filename == "delimiter_validation_a.bin" {
            validation_delimiter_observation = capture["first_observation_ids"][0]
                .as_str()
                .unwrap()
                .to_owned();
        }
    }
    let delimiter_probe = client.tool(
        "probe_delimiter",
        json!({"observation_id":first_delimiter_observation,"start_offset":0,"delimiter_hex":"0d0a"}),
    );
    assert_eq!(delimiter_probe["status"], "complete");
    assert_eq!(delimiter_probe["record_count"], 3);
    let delimiter_result = client.tool(
        "infer_delimiter",
        json!({"discovery_trial_id":delimiter_discovery_id,"validation_trial_id":delimiter_validation_id}),
    );
    let review = client.tool(
        "review_trials",
        json!({"discovery_trial_id":delimiter_discovery_id,"validation_trial_id":delimiter_validation_id}),
    );
    assert_eq!(review["validation_observation_count"], 2);
    assert_eq!(review["methods"].as_array().unwrap().len(), 4);
    assert_eq!(review["prediction_assessed"], false);
    assert!(
        delimiter_result["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| {
                candidate["config"]["start_offset"] == 0
                    && candidate["config"]["delimiter_hex"] == "0a"
                    && candidate["validation_matches"] == 2
            })
    );
    let delimiter_commit_config = |observation_id: &str, key: &str| json!({"observation_id":observation_id,"start_offset":0,"delimiter_hex":"0d0a","key":key});
    let delimiter_discovery_run = client.tool(
        "commit_delimiter",
        delimiter_commit_config(&first_delimiter_observation, "mcp-delimiter-discovery"),
    );
    assert_eq!(
        delimiter_discovery_run["run"]["records"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        client.tool(
            "commit_delimiter",
            delimiter_commit_config(&first_delimiter_observation, "mcp-delimiter-discovery")
        )["replayed"],
        true
    );
    let delimiter_validation_run = client.tool(
        "commit_delimiter",
        delimiter_commit_config(
            &validation_delimiter_observation,
            "mcp-delimiter-validation",
        ),
    );
    let delimiter_runs = client.tool(
        "frame_runs",
        json!({"trial_id":delimiter_discovery_id,"model":"delimiter"}),
    );
    assert_eq!(delimiter_runs["total"], 1);
    assert_eq!(
        delimiter_runs["frame_runs"][0]["key"],
        "mcp-delimiter-discovery"
    );
    assert_eq!(
        client.tool("frame_run_status", json!({"key":"mcp-delimiter-discovery"}))["model"],
        "delimiter"
    );
    let delimiter_frames =
        client.tool("frames", json!({"key":"mcp-delimiter-discovery","limit":1}));
    assert_eq!(delimiter_frames["model"], "delimiter");
    let delimiter_span = client.tool(
        "frame_span",
        json!({"frame_id":delimiter_frames["frames"][0]["id"],"start":0,"end":3}),
    );
    assert_eq!(delimiter_span["bytes_hex"], "410d0a");
    for (set, run, values) in [
        ("discovery", &delimiter_discovery_run, [65, 66, 70]),
        ("validation", &delimiter_validation_run, [67, 68, 73]),
    ] {
        for (index, value) in values.into_iter().enumerate() {
            client.tool(
                "annotate_frame_value",
                json!({"frame_id":run["run"]["records"][index]["id"],"variable":"mcp_delimiter_first_byte","value":value.to_string(),"set":set}),
            );
        }
    }
    let delimiter_field = client.tool(
        "infer_frame_value",
        json!({"variable":"mcp_delimiter_first_byte"}),
    );
    assert_eq!(delimiter_field["candidate_count"], 1);
    assert_eq!(delimiter_field["candidates"][0]["validation_matches"], 3);
    assert!(
        delimiter_result["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| {
                candidate["config"]["start_offset"] == 0
                    && candidate["config"]["delimiter_hex"] == "0d0a"
                    && candidate["validation_matches"] == 1
            })
    );
    let varint_experiment = client.tool(
        "create_experiment",
        json!({"question":"Where do variable-width records end?","prediction":"The unsigned LEB128 layout consumes the sample."}),
    );
    let varint_trial = client.tool(
        "create_trial",
        json!({"experiment_id":varint_experiment["event"]["experiment"]["id"],"role":"discovery","changed_factor":"prefix width"}),
    );
    let varint_capture = client.tool(
        "capture_step",
        json!({"trial_id":varint_trial["event"]["trial"]["id"],"kind":"fixture","detail":"varint_discovery_a.bin","phase":"stimulus","label":"varint sample","step_key":"mcp-varint-d1","format":"binary","timeout_ms":5000,"command":["/bin/cat",fixtures.join("varint_discovery_a.bin").to_str().unwrap()]}),
    );
    let varint_observation = varint_capture["first_observation_ids"][0].as_str().unwrap();
    let varint_config = json!({"observation_id":varint_observation,"start_offset":4,"field_offset":1,"length_mode":"payload","alignment":2,"key":"mcp-varint-frames"});
    let mut varint_probe_input = varint_config.clone();
    varint_probe_input.as_object_mut().unwrap().remove("key");
    let varint_probe = client.tool("probe_varint", varint_probe_input);
    assert_eq!(varint_probe["status"], "complete");
    assert_eq!(varint_probe["record_count"], 3);
    let varint_committed = client.tool("commit_varint", varint_config.clone());
    assert_eq!(
        varint_committed["run"]["records"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        client.tool("commit_varint", varint_config)["replayed"],
        true
    );
    let varint_status = client.tool("frame_run_status", json!({"key":"mcp-varint-frames"}));
    assert_eq!(varint_status["model"], "unsigned_leb128");
    let varint_runs = client.tool("frame_runs", json!({"model":"unsigned_leb128","limit":1}));
    assert_eq!(varint_runs["total"], 1);
    assert_eq!(varint_runs["frame_runs"][0]["key"], "mcp-varint-frames");
    let varint_page = client.tool("frames", json!({"key":"mcp-varint-frames","limit":1}));
    assert_eq!(varint_page["total"], 3);
    let verification = client.tool("verify", json!({}));
    assert_eq!(verification["captures"], 9);
    client.stop();
    fs::remove_dir_all(root).unwrap();
}
