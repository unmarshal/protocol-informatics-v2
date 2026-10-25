use protocol_informatics_v2::workflow::{self, CaptureRun, CaptureRunStatus, Event};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn workspace() -> PathBuf {
    for attempt in 0..1000 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pi-v2-test-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        if fs::create_dir(&root).is_ok() {
            return root;
        }
    }
    panic!("could not create isolated test workspace")
}

fn cli(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn committed_frames_cluster_by_correlated_record_evidence() {
    let root = workspace();
    let root_text = path(&root);
    let mut bytes = Vec::new();
    for record in [
        "01a0b0c01001",
        "01a1b1c11002",
        "01a2b2c21003",
        "02d0e0f02004",
        "02d1e1f12005",
        "02d2e2f22006",
    ] {
        bytes.extend(workflow::from_hex(record).unwrap());
        bytes.push(b'\n');
    }
    let sample = root.join("records.bin");
    fs::write(&sample, bytes).unwrap();
    cli(&["init", root_text, "Which recurring record types appear?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Do record types correlate with later bytes?",
        "-",
        "Two groups have distinct payload structure",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "six records",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let imported = cli(&["import", root_text, trial_id, "binary", path(&sample)]);
    let observation_id = imported["event"]["observations"][0]["id"].as_str().unwrap();
    cli(&[
        "commit-delimiter",
        root_text,
        observation_id,
        "0",
        "0a",
        "six-records",
    ]);
    let groups = cli(&["cluster-frames", root_text, "delimiter", trial_id, "ignore"]);
    assert_eq!(groups["selected_frame_count"], 6);
    assert_eq!(groups["clusters"].as_array().unwrap().len(), 2);
    for cluster in groups["clusters"].as_array().unwrap() {
        assert_eq!(cluster["member_count"], 3);
        assert_eq!(cluster["split_rules"][0]["kind"], "byte");
        assert_eq!(cluster["split_rules"][0]["offset"], 0);
        assert!(
            cluster["split_rules"][0]["evidence_offsets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|offset| offset == 4)
        );
    }
    let first_cluster_id = groups["clusters"][0]["id"].as_str().unwrap();
    let alignment = cli(&[
        "align-frame-cluster",
        root_text,
        "delimiter",
        first_cluster_id,
        trial_id,
        "ignore",
    ]);
    assert_eq!(alignment["cluster_id"], first_cluster_id);
    assert_eq!(alignment["selected_frame_count"], 3);
    assert_eq!(alignment["aligned_frame_count"], 3);
    assert_eq!(alignment["analysis"]["sample_count"], 3);
    assert_eq!(alignment["analysis"]["aligned_width"], 6);
    assert_eq!(alignment["frame_ids"].as_array().unwrap().len(), 3);
    assert!(
        alignment["frame_ids"]
            .as_array()
            .unwrap()
            .contains(&alignment["reference_frame_id"])
    );
    let event_log = root.join(".pi/events.jsonl");
    let prior_log = fs::read_to_string(&event_log).unwrap();
    let legacy_log = prior_log.replace("\"schema_version\":14", "\"schema_version\":13");
    assert_ne!(legacy_log, prior_log);
    fs::write(&event_log, legacy_log).unwrap();
    let recorded = cli(&[
        "record-frame-alignment",
        root_text,
        "delimiter",
        first_cluster_id,
        trial_id,
        "ignore",
    ]);
    let saved = &recorded["event"]["analysis"];
    let analysis_id = saved["id"].as_str().unwrap();
    assert_eq!(recorded["schema_version"], 14);
    assert_eq!(saved["scope"]["kind"], "frame_cluster");
    assert_eq!(saved["frame_ids"], alignment["frame_ids"]);
    assert_eq!(saved["scope"]["source_revision"], alignment["revision"]);
    assert_eq!(
        cli(&["analyses", root_text, "0", "1"])["analyses"][0]["id"],
        analysis_id
    );
    let saved_page = cli(&[
        "analysis-result",
        root_text,
        analysis_id,
        "0",
        "2",
        "0",
        "2",
    ]);
    assert_eq!(saved_page["kind"], "frame");
    assert_eq!(saved_page["total_columns"], 6);
    assert_eq!(saved_page["next_column_offset"], 2);
    assert_eq!(saved_page["total_rows"], 3);
    assert_eq!(saved_page["next_row_offset"], 2);
    assert_eq!(
        saved_page["rows"][0]["entity_id"],
        alignment["frame_ids"][0]
    );
    assert_eq!(
        saved_page["rows"][0]["aligned_bytes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let verified_analysis = cli(&["verify", root_text]);
    assert_eq!(verified_analysis["analyses"], 1);
    assert_eq!(verified_analysis["frame_analyses"], 1);
    let mut validation_bytes = Vec::new();
    for record in ["01a0b0c01001", "02d0e0f02004", "03e0f0a03007"] {
        validation_bytes.extend(workflow::from_hex(record).unwrap());
        validation_bytes.push(b'\n');
    }
    let validation_sample = root.join("validation-records.bin");
    fs::write(&validation_sample, validation_bytes).unwrap();
    let validation_trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "two known types and one unseen type",
    ]);
    let validation_trial_id = validation_trial["event"]["trial"]["id"].as_str().unwrap();
    let validation_import = cli(&[
        "import",
        root_text,
        validation_trial_id,
        "binary",
        path(&validation_sample),
    ]);
    let validation_observation_id = validation_import["event"]["observations"][0]["id"]
        .as_str()
        .unwrap();
    cli(&[
        "commit-delimiter",
        root_text,
        validation_observation_id,
        "0",
        "0a",
        "validation-records",
    ]);
    let validation = cli(&[
        "validate-frame-clusters",
        root_text,
        "delimiter",
        trial_id,
        validation_trial_id,
        "ignore",
    ]);
    assert_eq!(validation["discovery_count"], 6);
    assert_eq!(validation["validation_count"], 3);
    assert_eq!(validation["assigned_count"], 2);
    assert_eq!(validation["unassigned_count"], 1);
    assert_eq!(validation["frames"][2]["status"], "unassigned");
    assert_eq!(
        validation["frames"][2]["rejections"][0]["stable_byte_mismatch_offsets"][0],
        0
    );
    let report = root.join("record-groups.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Held-out record grouping"));
    assert!(html.contains("\"frame_cluster_validations\":[{"));
    assert!(html.contains("Frame alignment"));
    assert!(html.contains("\"frame_alignment_previews\":[{"));
    let saved_artifact = root.join(saved["artifact"].as_str().unwrap());
    fs::write(saved_artifact, b"{}").unwrap();
    for command in [
        vec!["verify", root_text],
        vec!["analysis-result", root_text, analysis_id],
    ] {
        let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
            .args(command)
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("mismatch"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn frame_alignment_discloses_sampling_and_retains_extremes() {
    let root = workspace();
    let root_text = path(&root);
    let mut bytes = Vec::new();
    for value in 0..40u8 {
        bytes.extend([1, value, 0, 0, 16, value, 0xff]);
    }
    let sample = root.join("many-records.bin");
    fs::write(&sample, bytes).unwrap();
    cli(&["init", root_text, "Which columns vary in these records?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Align records",
        "-",
        "Find variable columns",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "discovery", "40 records"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let imported = cli(&["import", root_text, trial_id, "binary", path(&sample)]);
    let observation_id = imported["event"]["observations"][0]["id"].as_str().unwrap();
    cli(&[
        "commit-delimiter",
        root_text,
        observation_id,
        "0",
        "ff",
        "many-records",
    ]);
    let groups = cli(&["cluster-frames", root_text, "delimiter", trial_id, "ignore"]);
    assert_eq!(groups["clusters"].as_array().unwrap().len(), 1);
    let cluster = &groups["clusters"][0];
    let aligned = cli(&[
        "align-frame-cluster",
        root_text,
        "delimiter",
        cluster["id"].as_str().unwrap(),
        trial_id,
        "ignore",
    ]);
    assert_eq!(aligned["selected_frame_count"], 40);
    assert_eq!(aligned["aligned_frame_count"], 32);
    assert_eq!(aligned["omitted_frame_count"], 8);
    assert_eq!(
        aligned["sampling_method"],
        "representative_outliers_then_hash_v1"
    );
    let ids = aligned["frame_ids"].as_array().unwrap();
    assert!(ids.contains(&cluster["representative_frame_id"]));
    assert!(ids.contains(&cluster["farthest_members"][0]["frame_id"]));
    assert_eq!(aligned["analysis"]["sample_count"], 32);
    fs::remove_dir_all(root).unwrap();
}

fn wait_for_capture(root: &str, key: &str, deadline: Duration) -> Value {
    let started = Instant::now();
    loop {
        let status = cli(&["capture-status", root, key]);
        if status["status"] == "completed" || status["status"] == "failed" {
            return status;
        }
        assert!(
            started.elapsed() < deadline,
            "capture {key} did not finish: {status}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn agent_can_repeat_a_capture_tag_analyze_decide_cycle() {
    let root = workspace();
    let root_text = path(&root);
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcap");
    let fixture_text = path(&fixture);

    assert_eq!(
        cli(&["init", root_text, "Which bytes carry the ICMP sequence?"])["revision"],
        1
    );
    let hypothesis = cli(&[
        "hypothesis",
        root_text,
        "Bytes 6-7 are a big-endian sequence",
    ]);
    assert_eq!(hypothesis["event"]["hypothesis"]["id"], "hyp-000002");
    cli(&[
        "experiment",
        root_text,
        "Cross the low-byte boundary",
        "hyp-000002",
        "High byte changes at 256",
    ]);
    cli(&[
        "trial",
        root_text,
        "exp-000003",
        "baseline",
        "sequence range",
    ]);
    cli(&[
        "mark",
        root_text,
        "trial-000004",
        "stimulus",
        "Generate echo requests",
    ]);
    let capture = cli(&[
        "import",
        root_text,
        "trial-000004",
        "pcap-icmp",
        fixture_text,
    ]);
    assert_eq!(capture["event"]["capture"]["observation_count"], 24);
    assert_eq!(capture["event"]["observations"][0]["source_offset"], 74);
    cli(&[
        "tag",
        root_text,
        "obs-000006-0008",
        "stimulus",
        "sequence 255",
    ]);
    cli(&[
        "tag",
        root_text,
        "obs-000006-0010",
        "stimulus",
        "sequence 256",
    ]);
    let raw_analysis = cli(&["analyze-investigation", root_text, "trial-000004"]);
    let raw_analysis_id = raw_analysis["event"]["analysis"]["id"].as_str().unwrap();
    let raw_page = cli(&[
        "analysis-result",
        root_text,
        raw_analysis_id,
        "0",
        "4",
        "0",
        "1",
    ]);
    assert_eq!(raw_page["kind"], "observation");
    assert_eq!(raw_page["coordinate_system"], "observation_bytes");
    assert_eq!(
        raw_page["rows"][0]["aligned_bytes"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    cli(&[
        "evaluate",
        root_text,
        "hyp-000002",
        "0.9",
        "obs-000006-0008,obs-000006-0010",
        "-",
    ]);
    cli(&[
        "decide",
        root_text,
        "Repeat with another payload",
        "obs-000006-0010",
    ]);

    // A second capture is appended to the same investigation, then queried by revision.
    let second = cli(&[
        "capture-command",
        root_text,
        "trial-000004",
        "pcap-icmp",
        "repeat-icmp",
        "5000",
        "--",
        "cat",
        fixture_text,
    ]);
    assert_eq!(second["status"], "completed");
    assert_eq!(second["capture"]["observation_count"], 24);
    let replay = cli(&[
        "capture-command",
        root_text,
        "trial-000004",
        "pcap-icmp",
        "repeat-icmp",
        "5000",
        "--",
        "cat",
        fixture_text,
    ]);
    assert_eq!(replay["capture"]["id"], second["capture"]["id"]);
    assert_eq!(replay["revision"], second["revision"]);
    assert_eq!(
        cli(&["capture-status", root_text, "repeat-icmp"])["status"],
        "completed"
    );
    let mismatched_replay = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "capture-command",
            root_text,
            "trial-000004",
            "pcap-icmp",
            "repeat-icmp",
            "5000",
            "--",
            "cat",
            "examples/toy_messages.hex",
        ])
        .output()
        .unwrap();
    assert!(!mismatched_replay.status.success());
    let summary = cli(&["resume", root_text]);
    assert_eq!(summary["revision"], 13);
    assert_eq!(summary["capture_runs"][0]["status"], "completed");
    assert_eq!(summary["observation_count"], 48);
    assert_eq!(summary["hypotheses"][0]["score"], 0.9);
    let corpus = cli(&["summary", root_text]);
    assert_eq!(corpus["schema_version"], 14);
    assert_eq!(corpus["revision"], 13);
    assert_eq!(corpus["counts"]["captures"], 2);
    assert_eq!(corpus["counts"]["observations"], 48);
    assert_eq!(corpus["counts"]["tagged_observations"], 2);
    assert_eq!(corpus["counts"]["completed_capture_runs"], 1);
    assert_eq!(corpus["formats"][0]["format"], "pcap-icmp");
    assert_eq!(corpus["formats"][0]["observations"], 48);
    assert_eq!(corpus["top_directions"].as_array().unwrap().len(), 2);
    assert_eq!(corpus["recent_trials"][0]["observations"], 48);
    assert!(corpus["timestamp_range_ns"].is_array());
    let trials = cli(&["trials", root_text, "0", "1"]);
    assert_eq!(trials["total"], 1);
    assert_eq!(trials["order"], "newest_first");
    assert_eq!(trials["trials"][0]["id"], "trial-000004");
    let experiments = cli(&["experiments", root_text, "0", "1"]);
    assert_eq!(experiments["total"], 1);
    assert_eq!(experiments["experiments"][0]["id"], "exp-000003");
    assert_eq!(experiments["experiments"][0]["capture_count"], 2);
    let hypotheses = cli(&["hypotheses", root_text, "0", "1"]);
    assert_eq!(hypotheses["hypotheses"][0]["score"], 0.9);
    assert_eq!(hypotheses["hypotheses"][0]["evidence_count"], 2);
    let decisions = cli(&["decisions", root_text, "0", "1"]);
    assert_eq!(decisions["decisions"][0]["evidence_count"], 1);
    assert!(decisions["next_offset"].is_null());
    let page = cli(&["observations", root_text, "trial-000004", "8", "2"]);
    assert_eq!(page["total"], 48);
    assert_eq!(page["observations"].as_array().unwrap().len(), 2);
    assert_eq!(page["observations"][0]["id"], "obs-000006-0008");
    assert_eq!(page["observations"][0]["tags"][0]["label"], "sequence 255");
    assert_eq!(page["next_offset"], 10);
    let direction = corpus["top_directions"][0]["direction"].as_str().unwrap();
    let direction_query =
        serde_json::json!({"trial_id":"trial-000004","direction":direction,"offset":2,"limit":3})
            .to_string();
    let matches = cli(&["search-observations", root_text, &direction_query]);
    assert_eq!(matches["schema_version"], 14);
    assert_eq!(matches["total"], 24);
    assert_eq!(matches["observations"].as_array().unwrap().len(), 3);
    assert_eq!(matches["next_offset"], 5);
    assert!(
        matches["observations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|observation| observation["direction"] == direction)
    );
    let tag_query =
        serde_json::json!({"tag_phase":"stimulus","tag_label":"sequence 256"}).to_string();
    let tagged = cli(&["search-observations", root_text, &tag_query]);
    assert_eq!(tagged["total"], 1);
    assert_eq!(tagged["observations"][0]["id"], "obs-000006-0010");
    let first_timestamp = capture["event"]["observations"][0]["timestamp_ns"]
        .as_u64()
        .unwrap();
    let time_query = serde_json::json!({"capture_id":capture["event"]["capture"]["id"],
        "timestamp_start_ns":first_timestamp.to_string(),"timestamp_end_ns":(first_timestamp+1).to_string()}).to_string();
    let time_matches = cli(&["search-observations", root_text, &time_query]);
    assert_eq!(time_matches["total"], 1);
    assert_eq!(time_matches["observations"][0]["id"], "obs-000006-0000");
    let invalid_filter = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "search-observations",
            root_text,
            "{\"trial\":\"trial-000004\"}",
        ])
        .output()
        .unwrap();
    assert!(!invalid_filter.status.success());
    assert!(String::from_utf8_lossy(&invalid_filter.stderr).contains("unknown field"));
    let invalid_range =
        serde_json::json!({"timestamp_start_ns":"5","timestamp_end_ns":"5"}).to_string();
    let rejected_range = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["search-observations", root_text, &invalid_range])
        .output()
        .unwrap();
    assert!(!rejected_range.status.success());
    assert!(String::from_utf8_lossy(&rejected_range.stderr).contains("half-open"));
    let exact_length = serde_json::json!({"min_bytes":14,"max_bytes":14}).to_string();
    let length_matches = cli(&["search-observations", root_text, &exact_length]);
    assert!(length_matches["total"].as_u64().unwrap() > 0);
    assert!(
        length_matches["observations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|observation| observation["length"] == 14)
    );
    let span = cli(&["span", root_text, "obs-000006-0010", "6", "8"]);
    assert_eq!(span["bytes_hex"], "0100");
    assert_eq!(span["source_file_offset"], 680);
    assert_eq!(span["coordinate_system"], "message_bytes");
    let diff = cli(&["diff", root_text, "obs-000006-0008", "obs-000006-0010"]);
    assert!(
        diff["changed_ranges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|range| range["start"] == 6 && range["end"] == 8)
    );
    let changes = cli(&["changes", root_text, "11"]);
    assert_eq!(changes.as_array().unwrap().len(), 2);
    assert_eq!(changes[0]["event"]["type"], "capture_run_reserved");
    assert_eq!(changes[1]["event"]["type"], "capture_imported");
    let verification = cli(&["verify", root_text]);
    assert_eq!(verification["captures"], 2);
    assert_eq!(verification["observations"], 48);
    assert_eq!(verification["artifacts_verified"], 3);

    let report = root.join("report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Which bytes carry the ICMP sequence?"));
    assert!(html.contains("obs-000006-0010"));
    assert!(html.contains("Capture command runs"));
    assert!(html.contains("Corpus overview"));
    assert!(html.contains("corpus_summary"));
    assert!(html.contains("repeat-icmp"));

    let invalid = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["tag", root_text, "missing", "response", "invalid"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    let invalid_span = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["span", root_text, "obs-000006-0010", "6", "1000"])
        .output()
        .unwrap();
    assert!(!invalid_span.status.success());
    assert_eq!(cli(&["resume", root_text])["revision"], 13);
    let artifact = root.join(capture["event"]["capture"]["artifact"].as_str().unwrap());
    fs::write(&artifact, b"changed").unwrap();
    let invalid_artifact = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["verify", root_text])
        .output()
        .unwrap();
    assert!(!invalid_artifact.status.success());
    assert!(String::from_utf8_lossy(&invalid_artifact.stderr).contains("SHA-256 mismatch"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_mark_a_stimulus_and_tag_its_capture_window_idempotently() {
    let root = workspace();
    let root_text = path(&root);
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcap");
    cli(&["init", root_text, "Which packets followed the stimulus?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Timed stimulus",
        "-",
        "Tag only matching packets",
    ]);
    let exp_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        exp_id,
        "stimulus",
        "sequence 255 interval",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let other = cli(&["trial", root_text, exp_id, "control", "same timestamps"]);
    let other_id = other["event"]["trial"]["id"].as_str().unwrap();
    let start = "1700000004000000000";
    let end = "1700000005000000000";
    let marker = cli(&[
        "mark-at",
        root_text,
        trial_id,
        start,
        "stimulus",
        "Set sequence to 255",
    ]);
    let action_id = marker["event"]["action"]["id"].as_str().unwrap();
    assert_eq!(
        marker["event"]["action"]["timestamp_ns"],
        start.parse::<u64>().unwrap()
    );
    cli(&["import", root_text, trial_id, "pcap-icmp", path(&fixture)]);
    cli(&["import", root_text, other_id, "pcap-icmp", path(&fixture)]);
    let (first, retry) = thread::scope(|scope| {
        let one = scope.spawn(|| {
            cli(&[
                "tag-window",
                root_text,
                action_id,
                end,
                "stimulus",
                "sequence 255",
                "stimulus-window-once",
            ])
        });
        let two = scope.spawn(|| {
            cli(&[
                "tag-window",
                root_text,
                action_id,
                end,
                "stimulus",
                "sequence 255",
                "stimulus-window-once",
            ])
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_eq!(first["window"]["id"], retry["window"]["id"]);
    assert_ne!(first["replayed"], retry["replayed"]);
    assert_eq!(
        first["window"]["observation_ids"],
        serde_json::json!(["obs-000006-0008", "obs-000006-0009"])
    );
    let status = cli(&["window-status", root_text, "stimulus-window-once"]);
    assert_eq!(status["window"]["id"], first["window"]["id"]);
    assert_eq!(cli(&["resume", root_text])["tag_count"], 2);
    let mismatched = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "tag-window",
            root_text,
            action_id,
            end,
            "control",
            "sequence 255",
            "stimulus-window-once",
        ])
        .output()
        .unwrap();
    assert!(!mismatched.status.success());
    assert!(String::from_utf8_lossy(&mismatched.stderr).contains("different arguments"));
    cli(&["import", root_text, trial_id, "pcap-icmp", path(&fixture)]);
    let replay = cli(&[
        "tag-window",
        root_text,
        action_id,
        end,
        "stimulus",
        "sequence 255",
        "stimulus-window-once",
    ]);
    assert_eq!(
        replay["window"]["observation_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let later = cli(&[
        "tag-window",
        root_text,
        action_id,
        end,
        "stimulus",
        "sequence 255",
        "later-capture-window",
    ]);
    assert_eq!(
        later["window"]["observation_ids"],
        serde_json::json!(["obs-000009-0008", "obs-000009-0009"])
    );
    assert_eq!(cli(&["resume", root_text])["tag_count"], 4);
    let live_marker = cli(&[
        "mark",
        root_text,
        trial_id,
        "observation",
        "Current clock marker",
    ]);
    assert!(
        live_marker["event"]["action"]["timestamp_ns"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(cli(&["verify", root_text])["observations"], 72);
    let report = root.join("timed-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Tagged action windows"));
    assert!(html.contains("stimulus-window-once"));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn capture_timeout_records_failure_and_same_key_does_not_rerun() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Can a capture timeout safely?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Bound execution",
        "-",
        "Stop on time",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "test", "one command"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let marker = root.join("attempts.txt");
    let late_marker = root.join("late-child.txt");
    let arguments = [
        "capture-command",
        root_text,
        trial_id,
        "hex",
        "timeout-once",
        "300",
        "--",
        "sh",
        "-c",
        "printf x >> \"$1\"; (sleep 1; printf y > \"$2\") & sleep 5; printf 'aa\\n'",
        "_",
        path(&marker),
        path(&late_marker),
    ];
    let first = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(!first.status.success());
    let first_json: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_json["status"], "failed");
    assert!(first_json["error"].as_str().unwrap().contains("timed out"));
    assert_eq!(fs::read(&marker).unwrap(), b"x");
    assert_eq!(
        cli(&["capture-status", root_text, "timeout-once"])["status"],
        "failed"
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(!replay.status.success());
    assert_eq!(fs::read(&marker).unwrap(), b"x");
    thread::sleep(Duration::from_millis(1200));
    assert!(!late_marker.exists());
    let summary = cli(&["resume", root_text]);
    assert_eq!(summary["revision"], 5);
    assert_eq!(summary["captures"].as_array().unwrap().len(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn concurrent_capture_retry_sees_running_then_completed() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can concurrent retries share one capture?",
    ]);
    let experiment = cli(&["experiment", root_text, "Capture once", "-", "One artifact"]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "test", "one command"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcap");
    let arguments = [
        "capture-command",
        root_text,
        trial_id,
        "pcap-icmp",
        "concurrent-once",
        "5000",
        "--",
        "sh",
        "-c",
        "sleep 1; cat \"$1\"",
        "_",
        path(&fixture),
    ];
    let first = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut observed_running = false;
    for _ in 0..100 {
        let status = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
            .args(["capture-status", root_text, "concurrent-once"])
            .output()
            .unwrap();
        if status.status.success() {
            let value: Value = serde_json::from_slice(&status.stdout).unwrap();
            if value["status"] == "running" {
                observed_running = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(observed_running);
    let marker = cli(&[
        "mark",
        root_text,
        trial_id,
        "stimulus",
        "Changed the controlled input while capture ran",
    ]);
    assert_eq!(marker["event"]["action"]["kind"], "stimulus");
    let concurrent = cli(&arguments);
    assert_eq!(concurrent["status"], "running");
    let first_output = first.wait_with_output().unwrap();
    assert!(
        first_output.status.success(),
        "{}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    let completed: Value = serde_json::from_slice(&first_output.stdout).unwrap();
    assert_eq!(completed["status"], "completed");
    let replay = cli(&arguments);
    assert_eq!(replay["capture"]["id"], completed["capture"]["id"]);
    let summary = cli(&["resume", root_text]);
    assert_eq!(summary["revision"], 6);
    assert_eq!(summary["captures"].as_array().unwrap().len(), 1);
    assert_eq!(cli(&["verify", root_text])["observations"], 24);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn agent_can_start_mark_stop_and_resume_a_background_capture() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can an agent control a capture while marking actions?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Timed capture",
        "-",
        "Preserve a stopped PCAP",
    ]);
    let exp_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        exp_id,
        "baseline",
        "one emitted capture",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcap");
    let emitted = root.join("emitted.flag");
    let args = [
        "capture-start",
        root_text,
        trial_id,
        "pcap-icmp",
        "background-once",
        "10000",
        "--",
        "sh",
        "-c",
        "cat \"$1\"; touch \"$2\"; sleep 30",
        "_",
        path(&fixture),
        path(&emitted),
    ];
    let started = cli(&args);
    assert_eq!(started["status"], "running");
    assert_eq!(cli(&args)["status"], "running");
    for _ in 0..100 {
        if emitted.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(emitted.exists());
    let marker = cli(&[
        "mark",
        root_text,
        trial_id,
        "stimulus",
        "Changed input while capture ran",
    ]);
    assert_eq!(marker["event"]["action"]["kind"], "stimulus");
    let stop = cli(&["capture-stop", root_text, "background-once"]);
    assert_eq!(stop["stop_requested"], true);
    assert!(stop["status"] == "stopping" || stop["status"] == "completed");
    let again = cli(&["capture-stop", root_text, "background-once"]);
    assert_eq!(again["stop_requested"], true);
    let completed = wait_for_capture(root_text, "background-once", Duration::from_secs(5));
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["observation_ids"].as_array().unwrap().len(), 24);
    assert_eq!(cli(&["verify", root_text])["observations"], 24);
    let replay = cli(&args);
    assert_eq!(replay["capture"]["id"], completed["capture"]["id"]);
    assert_eq!(replay["revision"], completed["revision"]);
    let report = root.join("background-report.html");
    cli(&["report", root_text, path(&report)]);
    assert!(
        fs::read_to_string(report)
            .unwrap()
            .contains("stop requested")
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn stop_forces_an_unresponsive_capture_but_preserves_valid_output() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Can an unresponsive capture be stopped?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Force stop",
        "-",
        "Preserve emitted packets",
    ]);
    let exp_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, exp_id, "test", "ignore interrupt"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcap");
    let emitted = root.join("emitted.flag");
    let started = cli(&[
        "capture-start",
        root_text,
        trial_id,
        "pcap-icmp",
        "force-stop-once",
        "10000",
        "--",
        "sh",
        "-c",
        "trap '' INT; cat \"$1\"; touch \"$2\"; sleep 30",
        "_",
        path(&fixture),
        path(&emitted),
    ]);
    assert_eq!(started["status"], "running");
    for _ in 0..100 {
        if emitted.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(emitted.exists());
    assert_eq!(
        cli(&["capture-stop", root_text, "force-stop-once"])["stop_requested"],
        true
    );
    let completed = wait_for_capture(root_text, "force-stop-once", Duration::from_secs(5));
    assert_eq!(completed["status"], "completed");
    assert_eq!(cli(&["verify", root_text])["observations"], 24);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn stopping_before_any_payload_records_failure_without_a_capture() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "What if a capture stops before output?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Empty stop",
        "-",
        "No partial artifact",
    ]);
    let exp_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, exp_id, "test", "sleep first"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let started = cli(&[
        "capture-start",
        root_text,
        trial_id,
        "hex",
        "empty-stop-once",
        "10000",
        "--",
        "sh",
        "-c",
        "sleep 30; printf 'aa\\n'",
    ]);
    assert_eq!(started["status"], "running");
    cli(&["capture-stop", root_text, "empty-stop-once"]);
    let failed = wait_for_capture(root_text, "empty-stop-once", Duration::from_secs(5));
    assert_eq!(failed["status"], "failed");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("no supported messages")
    );
    assert_eq!(
        cli(&["resume", root_text])["captures"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn interrupted_reservation_is_inspectable_and_never_reexecuted() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "What if an agent dies during capture?"]);
    let experiment = cli(&["experiment", root_text, "Reserve work", "-", "No rerun"]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "test", "one command"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let marker = root.join("should-not-exist.txt");
    let argv = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "printf x >> \"$1\"; printf 'aa\\n'".to_owned(),
        "_".to_owned(),
        path(&marker).to_owned(),
    ];
    workflow::append(
        &root,
        Event::CaptureRunReserved {
            run: CaptureRun {
                id: String::new(),
                key: "interrupted-once".into(),
                trial_id: trial_id.into(),
                format: "hex".into(),
                command_fingerprint: workflow::capture_run_fingerprint(
                    trial_id, "hex", 5000, &argv,
                )
                .unwrap(),
                timeout_ms: 5000,
                status: CaptureRunStatus::Reserved,
                capture_id: None,
                error: None,
                stop_requested: false,
            },
        },
    )
    .unwrap();
    assert_eq!(
        cli(&["capture-status", root_text, "interrupted-once"])["status"],
        "interrupted"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "capture-command",
            root_text,
            trial_id,
            "hex",
            "interrupted-once",
            "5000",
            "--",
            "sh",
            "-c",
            "printf x >> \"$1\"; printf 'aa\\n'",
            "_",
            path(&marker),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!marker.exists());
    assert_eq!(
        cli(&["capture-status", root_text, "interrupted-once"])["status"],
        "failed"
    );
    assert_eq!(cli(&["resume", root_text])["revision"], 5);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn capture_output_limit_records_failure_without_importing() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Does a large capture stop?"]);
    let experiment = cli(&["experiment", root_text, "Bound output", "-", "No import"]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "test", "large output"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "capture-command",
            root_text,
            trial_id,
            "binary",
            "too-many-bytes",
            "5000",
            "--",
            "python3",
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * (32 * 1024 * 1024 + 1))",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "failed");
    assert!(result["error"].as_str().unwrap().contains("exceeds 32 MiB"));
    let summary = cli(&["resume", root_text]);
    assert_eq!(summary["revision"], 5);
    assert_eq!(summary["captures"].as_array().unwrap().len(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn controlled_trials_isolate_sequence_and_checksum_bytes() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&[
        "init",
        root_text,
        "Which bytes respond to sequence 255 → 256?",
    ]);
    cli(&[
        "hypothesis",
        root_text,
        "Bytes 6..8 encode sequence in network byte order",
    ]);
    cli(&[
        "experiment",
        root_text,
        "Hold identifier and payload constant",
        "hyp-000002",
        "Only sequence and checksum bytes change",
    ]);
    cli(&["trial", root_text, "exp-000003", "baseline", "sequence=255"]);
    cli(&["trial", root_text, "exp-000003", "variant", "sequence=256"]);
    cli(&[
        "import",
        root_text,
        "trial-000004",
        "pcap-icmp",
        path(&examples.join("icmp_baseline_255.pcap")),
    ]);
    cli(&[
        "import",
        root_text,
        "trial-000005",
        "pcap-icmp",
        path(&examples.join("icmp_variant_256.pcap")),
    ]);
    let diff = cli(&["diff", root_text, "obs-000006-0000", "obs-000007-0000"]);
    let ranges = diff["changed_ranges"].as_array().unwrap();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0]["start"], 3);
    assert_eq!(ranges[0]["end"], 4);
    assert_eq!(ranges[1]["start"], 6);
    assert_eq!(ranges[1]["end"], 8);
    assert_eq!(ranges[1]["left_hex"], "00ff");
    assert_eq!(ranges[1]["right_hex"], "0100");
    let trial_comparison = cli(&["compare-trials", root_text, "trial-000004", "trial-000005"]);
    assert_eq!(trial_comparison["pair_count"], 2);
    assert_eq!(trial_comparison["unmatched_baseline"], 0);
    assert_eq!(trial_comparison["unmatched_variant"], 0);
    assert_eq!(trial_comparison["changed_positions"][0]["offset"], 3);
    assert_eq!(trial_comparison["changed_positions"][0]["pairs_changed"], 2);
    assert_eq!(trial_comparison["changed_positions"][1]["offset"], 6);
    assert_eq!(trial_comparison["changed_positions"][2]["offset"], 7);
    assert_eq!(cli(&["verify", root_text])["observations"], 4);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_agents_get_unique_revisions_and_complete_artifacts() {
    let root = workspace();
    let root_text = path(&root).to_owned();
    cli(&["init", &root_text, "Can agents write concurrently?"]);

    let hypotheses: Vec<_> = (0..16)
        .map(|index| {
            let root_text = root_text.clone();
            thread::spawn(move || {
                Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
                    .args(["hypothesis", &root_text, &format!("claim {index}")])
                    .output()
                    .unwrap()
            })
        })
        .collect();
    let mut revisions = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    for handle in hypotheses {
        let output = handle.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        let revision = record["revision"].as_u64().unwrap();
        revisions.insert(revision);
        ids.insert(
            record["event"]["hypothesis"]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(revisions, (2..=17).collect());
    assert_eq!(ids.len(), 16);

    let experiment = cli(&[
        "experiment",
        &root_text,
        "Repeat the same capture",
        "-",
        "Every import retains its own observation IDs",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", &root_text, experiment_id, "baseline", "none"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap().to_owned();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcap");
    let fixture_text = path(&fixture).to_owned();
    let imports: Vec<_> = (0..8)
        .map(|_| {
            let root_text = root_text.clone();
            let fixture_text = fixture_text.clone();
            let trial_id = trial_id.clone();
            thread::spawn(move || {
                Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
                    .args(["import", &root_text, &trial_id, "pcap-icmp", &fixture_text])
                    .output()
                    .unwrap()
            })
        })
        .collect();
    let mut capture_ids = std::collections::BTreeSet::new();
    for handle in imports {
        let output = handle.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: Value = serde_json::from_slice(&output.stdout).unwrap();
        capture_ids.insert(
            record["event"]["capture"]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(capture_ids.len(), 8);
    assert_eq!(cli(&["resume", &root_text])["revision"], 27);
    let verification = cli(&["verify", &root_text]);
    assert_eq!(verification["captures"], 8);
    assert_eq!(verification["observations"], 192);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn imports_pcapng_through_the_same_investigation_workflow() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Read pcapng ICMP traffic"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Inspect packets",
        "-",
        "Echo pairs",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "baseline", "none"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcapng");
    let capture = cli(&["import", root_text, trial_id, "pcapng-icmp", path(&fixture)]);
    assert_eq!(capture["event"]["capture"]["observation_count"], 24);
    assert_eq!(capture["event"]["observations"][0]["source_offset"], 110);
    assert_eq!(cli(&["verify", root_text])["observations"], 24);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tagged_ethernet_capture_keeps_exact_span_provenance() {
    let root = workspace();
    let root_text = path(&root);
    let original = include_bytes!("../examples/icmp_echo.pcap");
    let frame_length = u32::from_le_bytes(original[32..36].try_into().unwrap()) as usize;
    let frame = &original[40..40 + frame_length];
    let mut tagged_frame = frame[..12].to_vec();
    tagged_frame.extend(0x88a8_u16.to_be_bytes());
    tagged_frame.extend(1_u16.to_be_bytes());
    tagged_frame.extend(0x8100_u16.to_be_bytes());
    tagged_frame.extend(2_u16.to_be_bytes());
    tagged_frame.extend(&frame[12..]);
    let mut pcap = original[..40].to_vec();
    pcap[32..36].copy_from_slice(&(tagged_frame.len() as u32).to_le_bytes());
    pcap[36..40].copy_from_slice(&(tagged_frame.len() as u32).to_le_bytes());
    pcap.extend(tagged_frame);
    let fixture = root.join("tagged-icmp.pcap");
    fs::write(&fixture, &pcap).unwrap();

    cli(&[
        "init",
        root_text,
        "Where is the ICMP sequence in VLAN traffic?",
    ]);
    let experiment = cli(&["experiment", root_text, "Tagged capture", "-", "One echo"]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "baseline", "QinQ"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let imported = cli(&["import", root_text, trial_id, "pcap-icmp", path(&fixture)]);
    let observation = &imported["event"]["observations"][0];
    assert_eq!(observation["source_offset"], 82);
    assert_eq!(observation["bytes_hex"].as_str().unwrap().len() / 2, 8);
    let id = observation["id"].as_str().unwrap();
    let span = cli(&["span", root_text, id, "6", "8"]);
    assert_eq!(span["source_file_offset"], 88);
    assert_eq!(span["bytes_hex"], "0000");
    assert_eq!(cli(&["verify", root_text])["observations"], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_investigate_ipv6_and_reassemble_tcp_with_provenance() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&["init", root_text, "Where are the fields in IPv6 traffic?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Vary echo and transaction IDs",
        "-",
        "Find stable fields and TCP runs",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "sweep", "IPv6 values"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let classic = examples.join("ipv6_mixed.pcap");
    let enhanced = examples.join("ipv6_mixed.pcapng");
    let mut imports = Vec::new();
    for (format, file, count) in [
        ("pcap-icmpv6", &classic, 12),
        ("pcapng-icmpv6", &enhanced, 12),
        ("pcap-udp", &classic, 8),
        ("pcapng-udp", &enhanced, 8),
        ("pcap-tcp-stream", &classic, 2),
        ("pcapng-tcp-stream", &enhanced, 2),
    ] {
        let result = cli(&["import", root_text, trial_id, format, path(file)]);
        assert_eq!(result["event"]["capture"]["observation_count"], count);
        imports.push(result);
    }
    let echo = &imports[0]["event"]["observations"];
    assert_eq!(echo[0]["direction"], "2001:db8::1 -> 2001:db8::2");
    assert_eq!(echo[1]["direction"], "2001:db8::2 -> 2001:db8::1");
    assert_eq!(&echo[6]["bytes_hex"].as_str().unwrap()[12..16], "0100");
    for (index, value, role) in [
        (0, 0, "discovery"),
        (2, 1, "discovery"),
        (4, 255, "discovery"),
        (6, 256, "discovery"),
        (8, 1024, "validation"),
        (10, 65535, "validation"),
    ] {
        let id = echo[index]["id"].as_str().unwrap();
        cli(&["value", root_text, id, "sequence", &value.to_string(), role]);
    }
    let inferred = cli(&["infer-value", root_text, "sequence"]);
    assert_eq!(inferred["candidate_count"], 1);
    assert_eq!(inferred["candidates"][0]["start"], 6);
    assert_eq!(inferred["candidates"][0]["end"], 8);
    assert_eq!(inferred["candidates"][0]["validation_matches"], 2);

    for run in [
        &imports[4]["event"]["observations"][0],
        &imports[5]["event"]["observations"][0],
    ] {
        assert_eq!(run["bytes_hex"], "5049325100000161");
        assert_eq!(run["source_spans"].as_array().unwrap().len(), 2);
        let span = cli(&["span", root_text, run["id"].as_str().unwrap(), "5", "8"]);
        assert_eq!(span["bytes_hex"], "000161");
        assert_eq!(span["source_spans"].as_array().unwrap().len(), 2);
    }
    assert_eq!(cli(&["verify", root_text])["observations"], 44);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_investigate_dns_over_udp_without_a_dns_specific_decoder() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Where is the DNS transaction ID?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Change transaction ID and query name",
        "-",
        "Find a two-byte ID inside UDP payloads",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "sweep", "six queries"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/dns_udp.pcap");
    let capture = cli(&["import", root_text, trial_id, "pcap-udp", path(&fixture)]);
    assert_eq!(capture["event"]["capture"]["observation_count"], 12);
    assert_eq!(capture["event"]["observations"][0]["source_offset"], 82);
    assert_eq!(capture["event"]["observations"][0]["source_port"], 40000);
    assert_eq!(capture["event"]["observations"][0]["destination_port"], 53);
    assert_eq!(capture["event"]["observations"][1]["source_port"], 53);
    let page = cli(&["observations", root_text, trial_id, "0", "1"]);
    assert_eq!(page["observations"][0]["source_port"], 40000);
    let request_query = serde_json::json!({"format":"pcap-udp","destination_port":53}).to_string();
    let requests = cli(&["search-observations", root_text, &request_query]);
    assert_eq!(requests["total"], 6);
    assert!(
        requests["observations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["destination_port"] == 53)
    );
    let one_port_query = serde_json::json!({"source_port":40000,"destination_port":53}).to_string();
    let one_port = cli(&["search-observations", root_text, &one_port_query]);
    assert_eq!(one_port["total"], 1);
    assert_eq!(one_port["observations"][0]["id"], "obs-000004-0000");
    let span = cli(&["span", root_text, "obs-000004-0000", "0", "2"]);
    assert_eq!(span["bytes_hex"], "0000");
    assert_eq!(span["source_file_offset"], 82);
    let groups = cli(&["cluster", root_text, trial_id, "respect"]);
    assert_eq!(groups["clusters"].as_array().unwrap().len(), 2);
    assert!(
        groups["clusters"]
            .as_array()
            .unwrap()
            .iter()
            .all(|cluster| cluster["member_count"] == 6)
    );
    let request_group = groups["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cluster| cluster["split_rules"][0]["value"] == "192.0.2.10 -> 192.0.2.53")
        .unwrap();
    let aligned = cli(&[
        "analyze-cluster",
        root_text,
        request_group["id"].as_str().unwrap(),
        trial_id,
        "respect",
    ]);
    assert_eq!(
        aligned["event"]["analysis"]["observation_ids"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    for (index, value) in [(0, 0), (2, 1), (4, 2), (6, 255)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "transaction_id",
            &value.to_string(),
            "discovery",
        ]);
    }
    for (index, value) in [(8, 256), (10, 257)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "transaction_id",
            &value.to_string(),
            "validation",
        ]);
    }
    let inferred = cli(&["infer-value", root_text, "transaction_id"]);
    assert_eq!(inferred["candidate_count"], 2);
    assert_eq!(inferred["validated_candidate_count"], 1);
    assert_eq!(inferred["preferred_candidate_count"], 1);
    assert_eq!(inferred["candidates"][0]["start"], 0);
    assert_eq!(inferred["candidates"][0]["end"], 2);
    assert_eq!(inferred["candidates"][0]["byte_order"], "big_endian");
    assert_eq!(inferred["candidates"][0]["validation_matches"], 2);
    assert_eq!(inferred["candidates"][0]["preferred"], true);
    assert_eq!(inferred["candidates"][1]["start"], 1);
    assert_eq!(inferred["candidates"][1]["end"], 2);
    assert_eq!(inferred["candidates"][1]["validation_matches"], 0);
    let report = root.join("dns-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("ports "));
    assert!(html.contains("transaction_id"));
    assert_eq!(cli(&["verify", root_text])["observations"], 12);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_investigate_tcp_payloads_without_an_application_decoder() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Where is the application transaction ID in TCP payloads?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Vary transaction ID and payload length",
        "-",
        "Find a two-byte ID in the application bytes",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "sweep", "six exchanges"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/tcp_payload.pcap");
    let capture = cli(&["import", root_text, trial_id, "pcap-tcp", path(&fixture)]);
    assert_eq!(capture["event"]["capture"]["observation_count"], 12);
    assert_eq!(capture["event"]["observations"][0]["source_index"], 1);
    assert_eq!(capture["event"]["observations"][0]["source_port"], 41000);
    assert_eq!(
        capture["event"]["observations"][0]["destination_port"],
        4242
    );
    assert_eq!(capture["event"]["observations"][0]["tcp_sequence"], 1000);
    assert_eq!(capture["event"]["observations"][1]["tcp_sequence"], 9000);
    let page = cli(&["observations", root_text, trial_id, "0", "1"]);
    assert_eq!(page["observations"][0]["tcp_sequence"], 1000);
    let span = cli(&["span", root_text, "obs-000004-0000", "4", "6"]);
    assert_eq!(span["bytes_hex"], "0000");
    assert_eq!(span["source_file_offset"], 172);
    cli(&[
        "tag",
        root_text,
        "obs-000004-0000",
        "baseline",
        "first request",
    ]);
    for (index, value) in [(0, 0), (2, 1), (4, 2), (6, 255)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "transaction_id",
            &value.to_string(),
            "discovery",
        ]);
    }
    for (index, value) in [(8, 256), (10, 257)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "transaction_id",
            &value.to_string(),
            "validation",
        ]);
    }
    let inferred = cli(&["infer-value", root_text, "transaction_id"]);
    let preferred: Vec<_> = inferred["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|candidate| candidate["preferred"] == true)
        .collect();
    assert_eq!(preferred.len(), 1);
    assert_eq!(preferred[0]["start"], 4);
    assert_eq!(preferred[0]["end"], 6);
    assert_eq!(preferred[0]["byte_order"], "big_endian");
    assert_eq!(preferred[0]["validation_matches"], 2);
    let enhanced_fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/tcp_payload.pcapng");
    let run = cli(&[
        "capture-command",
        root_text,
        trial_id,
        "pcapng-tcp",
        "tcp-ng-once",
        "5000",
        "--",
        "cat",
        path(&enhanced_fixture),
    ]);
    assert_eq!(run["status"], "completed");
    assert_eq!(run["capture"]["format"], "pcapng-tcp");
    assert_eq!(run["observation_ids"].as_array().unwrap().len(), 12);
    assert_eq!(
        cli(&["capture-status", root_text, "tcp-ng-once"])["status"],
        "completed"
    );
    assert_eq!(cli(&["verify", root_text])["observations"], 24);
    let report = root.join("tcp-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("TCP seq"));
    assert!(html.contains("transaction_id"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_infer_across_tcp_segments_and_trace_each_byte() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can a split TCP message be reconstructed?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Split the transaction ID across TCP packets",
        "-",
        "The reconstructed ID spans two source packets",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "sweep",
        "six split requests",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/tcp_stream.pcap");
    let raw = fs::read(&fixture).unwrap();
    let segments = protocol_informatics_v2::pcap::extract_tcp_segments(&raw).unwrap();
    let duplicate = segments
        .iter()
        .find(|segment| {
            segment.source_port == Some(42002)
                && segment.tcp_sequence == Some(2205)
                && segments.iter().any(|other| {
                    other.packet_index < segment.packet_index
                        && other.source_port == segment.source_port
                        && other.tcp_sequence == segment.tcp_sequence
                })
        })
        .unwrap();
    let mut conflicting = raw.clone();
    conflicting[duplicate.source_offset] ^= 0x01;
    let conflict_path = root.join("conflicting.pcap");
    fs::write(&conflict_path, conflicting).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "import",
            root_text,
            trial_id,
            "pcap-tcp-stream",
            path(&conflict_path),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("conflicting TCP overlap"));
    assert_eq!(
        cli(&["resume", root_text])["captures"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let capture = cli(&[
        "import",
        root_text,
        trial_id,
        "pcap-tcp-stream",
        path(&fixture),
    ]);
    assert_eq!(capture["event"]["capture"]["observation_count"], 12);
    assert_eq!(
        capture["event"]["observations"][0]["source_offset"],
        Value::Null
    );
    assert_eq!(
        capture["event"]["observations"][0]["source_spans"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        capture["event"]["observations"][0]["bytes_hex"],
        "5049325100000161"
    );
    let span = cli(&["span", root_text, "obs-000004-0000", "4", "6"]);
    assert_eq!(span["bytes_hex"], "0000");
    assert_eq!(span["source_file_offset"], Value::Null);
    let sources = span["source_spans"].as_array().unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["message_start"], 4);
    assert_eq!(sources[0]["message_end"], 5);
    assert_eq!(sources[1]["message_start"], 5);
    assert_eq!(sources[1]["message_end"], 6);
    // A single-record structural fit is deliberately weak evidence, but its
    // proposed boundary must still trace through both source packets.
    let framing = cli(&[
        "probe-framing",
        root_text,
        "obs-000004-0000",
        "0",
        "6",
        "1",
        "big",
        "payload",
        "1",
    ]);
    assert_eq!(framing["status"], "complete");
    assert_eq!(framing["record_count"], 1);
    assert_eq!(framing["records"][0]["source_file_offset"], Value::Null);
    assert_eq!(
        framing["records"][0]["source_spans"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for source in sources {
        let offset = source["file_offset"].as_u64().unwrap() as usize;
        let start = source["message_start"].as_u64().unwrap() as usize;
        let end = source["message_end"].as_u64().unwrap() as usize;
        let bytes = protocol_informatics_v2::workflow::from_hex(
            capture["event"]["observations"][0]["bytes_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(&raw[offset..offset + end - start], &bytes[start..end]);
    }
    for (index, value) in [(0, 0), (2, 1), (4, 2), (6, 255)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "transaction_id",
            &value.to_string(),
            "discovery",
        ]);
    }
    for (index, value) in [(8, 256), (10, 257)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "transaction_id",
            &value.to_string(),
            "validation",
        ]);
    }
    let inferred = cli(&["infer-value", root_text, "transaction_id"]);
    let preferred: Vec<_> = inferred["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|candidate| candidate["preferred"] == true)
        .collect();
    assert_eq!(preferred.len(), 1);
    assert_eq!(preferred[0]["start"], 4);
    assert_eq!(preferred[0]["end"], 6);
    assert_eq!(preferred[0]["validation_matches"], 2);
    let enhanced = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/tcp_stream.pcapng");
    let run = cli(&[
        "capture-command",
        root_text,
        trial_id,
        "pcapng-tcp-stream",
        "split-tcp-once",
        "5000",
        "--",
        "cat",
        path(&enhanced),
    ]);
    assert_eq!(run["status"], "completed");
    assert_eq!(run["observation_ids"].as_array().unwrap().len(), 12);
    assert_eq!(cli(&["verify", root_text])["observations"], 24);
    let report = root.join("stream-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Byte provenance"));
    assert!(html.contains("transaction_id"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_infer_a_field_from_standalone_binary_files() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Where is the sample rate in a binary file?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Change only the sample rate",
        "-",
        "Find its byte span",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "sweep", "four rates"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut observation_ids = Vec::new();
    for rate in [8000, 44100, 96000, 192000] {
        let fixture = examples.join(format!("wav_rate_{rate}.wav"));
        let capture = cli(&["import", root_text, trial_id, "binary", path(&fixture)]);
        assert_eq!(capture["event"]["capture"]["observation_count"], 1);
        assert_eq!(capture["event"]["observations"][0]["source_offset"], 0);
        observation_ids.push(
            capture["event"]["observations"][0]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let span = cli(&["span", root_text, &observation_ids[0], "24", "28"]);
    assert_eq!(span["bytes_hex"], "401f0000");
    assert_eq!(span["source_file_offset"], 24);
    for (index, rate) in [8000, 44100, 96000, 192000].into_iter().enumerate() {
        cli(&[
            "value",
            root_text,
            &observation_ids[index],
            "sample_rate",
            &rate.to_string(),
            if index == 3 {
                "validation"
            } else {
                "discovery"
            },
        ]);
    }
    let inferred = cli(&["infer-value", root_text, "sample_rate"]);
    assert_eq!(inferred["preferred_candidate_count"], 1);
    assert_eq!(inferred["candidates"][0]["start"], 24);
    assert_eq!(inferred["candidates"][0]["end"], 28);
    assert_eq!(inferred["candidates"][0]["byte_order"], "little_endian");
    assert_eq!(inferred["candidates"][0]["validation_matches"], 1);
    cli(&["analyze-investigation", root_text, trial_id]);
    let report = root.join("wav-report.html");
    cli(&["report", root_text, path(&report)]);
    assert!(fs::read_to_string(report).unwrap().contains("sample_rate"));
    assert_eq!(cli(&["verify", root_text])["observations"], 4);
    let too_large = root.join("too-large.bin");
    fs::write(&too_large, vec![0_u8; 1024 * 1024 + 1]).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["import", root_text, trial_id, "binary", path(&too_large)])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("binary file must contain"));
    let empty = root.join("empty.bin");
    fs::write(&empty, []).unwrap();
    let rejected_empty = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["import", root_text, trial_id, "binary", path(&empty)])
        .output()
        .unwrap();
    assert!(!rejected_empty.status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_probe_and_validate_length_prefixed_binary_records() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let truth: Value =
        serde_json::from_str(include_str!("../examples/records.truth.json")).unwrap();
    cli(&["init", root_text, "Where do binary records begin and end?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Vary record payload lengths",
        "-",
        "Length prefix predicts every boundary",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&["trial", root_text, experiment_id, "discovery", "two files"]);
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "two held-out files",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let mut observation_ids = Vec::new();
    for (index, trial_id) in [discovery_id, discovery_id, validation_id, validation_id]
        .into_iter()
        .enumerate()
    {
        let filename = truth["cases"][index]["file"].as_str().unwrap();
        let imported = cli(&[
            "import",
            root_text,
            trial_id,
            "binary",
            path(&examples.join(filename)),
        ]);
        observation_ids.push(
            imported["event"]["observations"][0]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let first = &observation_ids[0];
    let probe = cli(&[
        "probe-framing",
        root_text,
        first,
        "4",
        "1",
        "2",
        "big",
        "payload",
        "2",
    ]);
    assert_eq!(probe["status"], "complete");
    assert_eq!(probe["record_count"], 3);
    assert_eq!(probe["remaining_bytes"], 0);
    for (record, expected) in probe["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(truth["cases"][0]["records"].as_array().unwrap())
    {
        assert_eq!(record["start"], expected["start"]);
        assert_eq!(record["logical_end"], expected["logical_end"]);
        assert_eq!(record["end"], expected["end"]);
        assert_eq!(record["length_field_start"], expected["length_field_start"]);
        assert_eq!(record["length_value"], expected["length"]);
        assert_eq!(record["source_file_offset"], expected["start"]);
    }
    let tlv_probe = cli(&[
        "probe-tlv",
        root_text,
        first,
        "4",
        "1",
        "2",
        "big",
        "payload",
        "2",
    ]);
    assert_eq!(tlv_probe["status"], "complete");
    assert_eq!(tlv_probe["element_count"], 3);
    for (element, expected) in tlv_probe["elements"]
        .as_array()
        .unwrap()
        .iter()
        .zip(truth["cases"][0]["records"].as_array().unwrap())
    {
        assert_eq!(element["start"], expected["start"]);
        assert_eq!(element["end"], expected["end"]);
        assert_eq!(element["type_start"], expected["start"]);
        assert_eq!(
            element["type_end"].as_u64().unwrap(),
            expected["start"].as_u64().unwrap() + 1
        );
        assert_eq!(element["value_start"], element["length_field_end"]);
        assert_eq!(element["value_end"], expected["logical_end"]);
        assert_eq!(element["value_length"], expected["length"]);
        assert_eq!(
            element["type_hex"],
            format!("{:02x}", expected["kind"].as_u64().unwrap())
        );
        assert_eq!(element["source_file_offset"], expected["start"]);
    }
    let wrong = cli(&[
        "probe-framing",
        root_text,
        first,
        "4",
        "1",
        "2",
        "little",
        "payload",
        "2",
    ]);
    assert_ne!(wrong["status"], "complete");
    assert!(wrong["record_count"].as_u64().unwrap() < 3);

    let inferred = cli(&["infer-framing", root_text, discovery_id, validation_id]);
    assert_eq!(inferred["discovery_count"], 2);
    assert_eq!(inferred["validation_count"], 2);
    assert_eq!(inferred["candidate_count"], 1);
    assert_eq!(inferred["candidates"][0]["config"], probe["config"]);
    assert_eq!(inferred["candidates"][0]["validation_matches"], 2);
    let tlv_inferred = cli(&["infer-tlv", root_text, discovery_id, validation_id]);
    assert_eq!(tlv_inferred["candidate_count"], 1);
    assert_eq!(tlv_inferred["candidates"][0]["config"], tlv_probe["config"]);
    assert_eq!(
        tlv_inferred["candidates"][0]["recurring_discovery_types"],
        3
    );
    assert_eq!(
        tlv_inferred["candidates"][0]["validation_elements_with_seen_types"],
        6
    );
    assert_eq!(tlv_inferred["candidates"][0]["type_profile_count"], 3);
    let revision_before = cli(&["resume", root_text])["revision"].as_u64().unwrap();
    let committed = cli(&[
        "commit-framing",
        root_text,
        first,
        "4",
        "1",
        "2",
        "big",
        "payload",
        "2",
        "discovery-a-v1",
    ]);
    assert_eq!(committed["replayed"], false);
    assert_eq!(committed["revision"], revision_before + 1);
    assert_eq!(committed["run"]["records"].as_array().unwrap().len(), 3);
    let frame_id = committed["run"]["records"][1]["id"].as_str().unwrap();
    let replayed = cli(&[
        "commit-framing",
        root_text,
        first,
        "4",
        "1",
        "2",
        "big",
        "payload",
        "2",
        "discovery-a-v1",
    ]);
    assert_eq!(replayed["replayed"], true);
    assert_eq!(replayed["revision"], committed["revision"]);
    assert_eq!(
        cli(&["framing-status", root_text, "discovery-a-v1"])["run"],
        committed["run"]
    );
    let page = cli(&["frames", root_text, "discovery-a-v1", "1", "1"]);
    assert_eq!(page["total"], 3);
    assert_eq!(page["frames"][0]["id"], frame_id);
    assert_eq!(page["next_offset"], 2);
    let span = cli(&["frame-span", root_text, frame_id, "0", "8"]);
    let original = fs::read(examples.join("records_discovery_a.bin")).unwrap();
    assert_eq!(span["coordinate_system"], "frame_bytes");
    assert_eq!(span["frame_length"], 8);
    assert_eq!(span["logical_length"], 7);
    assert_eq!(span["observation_start"], 8);
    assert_eq!(span["source_file_offset"], 8);
    assert_eq!(
        span["bytes_hex"],
        protocol_informatics_v2::workflow::to_hex(&original[8..16])
    );
    let conflicting = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "commit-framing",
            root_text,
            first,
            "4",
            "1",
            "2",
            "little",
            "payload",
            "2",
            "discovery-a-v1",
        ])
        .output()
        .unwrap();
    assert!(!conflicting.status.success());
    assert!(String::from_utf8_lossy(&conflicting.stderr).contains("different arguments"));
    let report = root.join("framing-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(&report).unwrap();
    assert!(html.contains("Candidate record framing"));
    assert!(html.contains("Candidate typed records"));
    assert!(html.contains("tlv_inferences"));
    assert!(html.contains("framing_previews"));
    assert!(html.contains("framing_inferences"));
    assert!(html.contains("Committed frames"));
    assert!(html.contains(frame_id));

    let mut corrupted = fs::read(examples.join("records_validation_a.bin")).unwrap();
    corrupted[5] = 0xff;
    let corrupted_path = root.join("corrupted-validation.bin");
    fs::write(&corrupted_path, corrupted).unwrap();
    let corrupted_import = cli(&[
        "import",
        root_text,
        validation_id,
        "binary",
        path(&corrupted_path),
    ]);
    let corrupted_id = corrupted_import["event"]["observations"][0]["id"]
        .as_str()
        .unwrap();
    let challenged = cli(&["infer-framing", root_text, discovery_id, validation_id]);
    assert_eq!(challenged["validation_count"], 3);
    assert_eq!(challenged["candidates"][0]["validation_matches"], 2);
    let tlv_challenged = cli(&["infer-tlv", root_text, discovery_id, validation_id]);
    assert_eq!(tlv_challenged["candidates"][0]["validation_matches"], 2);
    assert_eq!(
        tlv_challenged["candidates"][0]["validation_counterexamples"][0]["observation_id"],
        corrupted_id
    );
    assert_eq!(
        challenged["candidates"][0]["validation_counterexamples"][0]["observation_id"],
        corrupted_id
    );
    assert_eq!(
        challenged["candidates"][0]["validation_counterexamples"][0]["status"],
        "truncated_record"
    );
    assert_eq!(cli(&["verify", root_text])["observations"], 5);
    let event_path = root.join(".pi/events.jsonl");
    let original_events = fs::read_to_string(&event_path).unwrap();
    let tampered = original_events
        .lines()
        .map(|line| {
            let mut event: Value = serde_json::from_str(line).unwrap();
            if event["event"]["type"] == "framing_committed" {
                event["event"]["run"]["records"][1]["logical_end"] = Value::from(14);
            }
            serde_json::to_string(&event).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&event_path, tampered).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["resume", root_text])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("committed frame does not match source bytes")
    );
    fs::write(&event_path, original_events).unwrap();
    assert_eq!(cli(&["verify", root_text])["observations"], 5);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tlv_probe_supports_two_byte_types_and_rejects_invalid_type_widths() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Are records typed?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Change record types",
        "-",
        "Type bytes precede lengths",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "discovery", "two types"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let file = root.join("typed.bin");
    fs::write(
        &file,
        [
            0x12, 0x34, 0x00, 0x01, 0xaa, 0x56, 0x78, 0x00, 0x02, 0xbb, 0xcc,
        ],
    )
    .unwrap();
    let imported = cli(&["import", root_text, trial_id, "binary", path(&file)]);
    let observation_id = imported["event"]["observations"][0]["id"].as_str().unwrap();
    let probe = cli(&[
        "probe-tlv",
        root_text,
        observation_id,
        "0",
        "2",
        "2",
        "big",
        "payload",
        "1",
    ]);
    assert_eq!(probe["status"], "complete");
    assert_eq!(probe["element_count"], 2);
    assert_eq!(probe["elements"][0]["type_hex"], "1234");
    assert_eq!(probe["elements"][0]["value_start"], 4);
    assert_eq!(probe["elements"][0]["value_end"], 5);
    assert_eq!(probe["elements"][1]["type_hex"], "5678");
    assert_eq!(probe["elements"][1]["value_start"], 9);
    assert_eq!(probe["elements"][1]["value_end"], 11);
    let invalid = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "probe-tlv",
            root_text,
            observation_id,
            "0",
            "3",
            "2",
            "big",
            "payload",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("type width must be 1 or 2"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_infer_canonical_varint_record_lengths_across_width_boundary() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let truth: Value = serde_json::from_str(include_str!("../examples/varint.truth.json")).unwrap();
    cli(&["init", root_text, "Are record lengths unsigned LEB128?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Cross the 127-byte boundary",
        "-",
        "Variable-width prefixes predict boundaries",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&["trial", root_text, experiment_id, "discovery", "two files"]);
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "two held-out files",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let mut observation_ids = Vec::new();
    for (index, trial_id) in [discovery_id, discovery_id, validation_id, validation_id]
        .into_iter()
        .enumerate()
    {
        let filename = truth["cases"][index]["file"].as_str().unwrap();
        let imported = cli(&[
            "import",
            root_text,
            trial_id,
            "binary",
            path(&examples.join(filename)),
        ]);
        observation_ids.push(
            imported["event"]["observations"][0]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let probe = cli(&[
        "probe-varint",
        root_text,
        &observation_ids[0],
        "4",
        "1",
        "payload",
        "2",
    ]);
    assert_eq!(probe["status"], "complete");
    assert_eq!(probe["record_count"], 3);
    for (record, expected) in probe["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(truth["cases"][0]["records"].as_array().unwrap())
    {
        assert_eq!(record["start"], expected["start"]);
        assert_eq!(record["length_field_start"], expected["length_field_start"]);
        assert_eq!(record["length_field_end"], expected["length_field_end"]);
        assert_eq!(record["length_value"], expected["length"]);
        assert_eq!(record["logical_end"], expected["logical_end"]);
        assert_eq!(record["end"], expected["end"]);
        assert_eq!(record["source_file_offset"], expected["start"]);
    }
    assert_eq!(
        probe["records"][2]["length_field_end"].as_u64().unwrap()
            - probe["records"][2]["length_field_start"].as_u64().unwrap(),
        2
    );
    let inferred = cli(&["infer-varint", root_text, discovery_id, validation_id]);
    assert_eq!(inferred["discovery_count"], 2);
    assert_eq!(inferred["validation_count"], 2);
    assert_eq!(inferred["candidate_count"], 2);
    assert_eq!(
        inferred["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|candidate| candidate["validation_matches"] == 2)
            .count(),
        1
    );
    assert_eq!(inferred["candidates"][0]["config"], probe["config"]);
    assert_eq!(inferred["candidates"][0]["validation_matches"], 2);
    assert_eq!(inferred["candidates"][0]["discovery_multibyte_prefixes"], 2);
    assert_eq!(inferred["candidates"][1]["validation_matches"], 1);
    assert_eq!(
        inferred["candidates"][1]["validation_counterexamples"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let revision_before = cli(&["resume", root_text])["revision"].as_u64().unwrap();
    let committed = cli(&[
        "commit-varint",
        root_text,
        &observation_ids[0],
        "4",
        "1",
        "payload",
        "2",
        "varint-a-v1",
    ]);
    assert_eq!(committed["replayed"], false);
    assert_eq!(committed["revision"], revision_before + 1);
    assert_eq!(committed["run"]["records"].as_array().unwrap().len(), 3);
    let repeated = cli(&[
        "commit-varint",
        root_text,
        &observation_ids[0],
        "4",
        "1",
        "payload",
        "2",
        "varint-a-v1",
    ]);
    assert_eq!(repeated["replayed"], true);
    assert_eq!(repeated["revision"], committed["revision"]);
    assert_eq!(
        cli(&["varint-status", root_text, "varint-a-v1"])["run"],
        committed["run"]
    );
    let page = cli(&["frames", root_text, "varint-a-v1", "2", "1"]);
    assert_eq!(page["model"], "unsigned_leb128");
    assert_eq!(page["total"], 3);
    let third_id = page["frames"][0]["id"].as_str().unwrap();
    let third_span = cli(&["frame-span", root_text, third_id, "0", "3"]);
    assert_eq!(third_span["model"], "unsigned_leb128");
    assert_eq!(third_span["bytes_hex"], "938001");
    assert_eq!(
        third_span["source_file_offset"],
        truth["cases"][0]["records"][2]["start"]
    );
    assert_eq!(third_span["logical_length"], 131);
    let validation_run = cli(&[
        "commit-varint",
        root_text,
        &observation_ids[3],
        "4",
        "1",
        "payload",
        "2",
        "varint-b-v1",
    ]);
    for (set, run) in [("discovery", &committed), ("validation", &validation_run)] {
        for (index, value) in [145, 146, 147].into_iter().enumerate() {
            let frame_id = run["run"]["records"][index]["id"].as_str().unwrap();
            cli(&[
                "frame-value",
                root_text,
                frame_id,
                "record_type",
                &value.to_string(),
                set,
            ]);
        }
    }
    let field = cli(&["infer-frame-value", root_text, "record_type"]);
    assert_eq!(field["discovery_count"], 3);
    assert_eq!(field["validation_count"], 3);
    assert!(
        field["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["start"] == 0
                && candidate["end"] == 1
                && candidate["validation_matches"] == 3)
    );
    let corpus = cli(&["summary", root_text]);
    assert_eq!(corpus["counts"]["varint_runs"], 2);
    assert_eq!(corpus["counts"]["frames"], 6);
    let filter = serde_json::json!({"framing_key":"varint-a-v1"}).to_string();
    assert_eq!(
        cli(&["search-observations", root_text, &filter])["total"],
        1
    );
    let conflicting = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "commit-varint",
            root_text,
            &observation_ids[0],
            "4",
            "0",
            "payload",
            "2",
            "varint-a-v1",
        ])
        .output()
        .unwrap();
    assert!(!conflicting.status.success());
    assert!(String::from_utf8_lossy(&conflicting.stderr).contains("different arguments"));
    let report = root.join("varint-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(&report).unwrap();
    assert!(html.contains("Candidate variable-length records"));
    assert!(html.contains("varint_inferences"));
    assert!(html.contains("varint_previews"));
    assert!(html.contains("unsigned LEB128"));
    assert!(html.contains("varint-a-v1"));
    assert!(html.contains(third_id));

    let mut corrupted = fs::read(examples.join("varint_validation_a.bin")).unwrap();
    corrupted[5] = 0xff;
    let corrupted_path = root.join("corrupted-varint.bin");
    fs::write(&corrupted_path, corrupted).unwrap();
    let imported = cli(&[
        "import",
        root_text,
        validation_id,
        "binary",
        path(&corrupted_path),
    ]);
    let corrupted_id = imported["event"]["observations"][0]["id"].as_str().unwrap();
    let challenged = cli(&["infer-varint", root_text, discovery_id, validation_id]);
    assert_eq!(challenged["validation_count"], 3);
    assert_eq!(challenged["candidates"][0]["validation_matches"], 2);
    assert_eq!(
        challenged["candidates"][0]["validation_counterexamples"][0]["observation_id"],
        corrupted_id
    );
    assert_eq!(cli(&["verify", root_text])["observations"], 5);
    let events_path = root.join(".pi/events.jsonl");
    let original_events = fs::read_to_string(&events_path).unwrap();
    let altered = original_events
        .lines()
        .map(|line| {
            let mut event: Value = serde_json::from_str(line).unwrap();
            if event["event"]["type"] == "varint_committed"
                && event["event"]["run"]["key"] == "varint-a-v1"
            {
                event["event"]["run"]["records"][0]["length_value"] = serde_json::json!(99);
            }
            serde_json::to_string(&event).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&events_path, altered).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["verify", root_text])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("committed varint frame does not match source bytes")
    );
    fs::write(&events_path, original_events).unwrap();
    assert_eq!(cli(&["verify", root_text])["observations"], 5);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn committed_tcp_frames_trace_bytes_across_packets() {
    let root = workspace();
    let root_text = path(&root);
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/framed_tcp.pcap");
    let raw = fs::read(&fixture).unwrap();
    cli(&["init", root_text, "Where are TCP application records?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Split records",
        "-",
        "Length prefix tracks packet split",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "two packets",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let imported = cli(&[
        "import",
        root_text,
        trial_id,
        "pcap-tcp-stream",
        path(&fixture),
    ]);
    assert_eq!(imported["event"]["capture"]["observation_count"], 1);
    let observation = &imported["event"]["observations"][0];
    assert_eq!(observation["bytes_hex"], "03616263026465");
    assert_eq!(observation["source_spans"].as_array().unwrap().len(), 2);
    let observation_id = observation["id"].as_str().unwrap();
    let committed = cli(&[
        "commit-framing",
        root_text,
        observation_id,
        "0",
        "0",
        "1",
        "big",
        "payload",
        "1",
        "tcp-two-records",
    ]);
    assert_eq!(committed["run"]["records"].as_array().unwrap().len(), 2);
    let first_id = committed["run"]["records"][0]["id"].as_str().unwrap();
    let span = cli(&["frame-span", root_text, first_id, "0", "4"]);
    assert_eq!(span["bytes_hex"], "03616263");
    assert_eq!(span["source_file_offset"], Value::Null);
    let sources = span["source_spans"].as_array().unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["message_start"], 0);
    assert_eq!(sources[0]["message_end"], 3);
    assert_eq!(sources[1]["message_start"], 3);
    assert_eq!(sources[1]["message_end"], 4);
    for source in sources {
        let start = source["message_start"].as_u64().unwrap() as usize;
        let end = source["message_end"].as_u64().unwrap() as usize;
        let offset = source["file_offset"].as_u64().unwrap() as usize;
        assert_eq!(&raw[offset..offset + end - start], &b"\x03abc"[start..end]);
    }
    assert_eq!(cli(&["verify", root_text])["artifacts_verified"], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_infers_a_field_with_held_out_committed_frames() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&[
        "init",
        root_text,
        "Which frame byte identifies record type?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Vary payload size",
        "-",
        "Type remains at frame offset zero",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&["trial", root_text, experiment_id, "discovery", "first file"]);
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "held-out file",
    ]);
    let mut runs = Vec::new();
    for (trial, filename, key) in [
        (&discovery, "records_discovery_a.bin", "type-discovery"),
        (&validation, "records_validation_b.bin", "type-validation"),
    ] {
        let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
        let imported = cli(&[
            "import",
            root_text,
            trial_id,
            "binary",
            path(&examples.join(filename)),
        ]);
        let observation_id = imported["event"]["observations"][0]["id"].as_str().unwrap();
        runs.push(cli(&[
            "commit-framing",
            root_text,
            observation_id,
            "4",
            "1",
            "2",
            "big",
            "payload",
            "2",
            key,
        ]));
    }
    for (set, run) in [("discovery", &runs[0]), ("validation", &runs[1])] {
        for (index, value) in [160, 161, 162].into_iter().enumerate() {
            let frame_id = run["run"]["records"][index]["id"].as_str().unwrap();
            let value_text = value.to_string();
            cli(&[
                "frame-value",
                root_text,
                frame_id,
                "record_type",
                &value_text,
                set,
            ]);
        }
    }
    let inference = cli(&["infer-frame-value", root_text, "record_type"]);
    assert_eq!(inference["coordinate_system"], "frame_bytes");
    assert_eq!(inference["byte_range"], "logical_record");
    assert_eq!(inference["discovery_count"], 3);
    assert_eq!(inference["validation_count"], 3);
    assert_eq!(inference["candidate_count"], 1);
    assert_eq!(inference["candidates"][0]["start"], 0);
    assert_eq!(inference["candidates"][0]["end"], 1);
    assert_eq!(inference["candidates"][0]["validation_matches"], 3);
    assert_eq!(inference["candidates"][0]["preferred"], true);
    let report = root.join("frame-fields.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Frame fields"));
    assert!(html.contains("frame_field_inferences"));
    assert!(html.contains("record_type"));

    let last_frame = runs[1]["run"]["records"][2]["id"].as_str().unwrap();
    cli(&[
        "frame-value",
        root_text,
        last_frame,
        "record_type",
        "999",
        "validation",
    ]);
    let challenged = cli(&["infer-frame-value", root_text, "record_type"]);
    assert_eq!(challenged["candidate_count"], 1);
    assert_eq!(challenged["candidates"][0]["validation_matches"], 2);
    assert_eq!(
        challenged["candidates"][0]["counterexample_frame_ids"][0],
        last_frame
    );
    assert_eq!(challenged["preferred_candidate_count"], 0);
    assert_eq!(cli(&["resume", root_text])["frame_known_value_count"], 6);
    let corpus = cli(&["summary", root_text]);
    assert_eq!(corpus["counts"]["observations"], 2);
    assert_eq!(corpus["counts"]["frames"], 6);
    assert_eq!(corpus["counts"]["frame_known_values"], 6);
    assert_eq!(corpus["recent_trials"][0]["frames"], 3);
    let framed_query = serde_json::json!({"framing_key":"type-discovery"}).to_string();
    let framed = cli(&["search-observations", root_text, &framed_query]);
    assert_eq!(framed["total"], 1);
    assert_eq!(
        framed["observations"][0]["id"],
        runs[0]["run"]["observation_id"]
    );
    let unknown_direction = serde_json::json!({"direction":"<unknown>"}).to_string();
    assert_eq!(
        cli(&["search-observations", root_text, &unknown_direction])["total"],
        2
    );
    cli(&[
        "frame-value",
        root_text,
        last_frame,
        "record_type",
        "162",
        "validation",
    ]);
    assert_eq!(
        cli(&["infer-frame-value", root_text, "record_type"])["preferred_candidate_count"],
        1
    );
    assert_eq!(cli(&["verify", root_text])["artifacts_verified"], 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn annotated_icmp_values_locate_sequence_on_held_out_packets() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Find the controlled sequence field"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Sweep sequence",
        "-",
        "Big-endian field",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "sweep", "sequence"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcapng");
    cli(&["import", root_text, trial_id, "pcapng-icmp", path(&fixture)]);
    for (index, value) in [(0, 0), (2, 1), (4, 2), (8, 254), (10, 256)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "sequence",
            &value.to_string(),
            "discovery",
        ]);
    }
    for (index, value) in [(12, 257), (22, 65535)] {
        let id = format!("obs-000004-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "sequence",
            &value.to_string(),
            "validation",
        ]);
    }
    // An explicit correction replaces the materialized annotation while the
    // original event remains in the log.
    cli(&[
        "value",
        root_text,
        "obs-000004-0008",
        "sequence",
        "0xff",
        "discovery",
    ]);
    let result = cli(&["infer-value", root_text, "sequence"]);
    assert_eq!(result["discovery_count"], 5);
    assert_eq!(result["validation_count"], 2);
    assert_eq!(result["candidate_count"], 1);
    assert_eq!(result["candidates"][0]["start"], 6);
    assert_eq!(result["candidates"][0]["end"], 8);
    assert_eq!(result["candidates"][0]["byte_order"], "big_endian");
    assert_eq!(result["candidates"][0]["validation_matches"], 2);
    assert_eq!(cli(&["resume", root_text])["known_value_count"], 7);
    let page = cli(&["observations", root_text, "-", "8", "1"]);
    assert_eq!(page["observations"][0]["known_values"][0]["value"], 255);
    let report = root.join("report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Candidate fields"));
    assert!(html.contains("big_endian"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn controlled_intervention_locates_checksum_candidate_on_new_packets() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&[
        "init",
        root_text,
        "Which field compensates for a sequence change?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Change only the sequence",
        "-",
        "A dependent field also changes",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    for (role, factor) in [
        ("baseline", "sequence=255"),
        ("variant", "sequence=256"),
        ("discovery", "many sequences and payloads"),
        ("validation", "new identifier and payloads"),
    ] {
        cli(&["trial", root_text, experiment_id, role, factor]);
    }
    for (trial, file) in [
        ("trial-000003", "icmp_baseline_255.pcap"),
        ("trial-000004", "icmp_variant_256.pcap"),
        ("trial-000005", "icmp_echo.pcap"),
        ("trial-000006", "icmp_holdout.pcap"),
    ] {
        cli(&[
            "import",
            root_text,
            trial,
            "pcap-icmp",
            path(&examples.join(file)),
        ]);
    }
    for (index, value) in [(0, 0), (2, 1), (4, 2), (8, 255), (10, 256)] {
        let id = format!("obs-000009-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "sequence",
            &value.to_string(),
            "discovery",
        ]);
    }
    for (index, value) in [(12, 257), (22, 65535)] {
        let id = format!("obs-000009-{index:04}");
        cli(&[
            "value",
            root_text,
            &id,
            "sequence",
            &value.to_string(),
            "validation",
        ]);
    }
    let result = cli(&[
        "infer-checksum",
        root_text,
        "trial-000005",
        "trial-000006",
        "trial-000003",
        "trial-000004",
        "sequence",
    ]);
    assert_eq!(result["discovery_count"], 24);
    assert_eq!(result["validation_count"], 6);
    assert_eq!(result["duplicate_validation_count"], 0);
    assert!(result["candidate_count"].as_u64().unwrap() > 1);
    assert_eq!(result["intervention_supported_count"], 1);
    assert_eq!(result["candidates"][0]["start"], 2);
    assert_eq!(result["candidates"][0]["end"], 4);
    assert_eq!(result["candidates"][0]["byte_order"], "big_endian");
    assert_eq!(result["candidates"][0]["validation_matches"], 6);
    assert_eq!(result["candidates"][0]["intervention_pair_matches"], 2);
    let reused_holdout = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "infer-checksum",
            root_text,
            "trial-000005",
            "trial-000003",
            "trial-000003",
            "trial-000004",
            "sequence",
        ])
        .output()
        .unwrap();
    assert!(!reused_holdout.status.success());
    assert!(String::from_utf8_lossy(&reused_holdout.stderr).contains("no new message bytes"));
    assert_eq!(cli(&["verify", root_text])["observations"], 34);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replays_v1_log_and_appends_current_events() {
    let root = workspace();
    let events = root.join(".pi/events.jsonl");
    fs::create_dir_all(events.parent().unwrap()).unwrap();
    fs::write(
        &events,
        "{\"schema_version\":1,\"revision\":1,\"timestamp_ms\":0,\"event\":{\"type\":\"created\",\"question\":\"Old investigation\"}}\n",
    )
    .unwrap();
    assert_eq!(
        cli(&["resume", path(&root)])["question"],
        "Old investigation"
    );
    let appended = cli(&["hypothesis", path(&root), "A new claim"]);
    assert_eq!(appended["schema_version"], 14);
    assert_eq!(appended["revision"], 2);
    assert_eq!(
        cli(&["changes", path(&root), "0"])
            .as_array()
            .unwrap()
            .len(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn clusters_icmp_roles_before_alignment_and_exposes_members() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Group request and reply formats"]);
    let experiment = cli(&["experiment", root_text, "Inspect roles", "-", "Two shapes"]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&["trial", root_text, experiment_id, "sweep", "sequence"]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_echo.pcapng");
    cli(&["import", root_text, trial_id, "pcapng-icmp", path(&fixture)]);
    let grouped = cli(&["cluster", root_text, trial_id, "respect"]);
    let clusters = grouped["clusters"].as_array().unwrap();
    assert_eq!(clusters.len(), 2);
    assert!(clusters.iter().all(|cluster| cluster["member_count"] == 12));
    let type_values: std::collections::BTreeSet<_> = clusters
        .iter()
        .map(|cluster| {
            cluster["stable_header_bytes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|byte| byte["offset"] == 0)
                .unwrap()["value"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(type_values, [0, 8].into());
    assert!(
        clusters
            .iter()
            .all(|cluster| cluster["split_rules"][0]["kind"] == "direction")
    );
    assert_eq!(
        cli(&["cluster", root_text, trial_id, "respect"])["clusters"][0]["id"],
        clusters[0]["id"]
    );
    let first_id = clusters[0]["id"].as_str().unwrap();
    let analysis = cli(&["analyze-cluster", root_text, first_id, trial_id, "respect"]);
    assert_eq!(analysis["event"]["analysis"]["scope"]["kind"], "cluster");
    assert_eq!(
        analysis["event"]["analysis"]["scope"]["cluster_id"],
        first_id
    );
    assert_eq!(
        analysis["event"]["analysis"]["method_version"],
        "best_of_positional_and_star_v1"
    );
    assert_eq!(
        analysis["event"]["analysis"]["observation_ids"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    let ignored = cli(&["cluster", root_text, trial_id, "ignore"]);
    assert_eq!(ignored["clusters"].as_array().unwrap().len(), 1);
    let report = root.join("report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Candidate format groups"));
    assert!(html.contains(first_id));
    cli(&["import", root_text, trial_id, "pcapng-icmp", path(&fixture)]);
    let stale = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["analyze-cluster", root_text, first_id, trial_id, "respect"])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("unknown cluster"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_check_format_groups_on_held_out_messages() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Do candidate format groups generalize?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Vary message kind",
        "-",
        "Header groups predict held-out messages",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "six messages",
    ]);
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "two known and one novel kind",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let discovery_file = root.join("discovery.hex");
    fs::write(
        &discovery_file,
        "01a0b0c01001\n01a1b1c11002\n01a2b2c21003\n02d0e0f02004\n02d1e1f12005\n02d2e2f22006\n",
    )
    .unwrap();
    let validation_file = root.join("validation.hex");
    fs::write(
        &validation_file,
        "01a3b3c31004\n02d3e3f32007\n03f0f0f03008\n",
    )
    .unwrap();
    cli(&[
        "import",
        root_text,
        discovery_id,
        "hex",
        path(&discovery_file),
    ]);
    let imported = cli(&[
        "import",
        root_text,
        validation_id,
        "hex",
        path(&validation_file),
    ]);
    let novel_id = imported["event"]["observations"][2]["id"].as_str().unwrap();
    let result = cli(&[
        "validate-clusters",
        root_text,
        discovery_id,
        validation_id,
        "ignore",
    ]);
    assert_eq!(result["discovery_count"], 6);
    assert_eq!(result["validation_count"], 3);
    assert_eq!(result["cluster_count"], 2);
    assert_eq!(result["assigned_count"], 2);
    assert_eq!(result["unassigned_count"], 1);
    assert_eq!(result["observations"][0]["status"], "assigned");
    assert_eq!(result["observations"][1]["status"], "assigned");
    assert_ne!(
        result["observations"][0]["assigned_cluster_id"],
        result["observations"][1]["assigned_cluster_id"]
    );
    assert_eq!(result["observations"][2]["status"], "unassigned");
    assert_eq!(result["observations"][2]["observation_id"], novel_id);
    assert_eq!(result["observations"][2]["rejected_cluster_count"], 2);
    assert!(
        result["observations"][2]["rejections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|rejected| rejected["stable_byte_mismatch_offsets"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(0)))
    );
    let report = root.join("cluster-validation.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Held-out grouping"));
    assert!(html.contains("cluster_validations"));
    assert!(html.contains(novel_id));
    let small_experiment = cli(&[
        "experiment",
        root_text,
        "Repeat a single sample",
        "-",
        "A lone sample is insufficient",
    ]);
    let small_experiment_id = small_experiment["event"]["experiment"]["id"]
        .as_str()
        .unwrap();
    let small_discovery = cli(&[
        "trial",
        root_text,
        small_experiment_id,
        "discovery",
        "one sample",
    ]);
    let small_validation = cli(&[
        "trial",
        root_text,
        small_experiment_id,
        "validation",
        "one repeat",
    ]);
    let small_discovery_id = small_discovery["event"]["trial"]["id"].as_str().unwrap();
    let small_validation_id = small_validation["event"]["trial"]["id"].as_str().unwrap();
    let small_file = root.join("one.hex");
    fs::write(&small_file, "0102030405\n").unwrap();
    cli(&[
        "import",
        root_text,
        small_discovery_id,
        "hex",
        path(&small_file),
    ]);
    cli(&[
        "import",
        root_text,
        small_validation_id,
        "hex",
        path(&small_file),
    ]);
    let small = cli(&[
        "validate-clusters",
        root_text,
        small_discovery_id,
        small_validation_id,
        "ignore",
    ]);
    assert_eq!(small["assigned_count"], 0);
    assert_eq!(small["unassigned_count"], 1);
    assert_eq!(
        small["observations"][0]["rejections"][0]["insufficient_discovery_members"],
        true
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_event_tail_can_be_inspected_and_recovered_without_hiding_complete_corruption() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can the investigation resume after a partial write?",
    ]);
    cli(&["hypothesis", root_text, "first event"]);
    let event_path = root.join(".pi/events.jsonl");
    let original = fs::read(&event_path).unwrap();
    let last_start = original[..original.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap()
        + 1;
    let partial = &original[last_start..last_start + 20];
    let mut interrupted = original[..last_start].to_vec();
    interrupted.extend_from_slice(partial);
    fs::write(&event_path, &interrupted).unwrap();
    let blocked = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["resume", root_text])
        .output()
        .unwrap();
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("unterminated final line"));
    let preview = cli(&["recover-tail", root_text]);
    assert_eq!(preview["action"], "truncate_partial_tail");
    assert_eq!(preview["applied"], false);
    assert_eq!(preview["last_valid_revision"], 1);
    assert_eq!(preview["tail_bytes"], partial.len());
    assert_eq!(fs::read(&event_path).unwrap(), interrupted);
    let repaired = cli(&["recover-tail", root_text, "--apply"]);
    assert_eq!(repaired["action"], "truncate_partial_tail");
    assert_eq!(repaired["applied"], true);
    let backup = repaired["backup_path"].as_str().unwrap();
    assert_eq!(fs::read(backup).unwrap(), partial);
    assert_eq!(cli(&["resume", root_text])["revision"], 1);
    assert_eq!(
        cli(&["hypothesis", root_text, "repeated event"])["revision"],
        2
    );

    let with_newline = fs::read(&event_path).unwrap();
    assert_eq!(with_newline.last(), Some(&b'\n'));
    fs::write(&event_path, &with_newline[..with_newline.len() - 1]).unwrap();
    let unterminated = fs::read(&event_path).unwrap();
    let blocked_append = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["hypothesis", root_text, "must not glue to the prior event"])
        .output()
        .unwrap();
    assert!(!blocked_append.status.success());
    assert_eq!(fs::read(&event_path).unwrap(), unterminated);
    let preview = cli(&["recover-tail", root_text]);
    assert_eq!(preview["action"], "append_newline");
    assert_eq!(preview["recovered_revision"], 2);
    let repaired = cli(&["recover-tail", root_text, "--apply"]);
    assert_eq!(repaired["action"], "append_newline");
    assert!(repaired["backup_path"].is_null());
    assert_eq!(fs::read(&event_path).unwrap(), with_newline);
    assert_eq!(cli(&["resume", root_text])["revision"], 2);
    assert_eq!(cli(&["recover-tail", root_text])["action"], "clean");

    let lines: Vec<_> = std::str::from_utf8(&with_newline)
        .unwrap()
        .lines()
        .collect();
    let mut invalid_event: Value = serde_json::from_str(lines[1]).unwrap();
    invalid_event["revision"] = serde_json::json!(99);
    let invalid_unterminated = format!("{}\n{}", lines[0], invalid_event);
    fs::write(&event_path, &invalid_unterminated).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["recover-tail", root_text, "--apply"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unterminated event is invalid"));
    assert_eq!(
        fs::read(&event_path).unwrap(),
        invalid_unterminated.as_bytes()
    );
    fs::write(&event_path, &with_newline).unwrap();

    let mut corrupt_complete = with_newline.clone();
    corrupt_complete.extend_from_slice(b"{broken\n");
    fs::write(&event_path, &corrupt_complete).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["recover-tail", root_text, "--apply"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert_eq!(fs::read(&event_path).unwrap(), corrupt_complete);
    fs::write(&event_path, with_newline).unwrap();
    assert_eq!(cli(&["verify", root_text])["revision"], 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_preserves_a_complete_first_event_and_refuses_to_discard_a_partial_one() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can the first event survive a missing newline?",
    ]);
    let event_path = root.join(".pi/events.jsonl");
    let original = fs::read(&event_path).unwrap();
    fs::write(&event_path, &original[..original.len() - 1]).unwrap();
    assert_eq!(
        cli(&["recover-tail", root_text])["action"],
        "append_newline"
    );
    assert_eq!(
        cli(&["recover-tail", root_text, "--apply"])["recovered_revision"],
        1
    );
    assert_eq!(fs::read(&event_path).unwrap(), original);
    assert_eq!(cli(&["verify", root_text])["revision"], 1);

    let partial = &original[..20];
    fs::write(&event_path, partial).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["recover-tail", root_text, "--apply"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("first event is incomplete"));
    assert_eq!(fs::read(&event_path).unwrap(), partial);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn keyed_action_and_capture_tags_link_untimed_agent_capture_without_duplicate_events() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Which generated messages came from this experiment step?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Vary an input",
        "-",
        "Capture scope is traceable",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "first input",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let source = root.join("messages.hex");
    fs::write(&source, "aabb01\naabb02\n").unwrap();
    let marked = cli(&[
        "mark-keyed",
        root_text,
        trial_id,
        "stimulus",
        "first input",
        "step-a",
        "1000",
    ]);
    assert_eq!(marked["replayed"], false);
    assert_eq!(marked["action"]["timestamp_ns"], 1000);
    let action_id = marked["action"]["id"].as_str().unwrap();
    let repeated_mark = cli(&[
        "mark-keyed",
        root_text,
        trial_id,
        "stimulus",
        "first input",
        "step-a",
    ]);
    assert_eq!(repeated_mark["replayed"], true);
    assert_eq!(repeated_mark["action"]["id"], action_id);
    let conflicting_mark = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "mark-keyed",
            root_text,
            trial_id,
            "stimulus",
            "different input",
            "step-a",
        ])
        .output()
        .unwrap();
    assert!(!conflicting_mark.status.success());
    let captured = cli(&[
        "capture-command",
        root_text,
        trial_id,
        "hex",
        "step-a-capture",
        "2000",
        "--",
        "/bin/cat",
        path(&source),
    ]);
    assert_eq!(captured["status"], "completed");
    let capture_id = captured["capture"]["id"].as_str().unwrap();
    assert_eq!(captured["observation_ids"].as_array().unwrap().len(), 2);
    let revision_before = cli(&["resume", root_text])["revision"].as_u64().unwrap();
    let tagged = cli(&[
        "tag-capture",
        root_text,
        action_id,
        capture_id,
        "capture_scope",
        "first input",
        "step-a-tags",
    ]);
    assert_eq!(tagged["replayed"], false);
    assert_eq!(tagged["revision"], revision_before + 1);
    assert_eq!(
        tagged["batch"]["observation_ids"],
        captured["observation_ids"]
    );
    assert_eq!(tagged["batch"]["tag_ids"].as_array().unwrap().len(), 2);
    let repeated_tag = cli(&[
        "tag-capture",
        root_text,
        action_id,
        capture_id,
        "capture_scope",
        "first input",
        "step-a-tags",
    ]);
    assert_eq!(repeated_tag["replayed"], true);
    assert_eq!(repeated_tag["revision"], tagged["revision"]);
    assert_eq!(
        cli(&["capture-tag-status", root_text, "step-a-tags"])["batch"],
        tagged["batch"]
    );
    let corpus = cli(&["summary", root_text]);
    assert_eq!(corpus["counts"]["capture_tag_batches"], 1);
    assert_eq!(corpus["counts"]["tagged_observations"], 2);
    let resumed = cli(&["resume", root_text]);
    assert_eq!(resumed["capture_tag_batches"][0]["key"], "step-a-tags");
    let conflict = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "tag-capture",
            root_text,
            action_id,
            capture_id,
            "capture_scope",
            "different input",
            "step-a-tags",
        ])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    let other_trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "other input",
    ]);
    let other_trial_id = other_trial["event"]["trial"]["id"].as_str().unwrap();
    let imported = cli(&["import", root_text, other_trial_id, "hex", path(&source)]);
    let other_capture_id = imported["event"]["capture"]["id"].as_str().unwrap();
    let wrong_trial = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "tag-capture",
            root_text,
            action_id,
            other_capture_id,
            "capture_scope",
            "first input",
            "wrong-trial",
        ])
        .output()
        .unwrap();
    assert!(!wrong_trial.status.success());
    assert!(String::from_utf8_lossy(&wrong_trial.stderr).contains("same trial"));
    let report = root.join("capture-tags.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Capture scope tags"));
    assert!(html.contains("step-a-tags"));
    assert_eq!(cli(&["verify", root_text])["observations"], 4);
    let events_path = root.join(".pi/events.jsonl");
    let original_events = fs::read_to_string(&events_path).unwrap();
    let tampered = original_events
        .lines()
        .map(|line| {
            let mut event: Value = serde_json::from_str(line).unwrap();
            if event["event"]["type"] == "capture_tagged" {
                event["event"]["batch"]["observation_ids"][0] = serde_json::json!("obs-wrong");
            }
            serde_json::to_string(&event).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&events_path, tampered).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["verify", root_text])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("capture tag selection"));
    fs::write(&events_path, original_events).unwrap();
    assert_eq!(cli(&["verify", root_text])["observations"], 4);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn capture_step_retries_after_capture_and_does_not_repeat_completed_work() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can an agent repeat one capture step safely?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Change payload",
        "-",
        "Capture each variation",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "payload one",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let source = root.join("step.hex");
    fs::write(&source, "aabb01\naabb02\n").unwrap();
    cli(&[
        "mark-keyed",
        root_text,
        trial_id,
        "stimulus",
        "payload one",
        "sweep-1:action",
    ]);
    cli(&[
        "capture-command",
        root_text,
        trial_id,
        "hex",
        "sweep-1:capture",
        "2000",
        "--",
        "/bin/cat",
        path(&source),
    ]);
    let arguments = [
        "capture-step",
        root_text,
        trial_id,
        "stimulus",
        "payload one",
        "capture_scope",
        "payload one",
        "sweep-1",
        "hex",
        "2000",
        "--",
        "/bin/cat",
        path(&source),
    ];
    let completed = cli(&arguments);
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["replayed"], false);
    assert_eq!(completed["observation_ids"].as_array().unwrap().len(), 2);
    assert_eq!(
        completed["tag_batch"]["observation_ids"],
        completed["observation_ids"]
    );
    let revision = completed["revision"].as_u64().unwrap();
    let repeated = cli(&arguments);
    assert_eq!(repeated["replayed"], true);
    assert_eq!(repeated["revision"], revision);
    assert_eq!(repeated["capture"]["id"], completed["capture"]["id"]);
    let direct = cli(&[
        "capture-step",
        root_text,
        trial_id,
        "stimulus",
        "payload two",
        "capture_scope",
        "payload two",
        "sweep-2",
        "hex",
        "2000",
        "--",
        "/bin/cat",
        path(&source),
    ]);
    assert_eq!(direct["status"], "completed");
    assert_eq!(direct["replayed"], false);
    let corpus = cli(&["summary", root_text]);
    assert_eq!(corpus["counts"]["captures"], 2);
    assert_eq!(corpus["counts"]["actions"], 2);
    assert_eq!(corpus["counts"]["capture_tag_batches"], 2);
    assert_eq!(cli(&["verify", root_text])["observations"], 4);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn capture_step_pages_large_capture_tags_and_resumes_after_partial_tagging() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can every observation be tagged after a retry?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Sweep ICMP sequence values",
        "-",
        "Keep acquisition scope for all observations",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "512 request and reply pairs",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/icmp_sweep_512.pcap");
    let arguments = [
        "capture-step",
        root_text,
        trial_id,
        "stimulus",
        "generated 512 ICMP sequences",
        "capture_scope",
        "value sweep",
        "large-icmp-step",
        "pcap-icmp",
        "5000",
        "--",
        "/bin/cat",
        path(&source),
    ];
    let first = cli(&arguments);
    assert_eq!(first["status"], "completed");
    assert_eq!(first["replayed"], false);
    assert!(first["tag_batch"].is_null());
    assert_eq!(first["observation_ids"].as_array().unwrap().len(), 1024);
    assert_eq!(first["tag_batches"].as_array().unwrap().len(), 2);
    let activity_first = cli(&["activity", root_text, "4", "1", "8"]);
    assert_eq!(activity_first["current_revision"], 8);
    assert_eq!(activity_first["through_revision"], 8);
    assert_eq!(activity_first["events"][0]["kind"], "capture_run_reserved");
    assert_eq!(activity_first["next_after_revision"], 5);
    let activity_capture = cli(&["activity", root_text, "5", "1", "8"]);
    assert_eq!(activity_capture["events"][0]["kind"], "capture_imported");
    assert_eq!(
        activity_capture["events"][0]["subject_id"],
        first["capture"]["id"]
    );
    assert_eq!(
        activity_capture["events"][0]["details"]["observation_count"],
        1024
    );
    assert_eq!(
        activity_capture["events"][0]["details"]["first_observation_ids"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        activity_capture["events"][0]["details"]["observation_ids_omitted"],
        1021
    );
    assert!(activity_capture.to_string().len() < 1000);
    let pinned_capture = cli(&["activity", root_text, "5", "1", "6"]);
    assert_eq!(pinned_capture["current_revision"], 8);
    assert_eq!(pinned_capture["through_revision"], 6);
    assert_eq!(pinned_capture["next_after_revision"], Value::Null);
    assert_eq!(
        cli(&["span", root_text, "obs-000006-0510", "6", "8"])["bytes_hex"],
        "00ff"
    );
    assert_eq!(
        cli(&["span", root_text, "obs-000006-0512", "6", "8"])["bytes_hex"],
        "0100"
    );
    assert_eq!(
        cli(&["span", root_text, "obs-000006-1022", "6", "8"])["bytes_hex"],
        "01ff"
    );
    assert_eq!(first["tag_batches"][0]["start_index"], 0);
    assert_eq!(
        first["tag_batches"][0]["tag_ids"].as_array().unwrap().len(),
        1000
    );
    assert_eq!(first["tag_batches"][1]["start_index"], 1000);
    assert_eq!(
        first["tag_batches"][1]["tag_ids"].as_array().unwrap().len(),
        24
    );
    let revision = first["revision"].as_u64().unwrap();
    let repeated = cli(&arguments);
    assert_eq!(repeated["replayed"], true);
    assert_eq!(repeated["revision"], revision);
    assert_eq!(
        cli(&["summary", root_text])["counts"]["tagged_observations"],
        1024
    );

    let overlapping = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "tag-capture",
            root_text,
            first["action"]["id"].as_str().unwrap(),
            first["capture"]["id"].as_str().unwrap(),
            "capture_scope",
            "value sweep",
            "overlap",
            "999",
            "2",
        ])
        .output()
        .unwrap();
    assert!(!overlapping.status.success());
    assert!(String::from_utf8_lossy(&overlapping.stderr).contains("duplicate capture tag batch"));
    assert_eq!(cli(&["resume", root_text])["revision"], revision);

    let events_path = root.join(".pi/events.jsonl");
    let complete = fs::read_to_string(&events_path).unwrap();
    let mut lines: Vec<_> = complete.lines().collect();
    let last: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["event"]["type"], "capture_tagged");
    lines.pop();
    fs::write(&events_path, lines.join("\n") + "\n").unwrap();
    assert_eq!(
        cli(&["summary", root_text])["counts"]["tagged_observations"],
        1000
    );
    let resumed = cli(&arguments);
    assert_eq!(resumed["replayed"], false);
    assert_eq!(resumed["revision"], revision);
    assert_eq!(
        resumed["tag_batches"][0]["id"],
        first["tag_batches"][0]["id"]
    );
    assert_eq!(
        resumed["tag_batches"][1]["id"],
        first["tag_batches"][1]["id"]
    );
    assert_eq!(cli(&["verify", root_text])["observations"], 1024);

    let valid = fs::read_to_string(&events_path).unwrap();
    let tampered = valid
        .lines()
        .map(|line| {
            let mut event: Value = serde_json::from_str(line).unwrap();
            if event["event"]["type"] == "capture_tagged"
                && event["event"]["batch"]["start_index"] == 0
            {
                event["event"]["batch"]["start_index"] = serde_json::json!(1);
            }
            serde_json::to_string(&event).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&events_path, tampered).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["verify", root_text])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("capture tag selection"));
    fs::write(&events_path, valid).unwrap();
    assert_eq!(cli(&["verify", root_text])["observations"], 1024);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn large_icmp_trials_disclose_sampling_and_validate_new_sequence_values() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Do ICMP format groups survive new sequences?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Sweep sequence values",
        "-",
        "Request and reply formats persist across the boundary",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "sequences 0 through 511",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "sequences 512 through 1023",
    ]);
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&[
        "import",
        root_text,
        discovery_id,
        "pcap-icmp",
        path(&fixtures.join("icmp_sweep_512.pcap")),
    ]);
    cli(&[
        "import",
        root_text,
        validation_id,
        "pcap-icmp",
        path(&fixtures.join("icmp_sweep_512_holdout.pcap")),
    ]);
    let clustered = cli(&["cluster", root_text, discovery_id, "respect"]);
    assert_eq!(
        clustered["method"],
        "direction_then_correlated_discriminator_v2"
    );
    assert_eq!(clustered["selected_observation_count"], 1024);
    assert_eq!(clustered["observation_count"], 512);
    assert_eq!(
        clustered["sampling_method"],
        "direction_length_stratified_hash_v1"
    );
    assert_eq!(clustered["sampling_strata_count"], 2);
    assert_eq!(clustered["clusters"].as_array().unwrap().len(), 2);
    for cluster in clustered["clusters"].as_array().unwrap() {
        assert_eq!(cluster["member_count"], 256);
    }
    assert_eq!(
        cli(&["cluster", root_text, discovery_id, "respect"]),
        clustered
    );
    let checked = cli(&[
        "validate-clusters",
        root_text,
        discovery_id,
        validation_id,
        "respect",
    ]);
    assert_eq!(checked["method"], "stable_header_and_medoid_held_out_v4");
    assert_eq!(checked["discovery_total"], 1024);
    assert_eq!(checked["discovery_count"], 512);
    assert_eq!(checked["validation_total"], 1024);
    assert_eq!(checked["validation_count"], 1024);
    assert_eq!(checked["assigned_count"], 1024);
    assert_eq!(checked["ambiguous_count"], 0);
    assert_eq!(checked["unassigned_count"], 0);
    assert_eq!(checked["validation_sampling_method"], "all");
    assert_eq!(checked["reported_observation_count"], 512);
    assert_eq!(checked["omitted_observation_count"], 512);
    assert_eq!(
        checked["detail_selection_method"],
        "counterexamples_then_hash_v1"
    );
    let report = root.join("large-clusters.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("selected observations"));
    assert!(html.contains("evaluated held-out observations"));
    assert_eq!(cli(&["verify", root_text])["observations"], 2048);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn full_held_out_evaluation_reports_a_rare_late_counterexample() {
    let root = workspace();
    let root_text = path(&root);
    cli(&[
        "init",
        root_text,
        "Can a rare held-out packet challenge a group?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Sweep with a novel held-out packet",
        "-",
        "Most messages retain the format, one does not",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "sequences 0 through 511",
    ]);
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "new sequences plus novel identifier",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&[
        "import",
        root_text,
        discovery_id,
        "pcap-icmp",
        path(&fixtures.join("icmp_sweep_512.pcap")),
    ]);
    let mut held_out = fs::read(fixtures.join("icmp_sweep_512_holdout.pcap")).unwrap();
    let novel = fs::read(fixtures.join("icmp_holdout.pcap")).unwrap();
    let packet_length = u32::from_le_bytes(novel[32..36].try_into().unwrap()) as usize;
    let mut record = novel[24..40 + packet_length].to_vec();
    record[..4].copy_from_slice(&1_722_000_000_u32.to_le_bytes());
    held_out.extend(record);
    let validation_file = root.join("held-out-with-one-novel.pcap");
    fs::write(&validation_file, held_out).unwrap();
    let imported = cli(&[
        "import",
        root_text,
        validation_id,
        "pcap-icmp",
        path(&validation_file),
    ]);
    let rare_id = imported["event"]["observations"].as_array().unwrap()[1024]["id"]
        .as_str()
        .unwrap();
    let checked = cli(&[
        "validate-clusters",
        root_text,
        discovery_id,
        validation_id,
        "respect",
    ]);
    assert_eq!(checked["validation_total"], 1025);
    assert_eq!(checked["validation_count"], 1025);
    assert_eq!(checked["validation_sampling_method"], "all");
    assert_eq!(checked["assigned_count"], 1024);
    assert_eq!(checked["ambiguous_count"], 0);
    assert_eq!(checked["unassigned_count"], 1);
    assert_eq!(checked["reported_observation_count"], 512);
    assert_eq!(checked["reported_counterexample_count"], 1);
    assert_eq!(checked["omitted_observation_count"], 513);
    let rare = checked["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|observation| observation["observation_id"] == rare_id)
        .unwrap();
    assert_eq!(rare["status"], "unassigned");
    assert_eq!(rare["rejected_cluster_count"], 2);
    assert_eq!(cli(&["verify", root_text])["observations"], 2049);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_page_provisional_exchanges_across_icmp_and_udp() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Which messages may be replies?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Inspect reciprocal traffic",
        "-",
        "Time and endpoint metadata identify candidate exchanges",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let trial = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "two captures",
    ]);
    let trial_id = trial["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let icmp = cli(&[
        "import",
        root_text,
        trial_id,
        "pcap-icmp",
        path(&fixtures.join("icmp_sweep_512.pcap")),
    ]);
    let icmp_id = icmp["event"]["capture"]["id"].as_str().unwrap();
    let dns = cli(&[
        "import",
        root_text,
        trial_id,
        "pcap-udp",
        path(&fixtures.join("dns_udp.pcap")),
    ]);
    let dns_id = dns["event"]["capture"]["id"].as_str().unwrap();
    let first = cli(&["pair-exchanges", root_text, icmp_id, "1000", "0", "5"]);
    assert_eq!(first["method"], "unique_reciprocal_predecessor_v1");
    assert_eq!(first["pair_count"], 512);
    assert_eq!(first["ambiguous_count"], 0);
    assert_eq!(first["unpaired_count"], 0);
    assert_eq!(first["pairs"].as_array().unwrap().len(), 5);
    assert_eq!(first["next_pair_offset"], 5);
    assert_eq!(
        first["pairs"][0]["earlier_observation_id"],
        "obs-000004-0000"
    );
    assert_eq!(first["pairs"][0]["later_observation_id"], "obs-000004-0001");
    assert_eq!(first["pairs"][0]["lag_ns"], "50000000");
    assert!(
        first["orientation_summaries"][0]["varying_equal_ranges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|range| range["start"] == 6 && range["end"] == 8)
    );
    let last = cli(&["pair-exchanges", root_text, icmp_id, "1000", "510", "5"]);
    assert_eq!(last["pairs"].as_array().unwrap().len(), 2);
    assert!(last["next_pair_offset"].is_null());
    assert_eq!(
        last["pairs"][1]["earlier_observation_id"],
        "obs-000004-1022"
    );
    let too_short = cli(&["pair-exchanges", root_text, icmp_id, "10"]);
    assert_eq!(too_short["pair_count"], 0);
    assert_eq!(too_short["unpaired_count"], 1024);
    let dns_pairs = cli(&["pair-exchanges", root_text, dns_id]);
    assert_eq!(dns_pairs["pair_count"], 6);
    assert_eq!(dns_pairs["ambiguous_count"], 0);
    assert_eq!(dns_pairs["pairs"][0]["source_port"], 40000);
    assert_eq!(dns_pairs["pairs"][0]["destination_port"], 53);
    assert!(
        dns_pairs["orientation_summaries"][0]["varying_equal_ranges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|range| range["start"] == 0 && range["end"] == 2)
    );
    let report = root.join("exchanges.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Candidate exchanges"));
    assert!(html.contains("varying_equal_ranges"));
    assert!(html.contains(icmp_id));
    assert_eq!(cli(&["verify", root_text])["observations"], 1036);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_can_validate_exchange_bytes_on_distinct_trials_and_inspect_counterexamples() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "Which paired bytes persist?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Test candidate ICMP exchange bytes",
        "-",
        "Sequence bytes agree across distinct captures",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "sequence 0 to 511",
    ]);
    let discovery_trial = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "sequence 512 to 1023",
    ]);
    let validation_trial = validation["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let discovery_capture = cli(&[
        "import",
        root_text,
        discovery_trial,
        "pcap-icmp",
        path(&fixtures.join("icmp_sweep_512.pcap")),
    ]);
    let discovery_id = discovery_capture["event"]["capture"]["id"]
        .as_str()
        .unwrap();
    let validation_capture = cli(&[
        "import",
        root_text,
        validation_trial,
        "pcap-icmp",
        path(&fixtures.join("icmp_sweep_512_holdout.pcap")),
    ]);
    let validation_id = validation_capture["event"]["capture"]["id"]
        .as_str()
        .unwrap();
    let supported = cli(&["validate-exchanges", root_text, discovery_id, validation_id]);
    assert_eq!(supported["discovery_pair_count"], 512);
    assert_eq!(supported["validation_pair_count"], 512);
    assert_eq!(supported["candidate_offset_count"], 3);
    assert_eq!(supported["supported_offset_count"], 3);
    assert_eq!(supported["contradicted_offset_count"], 0);
    assert_eq!(supported["checks"][0]["tested_pair_count"], 512);

    let changed = cli(&[
        "import",
        root_text,
        validation_trial,
        "pcap-icmp",
        path(&fixtures.join("icmp_mismatched_reply.pcap")),
    ]);
    let changed_id = changed["event"]["capture"]["id"].as_str().unwrap();
    let result = cli(&["validate-exchanges", root_text, discovery_id, changed_id]);
    assert_eq!(result["validation_pair_count"], 3);
    assert_eq!(result["supported_offset_count"], 1);
    assert_eq!(result["contradicted_offset_count"], 2);
    let checks = result["checks"].as_array().unwrap();
    let sequence_low_byte = checks.iter().find(|check| check["offset"] == 7).unwrap();
    assert_eq!(sequence_low_byte["status"], "contradicted");
    assert_eq!(sequence_low_byte["matching_pair_count"], 2);
    assert_eq!(sequence_low_byte["contradicting_pair_count"], 1);
    assert_eq!(sequence_low_byte["counterexamples"][0]["earlier_byte"], 2);
    assert_eq!(sequence_low_byte["counterexamples"][0]["later_byte"], 3);
    assert_eq!(
        sequence_low_byte["counterexamples"][0]["reason"],
        "bytes_differ"
    );

    let same_trial = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["validate-exchanges", root_text, validation_id, changed_id])
        .output()
        .unwrap();
    assert!(!same_trial.status.success());
    assert!(String::from_utf8_lossy(&same_trial.stderr).contains("distinct trials"));
    let report = root.join("held-out-exchanges.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Held-out exchange bytes"));
    assert!(html.contains("exchange_validations"));
    assert!(html.contains("held_out_varying_equal_bytes_v1"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn held_out_delimiter_inference_rejects_strict_crlf_on_lf_records() {
    let root = workspace();
    let root_text = path(&root);
    cli(&["init", root_text, "How are records terminated?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Test delimiter changes",
        "-",
        "A byte terminator persists on held-out records",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "CRLF records",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "CRLF and LF records",
    ]);
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let truth: Value =
        serde_json::from_slice(&fs::read(fixtures.join("delimiter.truth.json")).unwrap()).unwrap();
    let mut observation_ids = Vec::new();
    for (trial_id, filename) in [
        (discovery_id, "delimiter_discovery_a.bin"),
        (discovery_id, "delimiter_discovery_b.bin"),
        (validation_id, "delimiter_validation_a.bin"),
        (validation_id, "delimiter_validation_b.bin"),
    ] {
        let imported = cli(&[
            "import",
            root_text,
            trial_id,
            "binary",
            path(&fixtures.join(filename)),
        ]);
        observation_ids.push(
            imported["event"]["observations"][0]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let probe = cli(&[
        "probe-delimiter",
        root_text,
        &observation_ids[0],
        "0",
        "0D0A",
    ]);
    assert_eq!(probe["status"], "complete");
    assert_eq!(probe["config"]["delimiter_hex"], "0d0a");
    assert_eq!(probe["record_count"], 3);
    for (actual, expected) in probe["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(truth["cases"][0]["records"].as_array().unwrap())
    {
        assert_eq!(actual["start"], expected["start"]);
        assert_eq!(actual["payload_end"], expected["payload_end"]);
        assert_eq!(actual["end"], expected["end"]);
        assert_eq!(actual["source_file_offset"], expected["start"]);
    }
    let lf_probe = cli(&["probe-delimiter", root_text, &observation_ids[3], "0", "0a"]);
    assert_eq!(lf_probe["status"], "complete");
    for (actual, expected) in lf_probe["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(truth["cases"][3]["records"].as_array().unwrap())
    {
        assert_eq!(actual["start"], expected["start"]);
        assert_eq!(actual["payload_end"], expected["payload_end"]);
        assert_eq!(actual["end"], expected["end"]);
    }
    let inferred = cli(&["infer-delimiter", root_text, discovery_id, validation_id]);
    assert_eq!(inferred["discovery_count"], 2);
    assert_eq!(inferred["validation_count"], 2);
    let candidates = inferred["candidates"].as_array().unwrap();
    let lf = candidates
        .iter()
        .find(|candidate| {
            candidate["config"]["start_offset"] == 0 && candidate["config"]["delimiter_hex"] == "0a"
        })
        .unwrap();
    assert_eq!(lf["validation_matches"], 2);
    let crlf = candidates
        .iter()
        .find(|candidate| {
            candidate["config"]["start_offset"] == 0
                && candidate["config"]["delimiter_hex"] == "0d0a"
        })
        .unwrap();
    assert_eq!(crlf["validation_matches"], 1);
    assert_eq!(
        crlf["validation_counterexamples"][0]["observation_id"],
        observation_ids[3]
    );
    let review = cli(&["review-trials", root_text, discovery_id, validation_id]);
    assert_eq!(review["prediction_assessed"], false);
    assert_eq!(review["discovery_capture_count"], 2);
    assert_eq!(review["validation_observation_count"], 2);
    let delimiter_method = review["methods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|method| method["method"] == "delimiter")
        .unwrap();
    assert_eq!(delimiter_method["candidate_count"], 3);
    assert_eq!(delimiter_method["fully_validated_reported_count"], 1);
    assert_eq!(delimiter_method["best_reported_validation_matches"], 2);
    assert_eq!(
        review["grouping"]["status"],
        "insufficient_discovery_members"
    );
    assert!(
        review["next_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| { action["kind"] == "capture_grouping_support" })
    );
    assert!(
        review["next_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| {
                action["kind"] == "inspect_model_counterexamples"
                    && action["observation_ids"]
                        .as_array()
                        .unwrap()
                        .contains(&Value::String(observation_ids[3].clone()))
            })
    );
    let report = root.join("delimiter-report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Candidate delimiter records"));
    assert!(!html.contains("\"delimiter_inferences\":[]"));
    assert!(html.contains("delimiterCandidates"));
    assert!(html.contains("Trial evidence review"));
    assert!(html.contains("\"trial_reviews\":[{"));
    let mut runs = Vec::new();
    for (observation_id, key) in [
        (&observation_ids[0], "delimiter-discovery"),
        (&observation_ids[2], "delimiter-validation"),
    ] {
        runs.push(cli(&[
            "commit-delimiter",
            root_text,
            observation_id,
            "0",
            "0D0A",
            key,
        ]));
    }
    assert_eq!(runs[0]["run"]["config"]["delimiter_hex"], "0d0a");
    assert_eq!(runs[0]["run"]["records"][0]["logical_end"], 1);
    let replay = cli(&[
        "commit-delimiter",
        root_text,
        &observation_ids[0],
        "0",
        "0d0a",
        "delimiter-discovery",
    ]);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["run"]["id"], runs[0]["run"]["id"]);
    let changed_key_use = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "commit-delimiter",
            root_text,
            &observation_ids[0],
            "0",
            "0a",
            "delimiter-discovery",
        ])
        .output()
        .unwrap();
    assert!(!changed_key_use.status.success());
    assert_eq!(
        cli(&["delimiter-status", root_text, "delimiter-discovery"])["run"]["id"],
        runs[0]["run"]["id"]
    );
    let run_page = cli(&["frame-runs", root_text, "-", "-", "0", "1"]);
    assert_eq!(run_page["total"], 2);
    assert_eq!(run_page["next_offset"], 1);
    assert_eq!(run_page["frame_runs"][0]["key"], "delimiter-validation");
    let discovery_runs = cli(&[
        "frame-runs",
        root_text,
        discovery_id,
        "delimiter",
        "0",
        "10",
    ]);
    assert_eq!(discovery_runs["total"], 1);
    assert_eq!(
        discovery_runs["frame_runs"][0]["key"],
        "delimiter-discovery"
    );
    assert_eq!(discovery_runs["frame_runs"][0]["record_count"], 3);
    assert_eq!(
        discovery_runs["frame_runs"][0]["config"]["delimiter_hex"],
        "0d0a"
    );
    assert_eq!(
        discovery_runs["frame_runs"][0]["first_frame_ids"][0],
        runs[0]["run"]["records"][0]["id"]
    );
    let grouped = cli(&["cluster-frames", root_text, "delimiter", "-", "ignore"]);
    assert_eq!(grouped["coordinate_system"], "logical_frame_bytes");
    assert_eq!(grouped["selected_frame_count"], 6);
    assert_eq!(grouped["frame_count"], 6);
    assert_eq!(grouped["clusters"][0]["member_count"], 6);
    assert!(
        grouped["clusters"][0]["member_frame_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &runs[0]["run"]["records"][0]["id"])
    );
    let discovery_grouped = cli(&[
        "cluster-frames",
        root_text,
        "delimiter",
        discovery_id,
        "ignore",
    ]);
    assert_eq!(discovery_grouped["selected_frame_count"], 3);
    assert_eq!(
        cli(&["frame-runs", root_text, discovery_id, "fixed_width"])["total"],
        0
    );
    let frame_page = cli(&["frames", root_text, "delimiter-discovery", "0", "1"]);
    assert_eq!(frame_page["model"], "delimiter");
    assert_eq!(frame_page["total"], 3);
    assert_eq!(frame_page["next_offset"], 1);
    let first_frame_id = frame_page["frames"][0]["id"].as_str().unwrap();
    let frame_span = cli(&["frame-span", root_text, first_frame_id, "0", "3"]);
    assert_eq!(frame_span["model"], "delimiter");
    assert_eq!(frame_span["logical_length"], 1);
    assert_eq!(frame_span["bytes_hex"], "410d0a");
    assert_eq!(frame_span["source_file_offset"], 0);
    for (set, run, values) in [
        ("discovery", &runs[0], [65, 66, 70]),
        ("validation", &runs[1], [67, 68, 73]),
    ] {
        for (index, value) in values.into_iter().enumerate() {
            cli(&[
                "frame-value",
                root_text,
                run["run"]["records"][index]["id"].as_str().unwrap(),
                "first_payload_byte",
                &value.to_string(),
                set,
            ]);
        }
    }
    let field = cli(&["infer-frame-value", root_text, "first_payload_byte"]);
    assert_eq!(field["candidate_count"], 1);
    assert_eq!(field["candidates"][0]["start"], 0);
    assert_eq!(field["candidates"][0]["end"], 1);
    assert_eq!(field["candidates"][0]["validation_matches"], 3);
    let framed_query = serde_json::json!({"framing_key":"delimiter-discovery"}).to_string();
    assert_eq!(
        cli(&["search-observations", root_text, &framed_query])["total"],
        1
    );
    let corpus = cli(&["summary", root_text]);
    assert_eq!(corpus["counts"]["delimiter_runs"], 2);
    assert_eq!(corpus["counts"]["frames"], 6);
    let committed_report = root.join("delimiter-committed.html");
    cli(&["report", root_text, path(&committed_report)]);
    let committed_html = fs::read_to_string(committed_report).unwrap();
    assert!(committed_html.contains("\"delimiter_runs\":[{"));
    assert!(committed_html.contains("terminator"));
    let unfinished = cli(&[
        "import",
        root_text,
        validation_id,
        "binary",
        path(&fixtures.join("delimiter_unterminated.bin")),
    ]);
    let unfinished_id = unfinished["event"]["observations"][0]["id"]
        .as_str()
        .unwrap();
    let incomplete = cli(&["probe-delimiter", root_text, unfinished_id, "0", "0d0a"]);
    assert_eq!(incomplete["status"], "unterminated_record");
    assert_eq!(incomplete["record_count"], 2);
    assert_eq!(incomplete["next_offset"], 10);
    assert_eq!(incomplete["remaining_bytes"], 4);
    assert_eq!(cli(&["verify", root_text])["observations"], 5);
    let incomplete_commit = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "commit-delimiter",
            root_text,
            unfinished_id,
            "0",
            "0d0a",
            "incomplete",
        ])
        .output()
        .unwrap();
    assert!(!incomplete_commit.status.success());
    cli(&[
        "commit-delimiter",
        root_text,
        &observation_ids[0],
        "0",
        "0d0a",
        "delimiter-competing",
    ]);
    let ambiguous_group = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["cluster-frames", root_text, "delimiter", "-", "ignore"])
        .output()
        .unwrap();
    assert!(!ambiguous_group.status.success());
    assert!(String::from_utf8_lossy(&ambiguous_group.stderr).contains("competing delimiter runs"));
    let selected_group = cli(&[
        "cluster-frames",
        root_text,
        "delimiter",
        "-",
        "ignore",
        "delimiter-discovery,delimiter-validation",
    ]);
    assert_eq!(selected_group["selected_frame_count"], 6);
    assert_eq!(selected_group["run_keys"].as_array().unwrap().len(), 2);
    let ambiguous_validation = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args([
            "validate-frame-clusters",
            root_text,
            "delimiter",
            discovery_id,
            validation_id,
            "ignore",
        ])
        .output()
        .unwrap();
    assert!(!ambiguous_validation.status.success());
    let selected_validation = cli(&[
        "validate-frame-clusters",
        root_text,
        "delimiter",
        discovery_id,
        validation_id,
        "ignore",
        "delimiter-discovery",
        "delimiter-validation",
    ]);
    assert_eq!(selected_validation["discovery_count"], 3);
    assert_eq!(selected_validation["validation_count"], 3);
    assert_eq!(selected_validation["unassigned_count"], 3);
    assert_eq!(
        selected_validation["frames"][0]["rejections"][0]["no_stable_header_evidence"],
        true
    );
    let event_path = root.join(".pi/events.jsonl");
    let mut events: Vec<Value> = fs::read_to_string(&event_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let committed = events
        .iter_mut()
        .find(|event| event["event"]["type"] == "delimiter_committed")
        .unwrap();
    committed["event"]["run"]["records"][0]["logical_end"] = serde_json::json!(2);
    fs::write(
        event_path,
        events
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let invalid = Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .args(["verify", root_text])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("committed delimiter frame"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn committed_delimiter_spans_trace_a_terminator_split_across_tcp_packets() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let fixture = examples.join("delimiter_split_tcp.pcap");
    let truth: Value =
        serde_json::from_slice(&fs::read(examples.join("delimiter_split_tcp.truth.json")).unwrap())
            .unwrap();
    let raw = fs::read(&fixture).unwrap();
    cli(&[
        "init",
        root_text,
        "Where does the TCP record terminator end?",
    ]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Split CRLF across packets",
        "-",
        "Record boundaries survive packet splits",
    ]);
    let trial = cli(&[
        "trial",
        root_text,
        experiment["event"]["experiment"]["id"].as_str().unwrap(),
        "discovery",
        "CRLF straddles packets",
    ]);
    let imported = cli(&[
        "import",
        root_text,
        trial["event"]["trial"]["id"].as_str().unwrap(),
        "pcap-tcp-stream",
        path(&fixture),
    ]);
    assert_eq!(imported["event"]["capture"]["observation_count"], 1);
    let observation_id = imported["event"]["observations"][0]["id"].as_str().unwrap();
    assert_eq!(
        imported["event"]["observations"][0]["bytes_hex"],
        truth["observation_hex"]
    );
    let probe = cli(&["probe-delimiter", root_text, observation_id, "0", "0d0a"]);
    assert_eq!(probe["status"], "complete");
    assert_eq!(probe["record_count"], 2);
    assert_eq!(probe["records"][0]["source_span_count"], 2);
    let committed = cli(&[
        "commit-delimiter",
        root_text,
        observation_id,
        "0",
        "0d0a",
        "split-crlf",
    ]);
    for (actual, expected) in committed["run"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .zip(truth["records"].as_array().unwrap())
    {
        assert_eq!(actual["start"], expected["start"]);
        assert_eq!(actual["logical_end"], expected["payload_end"]);
        assert_eq!(actual["end"], expected["end"]);
    }
    let first_frame_id = committed["run"]["records"][0]["id"].as_str().unwrap();
    let span = cli(&["frame-span", root_text, first_frame_id, "0", "3"]);
    assert_eq!(span["bytes_hex"], "410d0a");
    assert_eq!(span["source_file_offset"], Value::Null);
    let sources = span["source_spans"].as_array().unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["message_start"], 0);
    assert_eq!(sources[0]["message_end"], 2);
    assert_eq!(sources[1]["message_start"], 2);
    assert_eq!(sources[1]["message_end"], 3);
    for (actual, expected) in sources
        .iter()
        .zip(truth["source_spans"].as_array().unwrap())
    {
        assert_eq!(actual["packet_index"], expected["packet_index"]);
        assert_eq!(actual["file_offset"], expected["file_offset"]);
        let start = actual["message_start"].as_u64().unwrap() as usize;
        let end = actual["message_end"].as_u64().unwrap() as usize;
        let offset = actual["file_offset"].as_u64().unwrap() as usize;
        assert_eq!(&raw[offset..offset + end - start], &b"A\r\n"[start..end]);
    }
    assert_eq!(cli(&["verify", root_text])["artifacts_verified"], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn trial_review_identifies_missing_independent_evidence() {
    let root = workspace();
    let root_text = path(&root);
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    cli(&["init", root_text, "What evidence is missing?"]);
    let experiment = cli(&[
        "experiment",
        root_text,
        "Check record boundaries",
        "-",
        "A terminator survives a changed capture",
    ]);
    let experiment_id = experiment["event"]["experiment"]["id"].as_str().unwrap();
    let discovery = cli(&[
        "trial",
        root_text,
        experiment_id,
        "discovery",
        "first message",
    ]);
    let validation = cli(&[
        "trial",
        root_text,
        experiment_id,
        "validation",
        "held-out message",
    ]);
    let discovery_id = discovery["event"]["trial"]["id"].as_str().unwrap();
    let validation_id = validation["event"]["trial"]["id"].as_str().unwrap();
    cli(&[
        "import",
        root_text,
        discovery_id,
        "binary",
        path(&examples.join("delimiter_discovery_a.bin")),
    ]);
    let revision_before = cli(&["resume", root_text])["revision"].clone();
    let review = cli(&["review-trials", root_text, discovery_id, validation_id]);
    assert_eq!(cli(&["resume", root_text])["revision"], revision_before);
    assert_eq!(review["discovery_observation_count"], 1);
    assert_eq!(review["validation_observation_count"], 0);
    assert_eq!(review["prediction_assessed"], false);
    assert_eq!(review["methods"][0]["status"], "unavailable");
    let actions: Vec<_> = review["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action["kind"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"capture_distinct_discovery"));
    assert!(actions.contains(&"capture_held_out_validation"));
    assert_eq!(cli(&["verify", root_text])["observations"], 1);
    fs::remove_dir_all(root).unwrap();
}
