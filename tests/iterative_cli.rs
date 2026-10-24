use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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
    cli(&["analyze-investigation", root_text, "trial-000004"]);
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
        "--",
        "cat",
        fixture_text,
    ]);
    assert_eq!(second["event"]["capture"]["observation_count"], 24);
    let summary = cli(&["resume", root_text]);
    assert_eq!(summary["revision"], 12);
    assert_eq!(summary["observation_count"], 48);
    assert_eq!(summary["hypotheses"][0]["score"], 0.9);
    let page = cli(&["observations", root_text, "trial-000004", "8", "2"]);
    assert_eq!(page["total"], 48);
    assert_eq!(page["observations"].as_array().unwrap().len(), 2);
    assert_eq!(page["observations"][0]["id"], "obs-000006-0008");
    assert_eq!(page["observations"][0]["tags"][0]["label"], "sequence 255");
    assert_eq!(page["next_offset"], 10);
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
    assert_eq!(changes.as_array().unwrap().len(), 1);
    assert_eq!(changes[0]["event"]["type"], "capture_imported");
    let verification = cli(&["verify", root_text]);
    assert_eq!(verification["captures"], 2);
    assert_eq!(verification["observations"], 48);
    assert_eq!(verification["artifacts_verified"], 3);

    let report = root.join("report.html");
    cli(&["report", root_text, path(&report)]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Which bytes carry the ICMP sequence?"));
    assert!(html.contains("obs-000006-0010"));

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
    assert_eq!(cli(&["resume", root_text])["revision"], 12);
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
fn replays_v1_log_and_appends_v2_events() {
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
    assert_eq!(appended["schema_version"], 2);
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
