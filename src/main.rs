use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use protocol_informatics_v2::workflow::{
    self, Action, AnalysisRecord, AnalysisScope, CaptureRun, CaptureRunStatus, CaptureTagBatch,
    Decision, Event, Experiment, FrameKnownValue, Hypothesis, KnownValue, Observation, Tag, Trial,
    ValueSet, WindowTag,
};
use protocol_informatics_v2::{CpuAligner, analyze_best, parse_hex_samples};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

mod mcp;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }
    if args[0] == "analyze" {
        return run_standalone_analysis(&args[1..]);
    }
    if args[0] == "mcp-stdio" {
        require_len(&args, 2)?;
        return mcp::serve(Path::new(&args[1]));
    }
    run_investigation_command(&args)
}

fn print_help() {
    println!("Protocol Informatics v2\n");
    println!("  analyze <hex-file> [--json]          one-shot alignment");
    println!("  mcp-stdio <dir>                     serve investigation tools over MCP stdio");
    println!("  init <dir> <question>                create investigation");
    println!("  hypothesis <dir> <claim>             add hypothesis");
    println!("  evaluate <dir> <hyp-id> <score> <evidence-ids> <counterexample-ids>");
    println!("  experiment <dir> <question> <hyp-ids> <prediction>");
    println!("  trial <dir> <exp-id> <role> <changed-factor>");
    println!(
        "  import <dir> <trial-id> <hex|binary|pcap-icmp|pcapng-icmp|pcap-icmpv6|pcapng-icmpv6|pcap-udp|pcapng-udp|pcap-tcp|pcapng-tcp|pcap-tcp-stream|pcapng-tcp-stream> <file>"
    );
    println!(
        "  capture-command <dir> <trial-id> <format> <key> <timeout-ms> -- <program> [args...]"
    );
    println!(
        "  capture-step <dir> <trial-id> <kind> <detail> <phase> <label> <step-key> <format> <timeout-ms> -- <program> [args...]"
    );
    println!("  capture-start <dir> <trial-id> <format> <key> <timeout-ms> -- <program> [args...]");
    println!("  capture-stop <dir> <key>             request a running capture to stop");
    println!("  capture-status <dir> <key>           inspect a reserved capture command");
    println!("  mark <dir> <trial-id> <kind> <detail>");
    println!("  mark-keyed <dir> <trial-id> <kind> <detail> <key> [timestamp-ns]");
    println!("  mark-at <dir> <trial-id> <timestamp-ns> <kind> <detail>");
    println!("  tag <dir> <obs-id> <phase> <label>");
    println!("  tag-window <dir> <action-id> <end-ns> <phase> <label> <key>");
    println!(
        "  tag-capture <dir> <action-id> <capture-id> <phase> <label> <key> [offset count<=1000]"
    );
    println!("  capture-tag-status <dir> <key>    inspect a completed capture tag batch");
    println!("  window-status <dir> <key>             inspect a completed tag window");
    println!("  value <dir> <obs-id> <variable> <unsigned> <discovery|validation>");
    println!("  infer-value <dir> <variable>         find exact unsigned field candidates");
    println!("  frame-value <dir> <frame-id> <variable> <unsigned> <discovery|validation>");
    println!(
        "  infer-frame-value <dir> <variable>   search logical frame bytes with held-out checks"
    );
    println!(
        "  probe-framing <dir> <obs-id> <start> <field-offset> <width> <big|little> <total|payload> <alignment>"
    );
    println!("  infer-framing <dir> <discovery-trial> <validation-trial>");
    println!("  probe-delimiter <dir> <obs-id> <start> <delimiter-hex>");
    println!("  infer-delimiter <dir> <discovery-trial> <validation-trial>");
    println!("  commit-delimiter <dir> <obs-id> <start> <delimiter-hex> <key>");
    println!("  delimiter-status <dir> <key>       inspect a committed delimiter run");
    println!(
        "  probe-tlv <dir> <obs-id> <start> <type-width> <length-width> <big|little> <total|payload> <alignment>"
    );
    println!("  infer-tlv <dir> <discovery-trial> <validation-trial>");
    println!("  probe-varint <dir> <obs-id> <start> <field-offset> <total|payload> <alignment>");
    println!("  infer-varint <dir> <discovery-trial> <validation-trial>");
    println!(
        "  commit-varint <dir> <obs-id> <start> <field-offset> <total|payload> <alignment> <key>"
    );
    println!("  varint-status <dir> <key>          inspect a committed varint run");
    println!(
        "  commit-framing <dir> <obs-id> <start> <field-offset> <width> <big|little> <total|payload> <alignment> <key>"
    );
    println!("  framing-status <dir> <key>         inspect a committed framing run");
    println!("  frames <dir> <key> [offset] [limit<=100]");
    println!("  frame-span <dir> <frame-id> <start> <end>  read half-open frame byte span");
    println!(
        "  infer-checksum <dir> <discovery-trial> <validation-trial> <baseline-trial> <variant-trial> <controlled-variable>"
    );
    println!("  analyze-investigation <dir> [trial-id]");
    println!("  cluster <dir> [trial-id|-] [respect|ignore]");
    println!("  validate-clusters <dir> <discovery-trial> <validation-trial> [respect|ignore]");
    println!("  pair-exchanges <dir> <capture-id> [max-lag-ms] [offset] [limit<=100]");
    println!("  validate-exchanges <dir> <discovery-capture> <validation-capture> [max-lag-ms]");
    println!("  analyze-cluster <dir> <cluster-id> [trial-id|-] [respect|ignore]");
    println!("  decide <dir> <decision> [evidence-ids]");
    println!("  summary <dir>                      bounded corpus overview for agents");
    println!("  trials <dir> [offset] [limit<=100]  page trial metadata newest first");
    println!("  experiments <dir> [offset] [limit<=100]  page experiment plans");
    println!("  hypotheses <dir> [offset] [limit<=100]  page claims and evidence counts");
    println!("  decisions <dir> [offset] [limit<=100]  page recorded decisions");
    println!("  resume <dir> | changes <dir> <revision> | report <dir> <html-file>");
    println!("  recover-tail <dir> [--apply]       inspect or repair an unterminated final event");
    println!("  observations <dir> [trial-id|-] [offset] [limit<=100]");
    println!("  search-observations <dir> <json-filter>  bounded multi-filter query");
    println!("  span <dir> <obs-id> <start> <end>    read half-open message byte span");
    println!("  diff <dir> <left-obs-id> <right-obs-id>");
    println!("  compare-trials <dir> <baseline-trial-id> <variant-trial-id>");
    println!("  verify <dir>                         verify stored evidence artifacts");
    println!("IDs are comma-separated where plural; use '-' for an empty list.");
}

fn run_standalone_analysis(args: &[String]) -> Result<(), String> {
    let mut path = None;
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else if arg.starts_with('-') || path.replace(arg).is_some() {
            return Err(format!("unexpected argument: {arg}"));
        }
    }
    let path = path.ok_or("missing hex-lines-file")?;
    let input = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let samples = parse_hex_samples(&input).map_err(|error| error.to_string())?;
    let result = analyze_best(&samples, &CpuAligner).map_err(|error| error.to_string())?;

    if json {
        println!("{}", result.to_json());
    } else {
        println!("samples: {}", samples.len());
        println!("reference sample: {}", result.reference_index + 1);
        println!("strategy: {}", result.strategy);
        println!("aligned columns: {}", result.columns.len());
        println!("column  consensus  support  distinct  entropy_bits");
        for (index, column) in result.columns.iter().enumerate() {
            let consensus = column
                .consensus
                .map(|byte| format!("{byte:02x}"))
                .unwrap_or_else(|| "--".into());
            println!(
                "{index:>6}  {consensus:>9}  {:>7}  {:>8}  {:>12.3}",
                column.support, column.distinct, column.entropy_bits
            );
        }
    }
    Ok(())
}

fn require_len(args: &[String], expected: usize) -> Result<(), String> {
    if args.len() != expected {
        Err(format!(
            "expected {expected} arguments; use --help for syntax"
        ))
    } else {
        Ok(())
    }
}

fn ids(text: &str) -> Vec<String> {
    if text == "-" {
        Vec::new()
    } else {
        text.split(',').map(str::to_owned).collect()
    }
}

fn print_json(value: &impl Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn parse_unsigned(text: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    };
    parsed.map_err(|_| "value must be an unsigned decimal or 0x-prefixed integer".into())
}

fn page_arguments(args: &[String]) -> Result<(usize, usize), String> {
    if args.len() > 4 {
        return Err("expected optional offset and limit".into());
    }
    let offset = args.get(2).map_or(Ok(0), |value| {
        value.parse().map_err(|_| "offset must be an integer")
    })?;
    let limit = args.get(3).map_or(Ok(50), |value| {
        value.parse().map_err(|_| "limit must be an integer")
    })?;
    Ok((offset, limit))
}

fn direction_mode(text: Option<&String>) -> Result<bool, String> {
    match text.map(String::as_str).unwrap_or("respect") {
        "respect" => Ok(true),
        "ignore" => Ok(false),
        _ => Err("direction mode must be respect or ignore".into()),
    }
}

fn record_analysis(
    root: &Path,
    selected: &[&Observation],
    scope: AnalysisScope,
) -> Result<(), String> {
    if selected.is_empty() {
        return Err("no observations selected".into());
    }
    let samples: Vec<Vec<u8>> = selected
        .iter()
        .map(|observation| workflow::from_hex(&observation.bytes_hex))
        .collect::<Result<_, _>>()?;
    let analysis = analyze_best(&samples, &CpuAligner).map_err(|error| error.to_string())?;
    let json = analysis.to_json();
    let (_, artifact) = workflow::store_artifact(root, json.as_bytes(), "json")?;
    let record = AnalysisRecord {
        id: workflow::next_id(root, "analysis")?,
        observation_ids: selected
            .iter()
            .map(|observation| observation.id.clone())
            .collect(),
        artifact,
        aligned_width: analysis.columns.len(),
        scope: Some(scope),
        method_version: Some("best_of_positional_and_star_v1".into()),
    };
    print_json(&workflow::append(
        root,
        Event::AnalysisRecorded { analysis: record },
    )?)
}

fn capture_run_view(
    state: &workflow::State,
    run: &CaptureRun,
    status_override: Option<&str>,
) -> serde_json::Value {
    let status = status_override.unwrap_or(match run.status {
        CaptureRunStatus::Reserved => "reserved",
        CaptureRunStatus::Completed => "completed",
        CaptureRunStatus::Failed => "failed",
    });
    let capture = run
        .capture_id
        .as_ref()
        .and_then(|id| state.captures.iter().find(|capture| &capture.id == id));
    let observation_ids: Vec<_> = capture
        .map(|capture| {
            state
                .observations
                .iter()
                .filter(|observation| observation.capture_id == capture.id)
                .map(|observation| &observation.id)
                .collect()
        })
        .unwrap_or_default();
    json!({
        "revision": state.revision, "run_id": run.id, "key": run.key,
        "status": status, "trial_id": run.trial_id, "format": run.format,
        "timeout_ms": run.timeout_ms, "capture": capture,
        "observation_ids": observation_ids, "error": run.error,
        "stop_requested": run.stop_requested,
    })
}

fn capture_status_name(root: &Path, run: &CaptureRun) -> Result<&'static str, String> {
    match run.status {
        CaptureRunStatus::Completed => Ok("completed"),
        CaptureRunStatus::Failed => Ok("failed"),
        CaptureRunStatus::Reserved => {
            if workflow::capture_run_lock(root, &run.key)?.is_some() {
                Ok("interrupted")
            } else if run.stop_requested {
                Ok("stopping")
            } else {
                Ok("running")
            }
        }
    }
}

fn capture_command(root: &Path, args: &[String]) -> Result<(), String> {
    if args.len() < 8 || args[6] != "--" {
        return Err(
            "expected <trial-id> <format> <key> <timeout-ms> -- <program> [args...]".into(),
        );
    }
    let trial_id = &args[2];
    let format = &args[3];
    let key = &args[4];
    let timeout_ms: u64 = args[5]
        .parse()
        .map_err(|_| "timeout must be an unsigned number of milliseconds".to_string())?;
    if timeout_ms == 0 || timeout_ms > protocol_informatics_v2::capture::MAX_TIMEOUT_MS {
        return Err("timeout must be between 1 and 600000 ms".into());
    }
    if !workflow::valid_capture_format(format) {
        return Err("unknown capture format".into());
    }
    let argv = &args[7..];
    let fingerprint = workflow::capture_run_fingerprint(trial_id, format, timeout_ms, argv)?;
    let state = workflow::load(root)?;
    if !state.trials.iter().any(|trial| &trial.id == trial_id) {
        return Err(format!("unknown trial {trial_id}"));
    }
    let lock = workflow::capture_run_lock(root, key)?;
    let state = workflow::load(root)?;
    let existing = state.capture_runs.iter().find(|run| &run.key == key);
    if let Some(run) = existing
        && run.command_fingerprint != fingerprint
    {
        return Err(format!(
            "capture key {key} was used with different arguments"
        ));
    }
    let Some(_lock) = lock else {
        if let Some(run) = existing {
            return print_json(&capture_run_view(
                &state,
                run,
                (run.status == CaptureRunStatus::Reserved).then_some(if run.stop_requested {
                    "stopping"
                } else {
                    "running"
                }),
            ));
        }
        return print_json(&json!({"key": key, "status": "running"}));
    };
    if let Some(run) = existing {
        match run.status {
            CaptureRunStatus::Completed => return print_json(&capture_run_view(&state, run, None)),
            CaptureRunStatus::Failed => {
                print_json(&capture_run_view(&state, run, None))?;
                return Err(format!("capture key {key} already failed"));
            }
            CaptureRunStatus::Reserved => {
                workflow::append(
                    root,
                    Event::CaptureRunFailed {
                        key: key.clone(),
                        error: "previous command ended before capture completion".into(),
                    },
                )?;
                let updated = workflow::load(root)?;
                let run = updated
                    .capture_runs
                    .iter()
                    .find(|run| &run.key == key)
                    .unwrap();
                print_json(&capture_run_view(&updated, run, None))?;
                return Err(format!(
                    "capture key {key} was interrupted; use a new key to rerun"
                ));
            }
        }
    }
    let reserved = CaptureRun {
        id: workflow::next_id(root, "run")?,
        key: key.clone(),
        trial_id: trial_id.clone(),
        format: format.clone(),
        command_fingerprint: fingerprint,
        timeout_ms,
        status: CaptureRunStatus::Reserved,
        capture_id: None,
        error: None,
        stop_requested: false,
    };
    workflow::append(root, Event::CaptureRunReserved { run: reserved })?;
    let event_path = root.join(".pi/events.jsonl");
    let mut last_length = 0;
    let result = protocol_informatics_v2::capture::run_command_with_stop(argv, timeout_ms, || {
        let length = fs::metadata(&event_path)
            .map_err(|error| error.to_string())?
            .len();
        if length == last_length {
            return Ok(false);
        }
        last_length = length;
        let state = workflow::load(root)?;
        let run = state
            .capture_runs
            .iter()
            .find(|run| &run.key == key)
            .ok_or_else(|| format!("capture run {key} disappeared"))?;
        Ok(run.stop_requested)
    })
    .and_then(|raw| {
        workflow::import_capture_for_run(
            root,
            trial_id,
            &format!("command: {}", argv[0]),
            format,
            &raw,
            Some(key),
        )
        .map(|_| ())
    });
    if let Err(error) = result {
        workflow::append(
            root,
            Event::CaptureRunFailed {
                key: key.clone(),
                error: error.clone(),
            },
        )?;
        let updated = workflow::load(root)?;
        let run = updated
            .capture_runs
            .iter()
            .find(|run| &run.key == key)
            .unwrap();
        print_json(&capture_run_view(&updated, run, None))?;
        return Err(error);
    }
    let updated = workflow::load(root)?;
    let run = updated
        .capture_runs
        .iter()
        .find(|run| &run.key == key)
        .unwrap();
    print_json(&capture_run_view(&updated, run, None))
}

fn invoke_local_json(args: &[String]) -> Result<serde_json::Value, String> {
    let output = Command::new(env::current_exe().map_err(|error| error.to_string())?)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{} returned invalid JSON: {error}", args[0]))
}

fn capture_step(root: &Path, args: &[String]) -> Result<(), String> {
    if args.len() < 12 || args[10] != "--" {
        return Err("expected trial, action kind/detail, phase/label, step key, format, timeout, --, and a program".into());
    }
    let step_key = &args[7];
    if step_key.is_empty() || step_key.len() > 120 || step_key.chars().any(char::is_control) {
        return Err(
            "step key must be nonempty, at most 120 bytes, and contain no control characters"
                .into(),
        );
    }
    if !workflow::valid_capture_format(&args[8]) {
        return Err("unknown capture format".into());
    }
    let timeout_ms: u64 = args[9]
        .parse()
        .map_err(|_| "timeout must be an unsigned number of milliseconds".to_string())?;
    if timeout_ms == 0 || timeout_ms > protocol_informatics_v2::capture::MAX_TIMEOUT_MS {
        return Err("timeout must be between 1 and 600000 ms".into());
    }
    if args[3].trim().is_empty()
        || args[4].trim().is_empty()
        || args[5].trim().is_empty()
        || args[6].trim().is_empty()
    {
        return Err("action kind/detail and tag phase/label must be nonempty".into());
    }
    let directory = args[1].clone();
    let trial_id = args[2].clone();
    let action_args = vec![
        "mark-keyed".into(),
        directory.clone(),
        trial_id.clone(),
        args[3].clone(),
        args[4].clone(),
        format!("{step_key}:action"),
    ];
    let marked = invoke_local_json(&action_args)?;
    let action_id = marked["action"]["id"]
        .as_str()
        .ok_or("mark-keyed returned no action ID")?;
    let mut capture_args = vec![
        "capture-command".into(),
        directory.clone(),
        trial_id,
        args[8].clone(),
        format!("{step_key}:capture"),
        args[9].clone(),
        "--".into(),
    ];
    capture_args.extend_from_slice(&args[11..]);
    let captured = invoke_local_json(&capture_args)?;
    if captured["status"] != "completed" {
        return print_json(&json!({
            "revision": workflow::load(root)?.revision, "step_key": step_key,
            "status": captured["status"], "action": marked["action"],
            "capture_run": captured,
        }));
    }
    let capture_id = captured["capture"]["id"]
        .as_str()
        .ok_or("capture-command returned no capture ID")?;
    let observation_count = captured["observation_ids"]
        .as_array()
        .ok_or("capture-command returned no observation IDs")?
        .len();
    let mut tag_batches = Vec::new();
    let mut all_replayed = true;
    let mut revision = captured["revision"].clone();
    for offset in (0..observation_count).step_by(1000) {
        let count = (observation_count - offset).min(1000);
        let key = if observation_count <= 1000 {
            format!("{step_key}:tags")
        } else {
            format!(
                "step-tags-{:x}-{offset}",
                Sha256::digest(step_key.as_bytes())
            )
        };
        let mut tag_args = vec![
            "tag-capture".into(),
            directory.clone(),
            action_id.into(),
            capture_id.into(),
            args[5].clone(),
            args[6].clone(),
            key,
        ];
        if observation_count > 1000 {
            tag_args.push(offset.to_string());
            tag_args.push(count.to_string());
        }
        let tagged = invoke_local_json(&tag_args)?;
        all_replayed &= tagged["replayed"] == true;
        revision = tagged["revision"].clone();
        tag_batches.push(tagged["batch"].clone());
    }
    let tag_batch = if tag_batches.len() == 1 {
        tag_batches[0].clone()
    } else {
        serde_json::Value::Null
    };
    print_json(&json!({
        "revision": revision, "step_key": step_key, "status": "completed",
        "action": marked["action"], "capture": captured["capture"],
        "observation_ids": captured["observation_ids"], "tag_batch": tag_batch,
        "tag_batches": tag_batches, "replayed": all_replayed,
    }))
}

fn capture_start(root: &Path, args: &[String]) -> Result<(), String> {
    if args.len() < 8 || args[6] != "--" {
        return Err(
            "expected <trial-id> <format> <key> <timeout-ms> -- <program> [args...]".into(),
        );
    }
    let trial_id = &args[2];
    let format = &args[3];
    let key = &args[4];
    let timeout_ms: u64 = args[5]
        .parse()
        .map_err(|_| "timeout must be an unsigned number of milliseconds".to_string())?;
    if timeout_ms == 0 || timeout_ms > protocol_informatics_v2::capture::MAX_TIMEOUT_MS {
        return Err("timeout must be between 1 and 600000 ms".into());
    }
    if !workflow::valid_capture_format(format) {
        return Err("unknown capture format".into());
    }
    let fingerprint = workflow::capture_run_fingerprint(trial_id, format, timeout_ms, &args[7..])?;
    let state = workflow::load(root)?;
    if !state.trials.iter().any(|trial| &trial.id == trial_id) {
        return Err(format!("unknown trial {trial_id}"));
    }
    if let Some(run) = state.capture_runs.iter().find(|run| &run.key == key) {
        if run.command_fingerprint != fingerprint {
            return Err(format!(
                "capture key {key} was used with different arguments"
            ));
        }
        let status = capture_status_name(root, run)?;
        return print_json(&capture_run_view(&state, run, Some(status)));
    }
    let mut command = Command::new(env::current_exe().map_err(|error| error.to_string())?);
    command
        .arg("capture-command")
        .args(&args[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    command.process_group(0);
    let mut worker = command
        .spawn()
        .map_err(|error| format!("capture worker could not start: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let state = workflow::load(root)?;
        let worker_exited = worker
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some();
        if let Some(run) = state.capture_runs.iter().find(|run| &run.key == key) {
            if run.command_fingerprint != fingerprint {
                return Err(format!(
                    "capture key {key} was used with different arguments"
                ));
            }
            let status = capture_status_name(root, run)?;
            if status != "interrupted" || worker_exited {
                return print_json(&capture_run_view(&state, run, Some(status)));
            }
        }
        if Instant::now() >= deadline {
            if worker_exited {
                return Err(format!("capture worker exited before reserving key {key}"));
            }
            return print_json(&json!({"key": key, "status": "starting"}));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn capture_stop(root: &Path, key: &str) -> Result<(), String> {
    let state = workflow::load(root)?;
    let run = state
        .capture_runs
        .iter()
        .find(|run| run.key == key)
        .ok_or_else(|| format!("unknown capture key {key}"))?;
    if capture_status_name(root, run)? == "running"
        && let Err(error) =
            workflow::append(root, Event::CaptureRunStopRequested { key: key.into() })
    {
        let updated = workflow::load(root)?;
        let Some(current) = updated.capture_runs.iter().find(|run| run.key == key) else {
            return Err(error);
        };
        if current.status == CaptureRunStatus::Reserved && !current.stop_requested {
            return Err(error);
        }
    }
    let updated = workflow::load(root)?;
    let run = updated
        .capture_runs
        .iter()
        .find(|run| run.key == key)
        .ok_or_else(|| format!("unknown capture key {key}"))?;
    let status = capture_status_name(root, run)?;
    print_json(&capture_run_view(&updated, run, Some(status)))
}

fn window_view(state: &workflow::State, window: &WindowTag, replayed: bool) -> serde_json::Value {
    json!({"revision": state.revision, "window": window, "replayed": replayed})
}

fn tag_window(root: &Path, args: &[String]) -> Result<(), String> {
    require_len(args, 7)?;
    let action_id = &args[2];
    let end_ns: u64 = args[3]
        .parse()
        .map_err(|_| "window end must be UTC nanoseconds as an unsigned integer".to_string())?;
    let phase = &args[4];
    let label = &args[5];
    let key = &args[6];
    if key.is_empty()
        || key.len() > 128
        || key.chars().any(char::is_control)
        || phase.trim().is_empty()
        || label.trim().is_empty()
    {
        return Err(
            "window key, phase, and label must be nonempty; key has a 128-byte limit".into(),
        );
    }
    let matches_request = |window: &WindowTag| {
        &window.action_id == action_id
            && window.end_ns == end_ns
            && &window.phase == phase
            && &window.label == label
    };
    let state = workflow::load(root)?;
    if let Some(existing) = state.window_tags.iter().find(|window| &window.key == key) {
        return if matches_request(existing) {
            print_json(&window_view(&state, existing, true))
        } else {
            Err(format!(
                "window key {key} was used with different arguments"
            ))
        };
    }
    let action = state
        .actions
        .iter()
        .find(|action| &action.id == action_id)
        .ok_or_else(|| format!("unknown action {action_id}"))?;
    let selected = workflow::eligible_window_observations(&state, action, end_ns, phase, label)?;
    if selected.is_empty() {
        return Err("window has no new timestamped observations in the action's trial".into());
    }
    if selected.len() > 1000 {
        return Err("window contains more than 1000 observations; use shorter intervals".into());
    }
    let observation_ids: Vec<String> = selected.iter().map(|item| item.id.clone()).collect();
    let tags = observation_ids
        .iter()
        .map(|observation_id| Tag {
            id: String::new(),
            observation_id: observation_id.clone(),
            phase: phase.clone(),
            label: label.clone(),
            action_id: Some(action_id.clone()),
        })
        .collect();
    let window = WindowTag {
        id: String::new(),
        key: key.clone(),
        action_id: action_id.clone(),
        start_ns: action.timestamp_ns.expect("selection requires a timestamp"),
        end_ns,
        phase: phase.clone(),
        label: label.clone(),
        observation_ids,
    };
    let appended = workflow::append(root, Event::ObservationWindowTagged { window, tags });
    let updated = workflow::load(root)?;
    if let Some(existing) = updated.window_tags.iter().find(|window| &window.key == key) {
        if matches_request(existing) {
            return print_json(&window_view(&updated, existing, appended.is_err()));
        }
        return Err(format!(
            "window key {key} was used with different arguments"
        ));
    }
    Err(appended
        .err()
        .unwrap_or_else(|| "window event was not recorded".into()))
}

fn mark_keyed(root: &Path, args: &[String]) -> Result<(), String> {
    if args.len() < 6 || args.len() > 7 {
        return Err("expected trial, kind, detail, key, and optional UTC nanoseconds".into());
    }
    let key = &args[5];
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(
            "action key must be nonempty, at most 128 bytes, and contain no control characters"
                .into(),
        );
    }
    let supplied_timestamp = args
        .get(6)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "timestamp must be UTC nanoseconds as an unsigned integer".to_string())
        })
        .transpose()?;
    let matches_request = |action: &Action| {
        action.trial_id == args[2]
            && action.kind == args[3]
            && action.detail == args[4]
            && supplied_timestamp.is_none_or(|timestamp| action.timestamp_ns == Some(timestamp))
    };
    let state = workflow::load(root)?;
    if let Some(action) = state
        .actions
        .iter()
        .find(|action| action.key.as_ref() == Some(key))
    {
        return if matches_request(action) {
            print_json(&json!({"revision": state.revision, "action": action, "replayed": true}))
        } else {
            Err(format!(
                "action key {key} was used with different arguments"
            ))
        };
    }
    let action = Action {
        id: String::new(),
        trial_id: args[2].clone(),
        kind: args[3].clone(),
        detail: args[4].clone(),
        timestamp_ns: Some(supplied_timestamp.unwrap_or(workflow::now_ns()?)),
        key: Some(key.clone()),
    };
    let appended = workflow::append(root, Event::ActionMarked { action });
    let updated = workflow::load(root)?;
    if let Some(action) = updated
        .actions
        .iter()
        .find(|action| action.key.as_ref() == Some(key))
    {
        return if matches_request(action) {
            print_json(
                &json!({"revision": updated.revision, "action": action, "replayed": appended.is_err()}),
            )
        } else {
            Err(format!(
                "action key {key} was used with different arguments"
            ))
        };
    }
    Err(appended
        .err()
        .unwrap_or_else(|| "keyed action was not recorded".into()))
}

fn tag_capture(root: &Path, args: &[String]) -> Result<(), String> {
    if args.len() != 7 && args.len() != 9 {
        return Err(
            "expected action, capture, phase, label, key, and optional offset/count".into(),
        );
    }
    let action_id = &args[2];
    let capture_id = &args[3];
    let phase = &args[4];
    let label = &args[5];
    let key = &args[6];
    if key.is_empty()
        || key.len() > 128
        || key.chars().any(char::is_control)
        || phase.trim().is_empty()
        || label.trim().is_empty()
    {
        return Err(
            "capture tag key, phase, and label must be nonempty; key has a 128-byte limit".into(),
        );
    }
    let requested_range = if args.len() == 9 {
        let offset: usize = args[7]
            .parse()
            .map_err(|_| "capture tag offset must be an unsigned integer".to_string())?;
        let count: usize = args[8]
            .parse()
            .map_err(|_| "capture tag count must be an unsigned integer".to_string())?;
        if !(1..=1000).contains(&count) {
            return Err("capture tag count must be 1 to 1000".into());
        }
        Some((offset, count))
    } else {
        None
    };
    let state = workflow::load(root)?;
    let action = state
        .actions
        .iter()
        .find(|action| &action.id == action_id)
        .ok_or_else(|| format!("unknown action {action_id}"))?;
    let capture = state
        .captures
        .iter()
        .find(|capture| &capture.id == capture_id)
        .ok_or_else(|| format!("unknown capture {capture_id}"))?;
    if action.trial_id != capture.trial_id {
        return Err("action and capture must belong to the same trial".into());
    }
    let all_observation_ids: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| &observation.capture_id == capture_id)
        .map(|observation| observation.id.clone())
        .collect();
    let (start_index, end_index) = if let Some((offset, count)) = requested_range {
        let end = offset
            .checked_add(count)
            .ok_or("capture tag range overflows")?;
        if end > all_observation_ids.len() {
            return Err("capture tag range exceeds capture observations".into());
        }
        (offset, end)
    } else {
        if all_observation_ids.is_empty() || all_observation_ids.len() > 1000 {
            return Err("capture tag batch needs 1 to 1000 observations; use offset/count for larger captures".into());
        }
        (0, all_observation_ids.len())
    };
    let observation_ids = all_observation_ids[start_index..end_index].to_vec();
    let matches_request = |batch: &CaptureTagBatch| {
        &batch.action_id == action_id
            && &batch.capture_id == capture_id
            && &batch.phase == phase
            && &batch.label == label
            && batch.start_index == start_index
            && batch.observation_ids == observation_ids
    };
    if let Some(batch) = state
        .capture_tag_batches
        .iter()
        .find(|batch| &batch.key == key)
    {
        return if matches_request(batch) {
            print_json(&json!({"revision": state.revision, "batch": batch, "replayed": true}))
        } else {
            Err(format!(
                "capture tag key {key} was used with different arguments"
            ))
        };
    }
    let tags = observation_ids
        .iter()
        .map(|observation_id| Tag {
            id: String::new(),
            observation_id: observation_id.clone(),
            phase: phase.clone(),
            label: label.clone(),
            action_id: Some(action_id.clone()),
        })
        .collect();
    let batch = CaptureTagBatch {
        id: String::new(),
        key: key.clone(),
        action_id: action_id.clone(),
        capture_id: capture_id.clone(),
        phase: phase.clone(),
        label: label.clone(),
        start_index,
        observation_ids: observation_ids.clone(),
        tag_ids: Vec::new(),
    };
    let appended = workflow::append(root, Event::CaptureTagged { batch, tags });
    let updated = workflow::load(root)?;
    if let Some(batch) = updated
        .capture_tag_batches
        .iter()
        .find(|batch| &batch.key == key)
    {
        return if matches_request(batch) {
            print_json(
                &json!({"revision": updated.revision, "batch": batch, "replayed": appended.is_err()}),
            )
        } else {
            Err(format!(
                "capture tag key {key} was used with different arguments"
            ))
        };
    }
    Err(appended
        .err()
        .unwrap_or_else(|| "capture tag batch was not recorded".into()))
}

fn parse_framing_config(
    args: &[String],
) -> Result<protocol_informatics_v2::framing::FramingConfig, String> {
    let parse = |value: &str, name: &str| {
        value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be an unsigned integer"))
    };
    Ok(protocol_informatics_v2::framing::FramingConfig {
        start_offset: parse(&args[3], "start offset")?,
        prefix_offset: parse(&args[4], "length field offset")?,
        prefix_width: parse(&args[5], "length field width")?,
        byte_order: protocol_informatics_v2::framing::ByteOrder::parse(&args[6])?,
        length_mode: protocol_informatics_v2::framing::LengthMode::parse(&args[7])?,
        alignment: parse(&args[8], "record alignment")?,
    })
}

fn parse_tlv_config(args: &[String]) -> Result<protocol_informatics_v2::tlv::TlvConfig, String> {
    let framing = parse_framing_config(args)?;
    protocol_informatics_v2::tlv::TlvConfig {
        start_offset: framing.start_offset,
        type_width: framing.prefix_offset,
        length_width: framing.prefix_width,
        byte_order: framing.byte_order,
        length_mode: framing.length_mode,
        alignment: framing.alignment,
    }
    .validate()
}

fn parse_varint_config(
    args: &[String],
) -> Result<protocol_informatics_v2::varint::VarintConfig, String> {
    let parse = |value: &str, name: &str| {
        value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be an unsigned integer"))
    };
    protocol_informatics_v2::varint::VarintConfig {
        start_offset: parse(&args[3], "start offset")?,
        field_offset: parse(&args[4], "length field offset")?,
        length_mode: protocol_informatics_v2::framing::LengthMode::parse(&args[5])?,
        alignment: parse(&args[6], "record alignment")?,
    }
    .validate()
}

fn commit_framing(root: &Path, args: &[String]) -> Result<(), String> {
    require_len(args, 10)?;
    let observation_id = &args[2];
    let config = parse_framing_config(args)?;
    let key = &args[9];
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(
            "framing key must be nonempty, at most 128 bytes, and contain no control characters"
                .into(),
        );
    }
    let matches_request =
        |run: &workflow::FramingRun| &run.observation_id == observation_id && run.config == config;
    let state = workflow::load(root)?;
    if state.varint_runs.iter().any(|run| &run.key == key)
        || state.delimiter_runs.iter().any(|run| &run.key == key)
    {
        return Err(format!(
            "framing key {key} is already used by another frame run"
        ));
    }
    if let Some(existing) = state.framing_runs.iter().find(|run| &run.key == key) {
        return if matches_request(existing) {
            print_json(&json!({"revision": state.revision, "run": existing, "replayed": true}))
        } else {
            Err(format!(
                "framing key {key} was used with different arguments"
            ))
        };
    }
    let run =
        workflow::framing_run_from_probe(key.clone(), observation_id.clone(), config, &state)?;
    let appended = workflow::append(root, Event::FramingCommitted { run });
    let updated = workflow::load(root)?;
    if let Some(existing) = updated.framing_runs.iter().find(|run| &run.key == key) {
        return if matches_request(existing) {
            print_json(
                &json!({"revision": updated.revision, "run": existing, "replayed": appended.is_err()}),
            )
        } else {
            Err(format!(
                "framing key {key} was used with different arguments"
            ))
        };
    }
    Err(appended
        .err()
        .unwrap_or_else(|| "framing run was not recorded".into()))
}

fn commit_varint(root: &Path, args: &[String]) -> Result<(), String> {
    require_len(args, 8)?;
    let observation_id = &args[2];
    let config = parse_varint_config(args)?;
    let key = &args[7];
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(
            "varint key must be nonempty, at most 128 bytes, and contain no control characters"
                .into(),
        );
    }
    let matches_request =
        |run: &workflow::VarintRun| &run.observation_id == observation_id && run.config == config;
    let state = workflow::load(root)?;
    if state.framing_runs.iter().any(|run| &run.key == key)
        || state.delimiter_runs.iter().any(|run| &run.key == key)
    {
        return Err(format!(
            "varint key {key} is already used by another frame run"
        ));
    }
    if let Some(existing) = state.varint_runs.iter().find(|run| &run.key == key) {
        return if matches_request(existing) {
            print_json(&json!({"revision": state.revision, "run": existing, "replayed": true}))
        } else {
            Err(format!(
                "varint key {key} was used with different arguments"
            ))
        };
    }
    let run = workflow::varint_run_from_probe(key.clone(), observation_id.clone(), config, &state)?;
    let appended = workflow::append(root, Event::VarintCommitted { run });
    let updated = workflow::load(root)?;
    if let Some(existing) = updated.varint_runs.iter().find(|run| &run.key == key) {
        return if matches_request(existing) {
            print_json(
                &json!({"revision": updated.revision, "run": existing, "replayed": appended.is_err()}),
            )
        } else {
            Err(format!(
                "varint key {key} was used with different arguments"
            ))
        };
    }
    Err(appended
        .err()
        .unwrap_or_else(|| "varint run was not recorded".into()))
}

fn commit_delimiter(root: &Path, args: &[String]) -> Result<(), String> {
    require_len(args, 6)?;
    let observation_id = &args[2];
    let start_offset: usize = args[3]
        .parse()
        .map_err(|_| "start offset must be an unsigned integer".to_string())?;
    let config = protocol_informatics_v2::delimiter::DelimiterConfig {
        start_offset,
        delimiter_hex: args[4].clone(),
    }
    .validate()?;
    let key = &args[5];
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(
            "delimiter key must be nonempty, at most 128 bytes, and contain no control characters"
                .into(),
        );
    }
    let matches_request = |run: &workflow::DelimiterRun| {
        &run.observation_id == observation_id && run.config == config
    };
    let state = workflow::load(root)?;
    if state.framing_runs.iter().any(|run| &run.key == key)
        || state.varint_runs.iter().any(|run| &run.key == key)
    {
        return Err(format!(
            "delimiter key {key} is already used by another frame run"
        ));
    }
    if let Some(existing) = state.delimiter_runs.iter().find(|run| &run.key == key) {
        return if matches_request(existing) {
            print_json(&json!({"revision": state.revision, "run": existing, "replayed": true}))
        } else {
            Err(format!(
                "delimiter key {key} was used with different arguments"
            ))
        };
    }
    let run = workflow::delimiter_run_from_probe(
        key.clone(),
        observation_id.clone(),
        config.clone(),
        &state,
    )?;
    let appended = workflow::append(root, Event::DelimiterCommitted { run });
    let updated = workflow::load(root)?;
    if let Some(existing) = updated.delimiter_runs.iter().find(|run| &run.key == key) {
        return if matches_request(existing) {
            print_json(
                &json!({"revision": updated.revision, "run": existing, "replayed": appended.is_err()}),
            )
        } else {
            Err(format!(
                "delimiter key {key} was used with different arguments"
            ))
        };
    }
    Err(appended
        .err()
        .unwrap_or_else(|| "delimiter run was not recorded".into()))
}

fn run_investigation_command(args: &[String]) -> Result<(), String> {
    let command = args[0].as_str();
    if args.len() < 2 {
        return Err("missing investigation directory".into());
    }
    let root = Path::new(&args[1]);
    match command {
        "init" => {
            require_len(args, 3)?;
            print_json(&workflow::create(root, &args[2])?)
        }
        "hypothesis" => {
            require_len(args, 3)?;
            let hypothesis = Hypothesis {
                id: workflow::next_id(root, "hyp")?,
                claim: args[2].clone(),
                score: None,
                evidence: Vec::new(),
                counterexamples: Vec::new(),
            };
            print_json(&workflow::append(
                root,
                Event::HypothesisAdded { hypothesis },
            )?)
        }
        "evaluate" => {
            require_len(args, 6)?;
            let score: f64 = args[3]
                .parse()
                .map_err(|_| "score must be a number".to_string())?;
            print_json(&workflow::append(
                root,
                Event::HypothesisEvaluated {
                    hypothesis_id: args[2].clone(),
                    score,
                    evidence: ids(&args[4]),
                    counterexamples: ids(&args[5]),
                },
            )?)
        }
        "experiment" => {
            require_len(args, 5)?;
            let experiment = Experiment {
                id: workflow::next_id(root, "exp")?,
                question: args[2].clone(),
                hypothesis_ids: ids(&args[3]),
                prediction: args[4].clone(),
            };
            print_json(&workflow::append(
                root,
                Event::ExperimentCreated { experiment },
            )?)
        }
        "trial" => {
            require_len(args, 5)?;
            let trial = Trial {
                id: workflow::next_id(root, "trial")?,
                experiment_id: args[2].clone(),
                role: args[3].clone(),
                changed_factor: args[4].clone(),
            };
            print_json(&workflow::append(root, Event::TrialCreated { trial })?)
        }
        "import" => {
            require_len(args, 5)?;
            let raw = fs::read(&args[4]).map_err(|error| error.to_string())?;
            print_json(&workflow::import_capture(
                root, &args[2], &args[4], &args[3], &raw,
            )?)
        }
        "capture-command" => capture_command(root, args),
        "capture-step" => capture_step(root, args),
        "capture-start" => capture_start(root, args),
        "capture-stop" => {
            require_len(args, 3)?;
            capture_stop(root, &args[2])
        }
        "capture-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let run = state
                .capture_runs
                .iter()
                .find(|run| run.key == args[2])
                .ok_or_else(|| format!("unknown capture key {}", args[2]))?;
            let status = capture_status_name(root, run)?;
            print_json(&capture_run_view(&state, run, Some(status)))
        }
        "mark" => {
            require_len(args, 5)?;
            let action = Action {
                id: workflow::next_id(root, "action")?,
                trial_id: args[2].clone(),
                kind: args[3].clone(),
                detail: args[4].clone(),
                timestamp_ns: Some(workflow::now_ns()?),
                key: None,
            };
            print_json(&workflow::append(root, Event::ActionMarked { action })?)
        }
        "mark-keyed" => mark_keyed(root, args),
        "mark-at" => {
            require_len(args, 6)?;
            let timestamp_ns = args[3].parse().map_err(|_| {
                "timestamp must be UTC nanoseconds as an unsigned integer".to_string()
            })?;
            let action = Action {
                id: workflow::next_id(root, "action")?,
                trial_id: args[2].clone(),
                kind: args[4].clone(),
                detail: args[5].clone(),
                timestamp_ns: Some(timestamp_ns),
                key: None,
            };
            print_json(&workflow::append(root, Event::ActionMarked { action })?)
        }
        "tag" => {
            require_len(args, 5)?;
            let tag = Tag {
                id: workflow::next_id(root, "tag")?,
                observation_id: args[2].clone(),
                phase: args[3].clone(),
                label: args[4].clone(),
                action_id: None,
            };
            print_json(&workflow::append(root, Event::ObservationTagged { tag })?)
        }
        "tag-window" => tag_window(root, args),
        "tag-capture" => tag_capture(root, args),
        "capture-tag-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let batch = state
                .capture_tag_batches
                .iter()
                .find(|batch| batch.key == args[2])
                .ok_or_else(|| format!("unknown capture tag key {}", args[2]))?;
            print_json(&json!({"revision": state.revision, "batch": batch}))
        }
        "window-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let window = state
                .window_tags
                .iter()
                .find(|window| window.key == args[2])
                .ok_or_else(|| format!("unknown window key {}", args[2]))?;
            print_json(&json!({"revision": state.revision, "window": window}))
        }
        "value" => {
            require_len(args, 6)?;
            let value = parse_unsigned(&args[4])?;
            let set = match args[5].as_str() {
                "discovery" => ValueSet::Discovery,
                "validation" => ValueSet::Validation,
                _ => return Err("set must be discovery or validation".into()),
            };
            let known_value = KnownValue {
                id: workflow::next_id(root, "value")?,
                observation_id: args[2].clone(),
                variable: args[3].clone(),
                value,
                set,
            };
            print_json(&workflow::append(
                root,
                Event::ValueAnnotated { known_value },
            )?)
        }
        "infer-value" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::inference::infer_unsigned_field(
                &state, &args[2],
            )?)
        }
        "probe-delimiter" => {
            require_len(args, 5)?;
            let start_offset: usize = args[3]
                .parse()
                .map_err(|_| "start offset must be an unsigned integer".to_string())?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::delimiter::probe_observation(
                &state,
                &args[2],
                protocol_informatics_v2::delimiter::DelimiterConfig {
                    start_offset,
                    delimiter_hex: args[4].clone(),
                },
            )?)
        }
        "infer-delimiter" => {
            require_len(args, 4)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::delimiter::infer_delimiter(
                &state, &args[2], &args[3],
            )?)
        }
        "frame-value" => {
            require_len(args, 6)?;
            let value = parse_unsigned(&args[4])?;
            let set = match args[5].as_str() {
                "discovery" => ValueSet::Discovery,
                "validation" => ValueSet::Validation,
                _ => return Err("set must be discovery or validation".into()),
            };
            let known_value = FrameKnownValue {
                id: workflow::next_id(root, "frame-value")?,
                frame_id: args[2].clone(),
                variable: args[3].clone(),
                value,
                set,
            };
            print_json(&workflow::append(
                root,
                Event::FrameValueAnnotated { known_value },
            )?)
        }
        "infer-frame-value" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            print_json(
                &protocol_informatics_v2::inference::infer_frame_unsigned_field(&state, &args[2])?,
            )
        }
        "probe-framing" => {
            require_len(args, 9)?;
            let config = parse_framing_config(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::framing::probe_observation(
                &state, &args[2], config,
            )?)
        }
        "probe-tlv" => {
            require_len(args, 9)?;
            let config = parse_tlv_config(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::tlv::probe_tlv(
                &state, &args[2], config,
            )?)
        }
        "probe-varint" => {
            require_len(args, 7)?;
            let config = parse_varint_config(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::varint::probe_varint(
                &state, &args[2], config,
            )?)
        }
        "commit-framing" => commit_framing(root, args),
        "commit-varint" => commit_varint(root, args),
        "commit-delimiter" => commit_delimiter(root, args),
        "framing-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let run = state
                .framing_runs
                .iter()
                .find(|run| run.key == args[2])
                .ok_or_else(|| format!("unknown framing key {}", args[2]))?;
            print_json(&json!({"revision": state.revision, "run": run}))
        }
        "varint-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let run = state
                .varint_runs
                .iter()
                .find(|run| run.key == args[2])
                .ok_or_else(|| format!("unknown varint key {}", args[2]))?;
            print_json(&json!({"revision": state.revision, "run": run}))
        }
        "delimiter-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let run = state
                .delimiter_runs
                .iter()
                .find(|run| run.key == args[2])
                .ok_or_else(|| format!("unknown delimiter key {}", args[2]))?;
            print_json(&json!({"revision": state.revision, "run": run}))
        }
        "frames" => {
            if args.len() < 3 || args.len() > 5 {
                return Err("expected frame run key, optional offset and limit".into());
            }
            let state = workflow::load(root)?;
            let (run_id, key, observation_id, model, records) = if let Some(run) =
                state.framing_runs.iter().find(|run| run.key == args[2])
            {
                (
                    run.id.as_str(),
                    run.key.as_str(),
                    run.observation_id.as_str(),
                    "fixed_width",
                    run.records
                        .iter()
                        .map(|record| json!(record))
                        .collect::<Vec<_>>(),
                )
            } else if let Some(run) = state.varint_runs.iter().find(|run| run.key == args[2]) {
                (
                    run.id.as_str(),
                    run.key.as_str(),
                    run.observation_id.as_str(),
                    "unsigned_leb128",
                    run.records
                        .iter()
                        .map(|record| json!(record))
                        .collect::<Vec<_>>(),
                )
            } else if let Some(run) = state.delimiter_runs.iter().find(|run| run.key == args[2]) {
                (
                    run.id.as_str(),
                    run.key.as_str(),
                    run.observation_id.as_str(),
                    "delimiter",
                    run.records
                        .iter()
                        .map(|record| json!(record))
                        .collect::<Vec<_>>(),
                )
            } else {
                return Err(format!("unknown frame run key {}", args[2]));
            };
            let offset: usize = args.get(3).map_or(Ok(0), |value| {
                value.parse().map_err(|_| "offset must be an integer")
            })?;
            let limit: usize = args.get(4).map_or(Ok(50), |value| {
                value.parse().map_err(|_| "limit must be an integer")
            })?;
            if limit == 0 || limit > 100 {
                return Err("limit must be between 1 and 100".into());
            }
            let total = records.len();
            let records: Vec<_> = records.into_iter().skip(offset).take(limit).collect();
            let next_offset = (offset.saturating_add(limit) < total).then_some(offset + limit);
            print_json(
                &json!({"revision": state.revision, "framing_id": run_id, "key": key,
                "observation_id": observation_id, "model": model, "coordinate_system": "observation_bytes",
                "total": total, "offset": offset, "next_offset": next_offset, "frames": records}),
            )
        }
        "frame-span" => {
            require_len(args, 5)?;
            let start: usize = args[3].parse().map_err(|_| "start must be an integer")?;
            let end: usize = args[4].parse().map_err(|_| "end must be an integer")?;
            let state = workflow::load(root)?;
            let (run_id, observation_id, frame) = state
                .frame_by_id(&args[2])
                .ok_or_else(|| format!("unknown frame {}", args[2]))?;
            let length = frame.end - frame.start;
            if start >= end || end > length || end - start > 4096 {
                return Err(format!(
                    "invalid frame span [{start}, {end}); frame has {length} bytes and maximum span is 4096"
                ));
            }
            let absolute_start = frame.start + start;
            let absolute_end = frame.start + end;
            let span = protocol_informatics_v2::query::read_span(
                &state,
                observation_id,
                absolute_start,
                absolute_end,
            )?;
            let source_spans: Vec<_> = span
                .source_spans
                .iter()
                .map(|source| {
                    json!({
                        "message_start": source.message_start - frame.start,
                        "message_end": source.message_end - frame.start,
                        "packet_index": source.packet_index,
                        "file_offset": source.file_offset,
                    })
                })
                .collect();
            print_json(
                &json!({"revision": state.revision, "frame_id": frame.id, "framing_id": run_id,
                "observation_id": observation_id, "capture_id": span.capture_id, "artifact": span.artifact,
                "model": if run_id.starts_with("varint-") { "unsigned_leb128" } else if run_id.starts_with("delimiter-") { "delimiter" } else { "fixed_width" },
                "coordinate_system": "frame_bytes", "frame_length": length,
                "logical_length": frame.logical_end-frame.start, "start": start, "end": end,
                "observation_start": absolute_start, "observation_end": absolute_end,
                "source_file_offset": span.source_file_offset, "source_spans": source_spans,
                "bytes_hex": span.bytes_hex}),
            )
        }
        "infer-framing" => {
            require_len(args, 4)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::framing::infer_length_prefix(
                &state, &args[2], &args[3],
            )?)
        }
        "infer-tlv" => {
            require_len(args, 4)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::tlv::infer_tlv(
                &state, &args[2], &args[3],
            )?)
        }
        "infer-varint" => {
            require_len(args, 4)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::varint::infer_varint(
                &state, &args[2], &args[3],
            )?)
        }
        "infer-checksum" => {
            require_len(args, 7)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::checksum::infer_internet_checksum(
                &state, &args[2], &args[3], &args[4], &args[5], &args[6],
            )?)
        }
        "analyze-investigation" => {
            if args.len() > 3 {
                return Err("expected optional trial ID".into());
            }
            let state = workflow::load(root)?;
            let selected: Vec<_> = state
                .observations
                .iter()
                .filter(|observation| {
                    args.get(2).is_none_or(|trial_id| {
                        state.captures.iter().any(|capture| {
                            capture.id == observation.capture_id && &capture.trial_id == trial_id
                        })
                    })
                })
                .collect();
            let scope = args
                .get(2)
                .map_or(AnalysisScope::All, |trial_id| AnalysisScope::Trial {
                    trial_id: trial_id.clone(),
                });
            record_analysis(root, &selected, scope)
        }
        "cluster" => {
            if args.len() > 4 {
                return Err("expected optional trial ID and direction mode".into());
            }
            let state = workflow::load(root)?;
            let trial = args.get(2).filter(|id| *id != "-").map(String::as_str);
            print_json(&protocol_informatics_v2::clustering::cluster_observations(
                &state,
                trial,
                direction_mode(args.get(3))?,
            )?)
        }
        "validate-clusters" => {
            if args.len() < 4 || args.len() > 5 {
                return Err(
                    "expected discovery trial, validation trial, and optional direction mode"
                        .into(),
                );
            }
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::clustering::validate_clusters(
                &state,
                &args[2],
                &args[3],
                direction_mode(args.get(4))?,
            )?)
        }
        "pair-exchanges" => {
            if args.len() < 3 || args.len() > 6 {
                return Err("expected capture ID, optional max lag, offset, and page limit".into());
            }
            let max_lag_ms = args
                .get(3)
                .map(|value| {
                    value.parse::<u64>().map_err(|_| {
                        "max lag must be an unsigned number of milliseconds".to_string()
                    })
                })
                .transpose()?;
            let offset = args
                .get(4)
                .map(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|_| "pair offset must be an unsigned integer".to_string())
                })
                .transpose()?
                .unwrap_or(0);
            let limit = args
                .get(5)
                .map(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|_| "pair limit must be an unsigned integer".to_string())
                })
                .transpose()?
                .unwrap_or(20);
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::exchanges::pair_exchanges(
                &state, &args[2], max_lag_ms, offset, limit,
            )?)
        }
        "validate-exchanges" => {
            if args.len() < 4 || args.len() > 5 {
                return Err(
                    "expected discovery capture, validation capture, and optional max lag".into(),
                );
            }
            let max_lag_ms = args
                .get(4)
                .map(|value| {
                    value.parse::<u64>().map_err(|_| {
                        "max lag must be an unsigned number of milliseconds".to_string()
                    })
                })
                .transpose()?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::exchanges::validate_exchanges(
                &state, &args[2], &args[3], max_lag_ms,
            )?)
        }
        "analyze-cluster" => {
            if args.len() < 3 || args.len() > 5 {
                return Err("expected cluster ID, optional trial ID, and direction mode".into());
            }
            let state = workflow::load(root)?;
            let trial = args.get(3).filter(|id| *id != "-").map(String::as_str);
            let report = protocol_informatics_v2::clustering::cluster_observations(
                &state,
                trial,
                direction_mode(args.get(4))?,
            )?;
            let cluster = report
                .clusters
                .iter()
                .find(|cluster| cluster.id == args[2])
                .ok_or_else(|| {
                    format!("unknown cluster {} at revision {}", args[2], state.revision)
                })?;
            let members: std::collections::BTreeSet<_> =
                cluster.member_observation_ids.iter().collect();
            let selected: Vec<_> = state
                .observations
                .iter()
                .filter(|observation| members.contains(&observation.id))
                .collect();
            record_analysis(
                root,
                &selected,
                AnalysisScope::Cluster {
                    cluster_id: cluster.id.clone(),
                    trial_id: trial.map(str::to_owned),
                    direction_mode: if direction_mode(args.get(4))? {
                        "respect".into()
                    } else {
                        "ignore".into()
                    },
                },
            )
        }
        "decide" => {
            if args.len() < 3 || args.len() > 4 {
                return Err("expected decision and optional evidence IDs".into());
            }
            let decision = Decision {
                id: workflow::next_id(root, "decision")?,
                text: args[2].clone(),
                evidence_ids: args.get(3).map_or_else(Vec::new, |text| ids(text)),
            };
            print_json(&workflow::append(
                root,
                Event::DecisionRecorded { decision },
            )?)
        }
        "resume" => {
            require_len(args, 2)?;
            let state = workflow::load(root)?;
            print_json(
                &json!({"revision": state.revision, "question": state.question,
                "hypotheses": state.hypotheses, "experiments": state.experiments,
                "trials": state.trials, "captures": state.captures,
                "capture_runs": state.capture_runs,
                "framing_runs": state.framing_runs,
                "varint_runs": state.varint_runs,
                "delimiter_runs": state.delimiter_runs,
                "actions": state.actions, "window_tags": state.window_tags,
                "capture_tag_batches": state.capture_tag_batches,
                "observation_count": state.observations.len(), "tag_count": state.tags.len(),
                "known_value_count": state.known_values.len(),
                "frame_known_value_count": state.frame_known_values.len(),
                "analyses": state.analyses, "decisions": state.decisions}),
            )
        }
        "recover-tail" => {
            if args.len() < 2
                || args.len() > 3
                || args.get(2).is_some_and(|value| value != "--apply")
            {
                return Err("expected optional --apply".into());
            }
            print_json(&workflow::recover_tail(root, args.len() == 3)?)
        }
        "summary" => {
            require_len(args, 2)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::corpus_summary(&state))
        }
        "trials" => {
            let (offset, limit) = page_arguments(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::list_trials(
                &state, offset, limit,
            )?)
        }
        "experiments" => {
            let (offset, limit) = page_arguments(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::list_experiments(
                &state, offset, limit,
            )?)
        }
        "hypotheses" => {
            let (offset, limit) = page_arguments(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::list_hypotheses(
                &state, offset, limit,
            )?)
        }
        "decisions" => {
            let (offset, limit) = page_arguments(args)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::list_decisions(
                &state, offset, limit,
            )?)
        }
        "observations" => {
            if args.len() > 5 {
                return Err("expected optional trial ID, offset, and limit".into());
            }
            let state = workflow::load(root)?;
            let trial_id = args.get(2).filter(|id| *id != "-").map(String::as_str);
            let offset = args.get(3).map_or(Ok(0), |value| {
                value.parse().map_err(|_| "offset must be an integer")
            })?;
            let limit = args.get(4).map_or(Ok(50), |value| {
                value.parse().map_err(|_| "limit must be an integer")
            })?;
            print_json(&protocol_informatics_v2::query::list_observations(
                &state, trial_id, offset, limit,
            )?)
        }
        "search-observations" => {
            require_len(args, 3)?;
            let query: protocol_informatics_v2::query::ObservationSearch =
                serde_json::from_str(&args[2])
                    .map_err(|error| format!("invalid observation filter: {error}"))?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::search_observations(
                &state, &query,
            )?)
        }
        "span" => {
            require_len(args, 5)?;
            let start = args[3]
                .parse()
                .map_err(|_| "start must be an integer".to_string())?;
            let end = args[4]
                .parse()
                .map_err(|_| "end must be an integer".to_string())?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::read_span(
                &state, &args[2], start, end,
            )?)
        }
        "diff" => {
            require_len(args, 4)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::diff_observations(
                &state, &args[2], &args[3],
            )?)
        }
        "compare-trials" => {
            require_len(args, 4)?;
            let state = workflow::load(root)?;
            print_json(&protocol_informatics_v2::query::compare_trials(
                &state, &args[2], &args[3],
            )?)
        }
        "verify" => {
            require_len(args, 2)?;
            print_json(&workflow::verify(root)?)
        }
        "changes" => {
            require_len(args, 3)?;
            let revision = args[2]
                .parse()
                .map_err(|_| "revision must be an integer".to_string())?;
            print_json(&workflow::changes_since(root, revision, 100)?)
        }
        "report" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let html = protocol_informatics_v2::report::render(&state);
            fs::write(&args[2], html).map_err(|error| error.to_string())?;
            print_json(&json!({"path": args[2], "revision": state.revision}))
        }
        _ => Err(format!("unknown command: {command}")),
    }
}
