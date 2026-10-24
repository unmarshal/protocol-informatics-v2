use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use protocol_informatics_v2::workflow::{
    self, Action, AnalysisRecord, AnalysisScope, CaptureRun, CaptureRunStatus, Decision, Event,
    Experiment, Hypothesis, KnownValue, Observation, Tag, Trial, ValueSet,
};
use protocol_informatics_v2::{CpuAligner, analyze_best, parse_hex_samples};
use serde::Serialize;
use serde_json::json;

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
    run_investigation_command(&args)
}

fn print_help() {
    println!("Protocol Informatics v2\n");
    println!("  analyze <hex-file> [--json]          one-shot alignment");
    println!("  init <dir> <question>                create investigation");
    println!("  hypothesis <dir> <claim>             add hypothesis");
    println!("  evaluate <dir> <hyp-id> <score> <evidence-ids> <counterexample-ids>");
    println!("  experiment <dir> <question> <hyp-ids> <prediction>");
    println!("  trial <dir> <exp-id> <role> <changed-factor>");
    println!(
        "  import <dir> <trial-id> <hex|binary|pcap-icmp|pcapng-icmp|pcap-udp|pcapng-udp|pcap-tcp|pcapng-tcp|pcap-tcp-stream|pcapng-tcp-stream> <file>"
    );
    println!(
        "  capture-command <dir> <trial-id> <format> <key> <timeout-ms> -- <program> [args...]"
    );
    println!("  capture-status <dir> <key>           inspect a reserved capture command");
    println!("  mark <dir> <trial-id> <kind> <detail>");
    println!("  tag <dir> <obs-id> <phase> <label>");
    println!("  value <dir> <obs-id> <variable> <unsigned> <discovery|validation>");
    println!("  infer-value <dir> <variable>         find exact unsigned field candidates");
    println!(
        "  infer-checksum <dir> <discovery-trial> <validation-trial> <baseline-trial> <variant-trial> <controlled-variable>"
    );
    println!("  analyze-investigation <dir> [trial-id]");
    println!("  cluster <dir> [trial-id|-] [respect|ignore]");
    println!("  analyze-cluster <dir> <cluster-id> [trial-id|-] [respect|ignore]");
    println!("  decide <dir> <decision> [evidence-ids]");
    println!("  resume <dir> | changes <dir> <revision> | report <dir> <html-file>");
    println!("  observations <dir> [trial-id|-] [offset] [limit<=100]");
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
    })
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
                (run.status == CaptureRunStatus::Reserved).then_some("running"),
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
    };
    workflow::append(root, Event::CaptureRunReserved { run: reserved })?;
    let result = protocol_informatics_v2::capture::run_command(argv, timeout_ms).and_then(|raw| {
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
        "capture-status" => {
            require_len(args, 3)?;
            let state = workflow::load(root)?;
            let run = state
                .capture_runs
                .iter()
                .find(|run| run.key == args[2])
                .ok_or_else(|| format!("unknown capture key {}", args[2]))?;
            let status = if run.status == CaptureRunStatus::Reserved {
                if workflow::capture_run_lock(root, &run.key)?.is_some() {
                    Some("interrupted")
                } else {
                    Some("running")
                }
            } else {
                None
            };
            print_json(&capture_run_view(&state, run, status))
        }
        "mark" => {
            require_len(args, 5)?;
            let action = Action {
                id: workflow::next_id(root, "action")?,
                trial_id: args[2].clone(),
                kind: args[3].clone(),
                detail: args[4].clone(),
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
            };
            print_json(&workflow::append(root, Event::ObservationTagged { tag })?)
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
                "observation_count": state.observations.len(), "tag_count": state.tags.len(),
                "known_value_count": state.known_values.len(),
                "analyses": state.analyses, "decisions": state.decisions}),
            )
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
