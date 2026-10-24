use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;

use protocol_informatics_v2::workflow::{
    self, Action, AnalysisRecord, Decision, Event, Experiment, Hypothesis, KnownValue, Tag, Trial,
    ValueSet,
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
    println!("  import <dir> <trial-id> <hex|pcap-icmp|pcapng-icmp> <file>");
    println!(
        "  capture-command <dir> <trial-id> <hex|pcap-icmp|pcapng-icmp> -- <program> [args...]"
    );
    println!("  mark <dir> <trial-id> <kind> <detail>");
    println!("  tag <dir> <obs-id> <phase> <label>");
    println!("  value <dir> <obs-id> <variable> <unsigned> <discovery|validation>");
    println!("  infer-value <dir> <variable>         find exact unsigned field candidates");
    println!("  analyze-investigation <dir> [trial-id]");
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
        "capture-command" => {
            if args.len() < 7 || args[4] != "--" {
                return Err("expected -- <program> [args...]".into());
            }
            let mut child = Command::new(&args[5])
                .args(&args[6..])
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|error| format!("capture command failed to start: {error}"))?;
            let mut raw = Vec::new();
            let read_result = child
                .stdout
                .take()
                .expect("piped stdout")
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut raw);
            if let Err(error) = read_result {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("capture output could not be read: {error}"));
            }
            if raw.len() > 32 * 1024 * 1024 {
                let _ = child.kill();
                let _ = child.wait();
                return Err("capture output exceeds 32 MiB".into());
            }
            let status = child.wait().map_err(|error| error.to_string())?;
            if !status.success() {
                return Err(format!(
                    "capture command exited {status}; see command stderr for details"
                ));
            }
            let source = format!("command: {}", args[5..].join(" "));
            print_json(&workflow::import_capture(
                root, &args[2], &source, &args[3], &raw,
            )?)
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
            if selected.is_empty() {
                return Err("no observations selected".into());
            }
            let samples: Vec<Vec<u8>> = selected
                .iter()
                .map(|observation| workflow::from_hex(&observation.bytes_hex))
                .collect::<Result<_, _>>()?;
            let analysis =
                analyze_best(&samples, &CpuAligner).map_err(|error| error.to_string())?;
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
            };
            print_json(&workflow::append(
                root,
                Event::AnalysisRecorded { analysis: record },
            )?)
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
