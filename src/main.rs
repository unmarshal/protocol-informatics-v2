use std::env;
use std::fs;
use std::process::ExitCode;

use protocol_informatics_v2::{CpuAligner, analyze, parse_hex_samples};

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
        println!("Usage: protocol-informatics-v2 analyze <hex-lines-file> [--json]");
        println!("Each nonempty line contains one byte sequence as hexadecimal text.");
        return Ok(());
    }
    if args.first().map(String::as_str) != Some("analyze") {
        return Err("expected the 'analyze' command".into());
    }
    let mut path = None;
    let mut json = false;
    for arg in &args[1..] {
        if arg == "--json" {
            json = true;
        } else if arg.starts_with('-') || path.replace(arg).is_some() {
            return Err(format!("unexpected argument: {arg}"));
        }
    }
    let path = path.ok_or("missing hex-lines-file")?;
    let input = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let samples = parse_hex_samples(&input).map_err(|error| error.to_string())?;
    let result = analyze(&samples, &CpuAligner).map_err(|error| error.to_string())?;

    if json {
        println!("{}", result.to_json());
    } else {
        println!("samples: {}", samples.len());
        println!("reference sample: {}", result.reference_index + 1);
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
