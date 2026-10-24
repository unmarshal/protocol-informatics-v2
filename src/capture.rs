//! Bounded execution for commands that emit a capture on standard output.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub const MAX_CAPTURE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_TIMEOUT_MS: u64 = 600_000;

pub fn run_command(argv: &[String], timeout_ms: u64) -> Result<Vec<u8>, String> {
    if argv.is_empty() || timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err("capture command needs a program and a timeout from 1 to 600000 ms".into());
    }
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).stdout(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| format!("capture command failed to start: {error}"))?;
    let stdout = child.stdout.take().expect("capture stdout is piped");
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut raw = Vec::new();
        let result = stdout
            .take((MAX_CAPTURE_BYTES + 1) as u64)
            .read_to_end(&mut raw)
            .map(|_| raw)
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = None;
    let mut exit_status = None;
    loop {
        if output.is_none() {
            match receiver.try_recv() {
                Ok(result) => match result {
                    Ok(raw) if raw.len() <= MAX_CAPTURE_BYTES => output = Some(raw),
                    Ok(_) => {
                        stop_process_group(&mut child);
                        return Err("capture output exceeds 32 MiB".into());
                    }
                    Err(error) => {
                        stop_process_group(&mut child);
                        return Err(format!("capture output could not be read: {error}"));
                    }
                },
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    stop_process_group(&mut child);
                    return Err("capture output reader stopped unexpectedly".into());
                }
            }
        }
        if exit_status.is_none() {
            match child.try_wait() {
                Ok(status) => exit_status = status,
                Err(error) => {
                    stop_process_group(&mut child);
                    return Err(format!("capture command status failed: {error}"));
                }
            }
        }
        if let Some(status) = exit_status {
            if !status.success() {
                stop_process_group(&mut child);
                return Err(format!("capture command exited {status}"));
            }
            if let Some(raw) = output {
                return Ok(raw);
            }
        }
        if Instant::now() >= deadline {
            stop_process_group(&mut child);
            return Err(format!("capture command timed out after {timeout_ms} ms"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn stop_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let process_group = child.id() as libc::pid_t;
        // The child is spawned into its own group; stopping that group also
        // closes pipes inherited by descendants before this CLI exits.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
