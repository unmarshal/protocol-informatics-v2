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
const STOP_GRACE_MS: u64 = 2_000;

pub fn run_command(argv: &[String], timeout_ms: u64) -> Result<Vec<u8>, String> {
    run_command_with_stop(argv, timeout_ms, || Ok(false))
}

pub fn run_command_with_stop<F>(
    argv: &[String],
    timeout_ms: u64,
    mut stop_requested: F,
) -> Result<Vec<u8>, String>
where
    F: FnMut() -> Result<bool, String>,
{
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
    let mut stop_at = None;
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
            if !status.success() && stop_at.is_none() {
                stop_process_group(&mut child);
                return Err(format!("capture command exited {status}"));
            }
            if let Some(raw) = output {
                return Ok(raw);
            }
        }
        if stop_at.is_none() {
            match stop_requested() {
                Ok(true) => {
                    interrupt_process_group(&mut child);
                    stop_at = Some(Instant::now());
                }
                Ok(false) => {}
                Err(error) => {
                    stop_process_group(&mut child);
                    return Err(format!("capture stop status could not be checked: {error}"));
                }
            }
        }
        if stop_at.is_some_and(|at| at.elapsed() >= Duration::from_millis(STOP_GRACE_MS)) {
            stop_process_group(&mut child);
            if output.is_none() {
                let raw = receiver
                    .recv_timeout(Duration::from_millis(500))
                    .map_err(|_| "capture output did not close after stop".to_string())?
                    .map_err(|error| format!("capture output could not be read: {error}"))?;
                if raw.len() > MAX_CAPTURE_BYTES {
                    return Err("capture output exceeds 32 MiB".into());
                }
                output = Some(raw);
            }
            return Ok(output.expect("output received after stop"));
        }
        if stop_at.is_none() && Instant::now() >= deadline {
            stop_process_group(&mut child);
            return Err(format!("capture command timed out after {timeout_ms} ms"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn interrupt_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let process_group = child.id() as libc::pid_t;
        unsafe {
            libc::kill(-process_group, libc::SIGINT);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DumpcapOptions {
    pub executable: String,
    pub interface: String,
    pub capture_filter: String,
    pub duration_ms: u64,
    pub output_byte_limit: usize,
    pub packet_limit: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptureConditions {
    pub backend: String,
    pub executable: String,
    pub version: String,
    pub interface: String,
    pub capture_filter: String,
    pub duration_ms: u64,
    pub output_byte_limit: usize,
    pub packet_limit: Option<u64>,
    pub started_at_ns: u64,
    pub ended_at_ns: u64,
    pub exit_code: Option<i32>,
    pub stop_reason: String,
    pub quality: crate::pcap::PcapngQuality,
}

impl DumpcapOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.interface.is_empty()
            || self.interface.len() > 1024
            || self.capture_filter.len() > 4096
            || self.executable.is_empty()
            || self.duration_ms == 0
            || self.duration_ms > MAX_TIMEOUT_MS
            || !(1024..=MAX_CAPTURE_BYTES).contains(&self.output_byte_limit)
            || self.packet_limit == Some(0)
        {
            return Err("invalid_dumpcap_options: interface required; duration 1..600000 ms; byte limit 1024..33554432; packet limit positive".into());
        }
        Ok(())
    }
}

struct TemporaryCapture(std::path::PathBuf);
impl Drop for TemporaryCapture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn wall_clock_ns() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos()
        .try_into()
        .map_err(|_| "wall clock overflow".into())
}

/// Capture directly to a private regular file. RLIMIT_FSIZE is a hard bound,
/// independent of dumpcap's approximate kB autostop threshold and polling.
#[cfg(unix)]
pub fn run_dumpcap<F>(
    options: &DumpcapOptions,
    mut stop_requested: F,
) -> Result<(Vec<u8>, CaptureConditions), String>
where
    F: FnMut() -> Result<bool, String>,
{
    use std::os::unix::fs::DirBuilderExt;
    options.validate()?;
    let executable = if options.executable.contains('/') {
        std::fs::canonicalize(&options.executable).ok()
    } else {
        std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|path| path.join(&options.executable))
                    .find(|path| path.is_file())
            })
            .and_then(|path| std::fs::canonicalize(path).ok())
    }
    .ok_or("dumpcap_unavailable: executable not found")?;
    let executable_text = executable.to_string_lossy().into_owned();
    let version = run_command(&[executable_text.clone(), "--version".into()], 5000)
        .map_err(|e| format!("dumpcap_unavailable: {e}"))?;
    let version = String::from_utf8_lossy(&version)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(512)
        .collect::<String>();
    if version.is_empty() {
        return Err("dumpcap_unavailable: empty version".into());
    }
    let mut directory = None;
    for attempt in 0..100 {
        let path = std::env::temp_dir().join(format!(
            "pi-dumpcap-{}-{}-{attempt}",
            std::process::id(),
            wall_clock_ns()?
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                directory = Some(TemporaryCapture(path));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    let directory = directory.ok_or("could not allocate capture directory")?;
    let output_path = directory.0.join("capture.pcapng");
    let stderr_path = directory.0.join("stderr");
    let stderr = std::fs::File::create(&stderr_path).map_err(|e| e.to_string())?;
    let mut command = Command::new(&executable);
    command
        .args([
            "-q",
            "-n",
            "-i",
            &options.interface,
            "-f",
            &options.capture_filter,
            "-a",
            &format!("duration:{}", options.duration_ms as f64 / 1000.0),
            "-a",
            &format!("filesize:{}", options.output_byte_limit / 1024),
            "-w",
        ])
        .arg(&output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .process_group(0);
    if let Some(limit) = options.packet_limit {
        command.arg("-c").arg(limit.to_string());
    }
    let byte_limit = options.output_byte_limit as libc::rlim_t;
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: byte_limit,
                rlim_max: byte_limit,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let started_at_ns = wall_clock_ns()?;
    let mut child = command
        .spawn()
        .map_err(|e| format!("dumpcap_unavailable: {e}"))?;
    let deadline = Instant::now() + Duration::from_millis(options.duration_ms + 2000);
    let mut stop_at = None;
    let mut reason = "completed";
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        let stop = match stop_requested() {
            Ok(stop) => stop,
            Err(e) => {
                stop_process_group(&mut child);
                return Err(e);
            }
        };
        if stop_at.is_none() && (stop || Instant::now() >= deadline) {
            reason = if stop {
                "stop_requested"
            } else {
                "duration_watchdog"
            };
            interrupt_process_group(&mut child);
            stop_at = Some(Instant::now());
        }
        if stop_at.is_some_and(|at| at.elapsed() >= Duration::from_millis(STOP_GRACE_MS)) {
            stop_process_group(&mut child);
            break child.wait().map_err(|e| e.to_string())?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    // Ensure descendants cannot mutate the file while it is read/imported.
    stop_process_group(&mut child);
    let ended_at_ns = wall_clock_ns()?;
    let size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    if size >= options.output_byte_limit as u64 {
        return Err("output_limit_exceeded: dumpcap file reached byte limit".into());
    }
    if !status.success() && stop_at.is_none() {
        let mut diagnostic = String::new();
        std::fs::File::open(stderr_path)
            .map_err(|e| e.to_string())?
            .take(4096)
            .read_to_string(&mut diagnostic)
            .map_err(|e| e.to_string())?;
        let code = if diagnostic.to_lowercase().contains("permission")
            || diagnostic.contains("Operation not permitted")
        {
            "capture_permission_unavailable"
        } else {
            "dumpcap_failed"
        };
        return Err(format!("{code}: {status}: {diagnostic}"));
    }
    let raw = std::fs::read(output_path).map_err(|e| format!("invalid_capture_output: {e}"))?;
    let quality =
        crate::pcap::pcapng_quality(&raw).map_err(|e| format!("invalid_capture_output: {e}"))?;
    let conditions = CaptureConditions {
        backend: "dumpcap".into(),
        executable: executable_text,
        version,
        interface: options.interface.clone(),
        capture_filter: options.capture_filter.clone(),
        duration_ms: options.duration_ms,
        output_byte_limit: options.output_byte_limit,
        packet_limit: options.packet_limit,
        started_at_ns,
        ended_at_ns,
        exit_code: status.code(),
        stop_reason: reason.into(),
        quality,
    };
    Ok((raw, conditions))
}

#[cfg(not(unix))]
pub fn run_dumpcap<F>(
    _options: &DumpcapOptions,
    _stop_requested: F,
) -> Result<(Vec<u8>, CaptureConditions), String>
where
    F: FnMut() -> Result<bool, String>,
{
    Err("dumpcap_unavailable: hard file bounds currently require Unix".into())
}
