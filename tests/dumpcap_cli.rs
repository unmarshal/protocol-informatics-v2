#![cfg(unix)]
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

struct Workspace(PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn call(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_protocol-informatics-v2"))
        .arg(args[0])
        .arg(root)
        .args(&args[1..])
        .output()
        .unwrap()
}
fn json(root: &Path, args: &[&str]) -> Value {
    let output = call(root, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn setup() -> (Workspace, String, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "pi-dumpcap-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    json(&root, &["init", "capture test"]);
    let exp = json(&root, &["experiment", "echo", "-", "sequence changes"]);
    let trial = json(
        &root,
        &[
            "trial",
            exp["event"]["experiment"]["id"].as_str().unwrap(),
            "discovery",
            "sequence",
        ],
    );
    let fake = root.join("fake dumpcap");
    fs::write(
        &fake,
        format!(
            r#"#!/usr/bin/env python3
import sys, pathlib, time, resource
if '--version' in sys.argv:
    print('Dumpcap (fake) 1.0')
    sys.exit(0)
a=sys.argv
assert '-n' in a
assert a[a.index('-f')+1] == 'icmp'
assert a[a.index('-c')+1] == '24'
assert a.count('-a') == 2
mode=a[a.index('-i')+1]
out=pathlib.Path(a[a.index('-w')+1])
if mode=='permission':
    print('Permission denied opening interface',file=sys.stderr)
    sys.exit(1)
if mode=='invalid':
    out.write_bytes(b'invalid pcapng')
elif mode=='oversize':
    out.write_bytes(b'x'*(resource.getrlimit(resource.RLIMIT_FSIZE)[0]+1))
else:
    out.write_bytes(pathlib.Path({fixture:?}).read_bytes())
if mode=='wait':
    (pathlib.Path(__file__).parent/'ready').write_text('ready')
    time.sleep(60)
"#,
            fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples/icmp_echo.pcapng")
                .to_str()
                .unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    (
        Workspace(root),
        trial["event"]["trial"]["id"].as_str().unwrap().to_owned(),
        fake,
    )
}
#[allow(clippy::too_many_arguments)]
fn capture(
    root: &Path,
    trial: &str,
    fake: &Path,
    key: &str,
    mode: &str,
    background: bool,
    duration: &str,
    limit: &str,
) -> Output {
    call(
        root,
        &[
            if background {
                "network-capture-start"
            } else {
                "network-capture"
            },
            trial,
            key,
            mode,
            "icmp",
            duration,
            limit,
            "24",
            "pcapng-icmp",
            fake.to_str().unwrap(),
        ],
    )
}
#[test]
fn dumpcap_retains_exact_evidence_and_replays_retry() {
    let (root, trial, fake) = setup();
    let root = &root.0;
    let result = capture(
        root, &trial, &fake, "success", "ok", false, "1000", "1048576",
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "completed");
    let capture = &value["capture"];
    assert_eq!(
        capture["conditions"]["quality"]["captured_packet_count"],
        24
    );
    assert_eq!(
        capture["conditions"]["quality"]["interfaces"][0]["link_type"],
        1
    );
    assert!(capture["conditions"]["quality"]["interfaces"][0]["dropped_packets"].is_null());
    assert_eq!(
        fs::read(root.join(capture["artifact"].as_str().unwrap())).unwrap(),
        include_bytes!("../examples/icmp_echo.pcapng")
    );
    let repeat = capture_output(root, &trial, &fake, "success");
    assert_eq!(repeat["capture"]["id"], capture["id"]);
    assert_eq!(repeat["revision"], value["revision"]);
    let state = protocol_informatics_v2::workflow::load(root).unwrap();
    let expected = protocol_informatics_v2::pcap::extract_pcapng_icmp_messages(include_bytes!(
        "../examples/icmp_echo.pcapng"
    ))
    .unwrap();
    for (observation, packet) in state.observations.iter().zip(expected) {
        assert_eq!(observation.source_offset, Some(packet.source_offset));
        assert_eq!(observation.timestamp_ns, Some(packet.timestamp_ns));
        assert_eq!(
            observation.bytes_hex,
            protocol_informatics_v2::workflow::to_hex(&packet.bytes)
        );
    }
    json(root, &["verify"]);
    let report = root.join("capture-report.html");
    json(root, &["report", report.to_str().unwrap()]);
    let html = fs::read_to_string(report).unwrap();
    assert!(html.contains("Dumpcap (fake) 1.0"));
    assert!(html.contains("dropped_packets"));
    assert_eq!(
        json(root, &["attention"])["network_captures"][0]["id"],
        capture["id"]
    );
    let validation = json(root, &["trial", "exp-000002", "validation", "sequence"]);
    assert_eq!(
        json(
            root,
            &[
                "review-trials",
                &trial,
                validation["event"]["trial"]["id"].as_str().unwrap()
            ]
        )["network_captures"][0]["id"],
        capture["id"]
    );
    let conflict = capture_output_failure(root, &trial, &fake, "success", "invalid", "1048576");
    assert!(conflict.contains("different arguments"));
}
fn capture_output(root: &Path, trial: &str, fake: &Path, key: &str) -> Value {
    serde_json::from_slice(&capture(root, trial, fake, key, "ok", false, "1000", "1048576").stdout)
        .unwrap()
}
fn capture_output_failure(
    root: &Path,
    trial: &str,
    fake: &Path,
    key: &str,
    mode: &str,
    limit: &str,
) -> String {
    let result = capture(root, trial, fake, key, mode, false, "1000", limit);
    assert!(!result.status.success());
    String::from_utf8_lossy(&result.stderr).into_owned()
}
#[test]
fn dumpcap_failure_is_durable_and_file_is_bounded() {
    let (root, trial, fake) = setup();
    let root = &root.0;
    for (key, mode, code, limit) in [
        ("invalid", "invalid", "invalid_capture_output", "1048576"),
        (
            "permission",
            "permission",
            "capture_permission_unavailable",
            "1048576",
        ),
        ("oversize", "oversize", "output_limit_exceeded", "1024"),
    ] {
        assert!(capture_output_failure(root, &trial, &fake, key, mode, limit).contains(code));
        let status = json(root, &["capture-status", key]);
        assert_eq!(status["status"], "failed");
        assert_eq!(status["error_code"], code);
        assert!(
            capture_output_failure(root, &trial, &fake, key, mode, limit)
                .contains("already failed")
        );
    }
    assert!(
        capture_output_failure(
            root,
            &trial,
            &root.join("missing"),
            "missing",
            "ok",
            "1048576"
        )
        .contains("dumpcap_unavailable")
    );
    assert!(
        protocol_informatics_v2::workflow::load(root)
            .unwrap()
            .captures
            .is_empty()
    );
}
#[test]
fn dumpcap_stop_and_duration_watchdog_import_valid_partial_file() {
    let (root, trial, fake) = setup();
    let root = &root.0;
    let result = capture(
        root, &trial, &fake, "stop", "wait", true, "60000", "1048576",
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    // Wait until the fake has flushed a complete file before requesting stop.
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while !root.join("ready").exists() {
        assert!(
            Instant::now() < ready_deadline,
            "fake capture did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    json(root, &["capture-stop", "stop"]);
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        let status = json(root, &["capture-status", "stop"]);
        if status["status"] == "completed" {
            assert_eq!(
                status["capture"]["conditions"]["stop_reason"],
                "stop_requested"
            );
            break;
        }
        assert!(Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(30));
    }
    let result = capture(
        root, &trial, &fake, "watchdog", "wait", false, "1", "1048576",
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        result["capture"]["conditions"]["stop_reason"],
        "duration_watchdog"
    );
    json(root, &["verify"]);
}
