# Bounded dumpcap acquisition

`network-capture` runs dumpcap synchronously; `network-capture-start` starts the same acquisition in a background worker. Both use the existing event log, capture-run reservation, retry key, stop request, import, and content-addressed artifact store.

```sh
cargo run -- network-capture-start /tmp/pi trial-000004 baseline-255 eth0 'icmp' 5000 1048576 24 pcapng-icmp
cargo run -- capture-status /tmp/pi baseline-255
cargo run -- capture-stop /tmp/pi baseline-255
cargo run -- verify /tmp/pi
```

Arguments after the investigation directory are trial ID, retry key, interface, capture filter, duration in milliseconds, maximum output bytes, optional packet count (`-` means absent), extraction format, and optional dumpcap executable path. Duration is 1–600000 ms; output is 1024–33554432 bytes; packet count must be positive. Supported extraction formats are `pcapng-icmp`, `pcapng-icmpv6`, `pcapng-udp`, `pcapng-tcp`, and `pcapng-tcp-stream`. Transport extraction currently requires Ethernet link type 1; many loopback interfaces use other link types.

Dumpcap receives an argument vector with `-i`, `-f`, duration and filesize autostop conditions, `-w`, and optionally `-c`. No shell is inserted. Capture runs as the current user. This adapter currently requires Unix for the hard `RLIMIT_FSIZE` file bound. The private temporary directory has mode 0700 and is cleaned on normal completion or failure. The OS enforces the exact byte ceiling; dumpcap's own approximate kilobyte limit can stop earlier. A file that reaches the ceiling is rejected, since it may contain a partially written block. No truncation or repair is performed. The parent interrupts a backend that exceeds duration by two seconds, then allows two seconds to flush before forcing termination. Valid bytes after an explicit stop or watchdog stop can still be imported; malformed or empty supported-message output fails.

The exact pcapng file is retained unchanged with its SHA-256 hash. Conditions live on the same `capture_imported` event as the artifact reference. Start/end UTC nanoseconds describe the acquisition process, while observation timestamps come from the capture. A normal backend exit records `completed` and its exit code; this does not distinguish which dumpcap autostop criterion fired. Parent stops record `stop_requested` or `duration_watchdog`.

Repeated arguments and a successful key return the same capture and observation IDs without new events, even if dumpcap is subsequently unavailable. Conflicting arguments fail. Failed or interrupted keys require a new key to execute again. `capture-status` includes `error` and `error_code` (for example `dumpcap_unavailable`, `capture_permission_unavailable`, `invalid_capture_output`, or `output_limit_exceeded`). Inspect this durable status after a background start; the start response can precede backend failure.

## Conditions and quality

Schema 20 adds optional `Capture.conditions`. Existing captures without it still replay. It records backend, resolved executable path, version's first line, interface, filter, requested duration/byte/packet limits, UTC start/end nanoseconds, exit code, stop reason, and pcapng quality. Quality counts all Enhanced Packet Blocks, including packets excluded by transport extraction; this differs from the capture's extracted observation count.

Each Interface Description Block records section index, interface ID, link type, snapshot length, and packet count. The latest Interface Statistics Block for that interface provides `received_packets` (isb_ifrecv), `dropped_packets` (isb_ifdrop), and `os_dropped_packets` (isb_osdrop). Missing statistics are JSON null; measured zero stays zero. Interfaces and statistics are section-scoped, including mixed-endian sections. `verify` recomputes quality from the original artifact in addition to verifying hashes, extraction bytes, timestamps, and source spans.

Recent network captures and their conditions appear in `attention` (maximum 20 plus omitted count), `activity`, `review-trials` (maximum 20 plus omitted count), and the HTML capture-run section. Existing capture-scope tagging remains available through `mark-keyed` and `tag-capture`. Acquisition during an action does not establish that background traffic is a causal response.

## Optional live smoke test

`examples/live_dumpcap_smoke.py` sends ICMP echo sequences 255 and 256 with a fixed identifier and payload, in separate baseline and variant trials. Supply an Ethernet interface and IPv4 target you control, an unused investigation directory, and a built CLI path:

```sh
python3 examples/live_dumpcap_smoke.py eth0 192.0.2.10 /tmp/pi-live target/release/protocol-informatics-v2
```

The script needs raw-socket privileges and dumpcap capture permission. It records exact stimulus bytes, target, interface, and time as action markers, tags acquisition scope, prints matched request/reply IDs for each sequence, saves the trial comparison and report, and verifies the artifacts. Missing replies remain explicit; network behavior can make the result inconclusive. CI uses a fake dumpcap and never requires these permissions.

Dumpcap option semantics follow the [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html). Metadata uses the [pcapng format](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/).

## Live validation result (2026-10-24)

The smoke script passed with real dumpcap 4.6.9 on a temporary Ethernet veth pair, with its peer in an isolated Linux network namespace. The sender used 198.18.0.1 and the peer 198.18.0.2. Each four-second capture contained one echo request and reply, with zero reported interface drops; OS drop counters were absent. Both direction-matched comparisons changed sequence bytes `[6, 8)` from `00ff` to `0100` and checksum byte `[3, 4)` from `1b` to `1a`. There were no unmatched observations.

Both original pcapng hashes, source byte spans, ICMP checksums, and `verify` passed. Repeating each successful key after deleting the temporary network returned the same capture ID without changing the revision. The network namespace and veth pair were removed after testing. The live run exposed and fixed the smoke script's keyed-action response lookup (`action.id` rather than `event.action.id`).
