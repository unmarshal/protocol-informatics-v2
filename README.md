# Protocol Informatics v2

A new Rust implementation inspired by [Marshall Beddoe's Protocol Informatics](https://github.com/unmarshal/protocol-informatics). It helps an analyst or agent collect examples, test protocol hypotheses, and retain the evidence behind each decision. This is an early working baseline, not a general protocol reverse engineering system. No historical LGPL code has been imported.

## Quick start: an ICMP investigation

The repository includes a deterministic, 24-packet Ethernet/IPv4/ICMP echo capture. `examples/generate_icmp_fixture.py` regenerates the PCAP and a separate known-answer manifest. The sequence numbers cross the `255 → 256` boundary, which makes byte order and field width visible.

```sh
cargo test --offline
cargo run -- init /tmp/pi-icmp 'Where is the ICMP sequence number?'
cargo run -- hypothesis /tmp/pi-icmp 'Bytes 6..8 are a big-endian sequence'
cargo run -- experiment /tmp/pi-icmp 'Cross the low-byte boundary' hyp-000002 'Byte 6 changes at 256'
cargo run -- trial /tmp/pi-icmp exp-000003 baseline 'sequence number'
cargo run -- mark /tmp/pi-icmp trial-000004 stimulus 'Generate echo traffic'
cargo run -- import /tmp/pi-icmp trial-000004 pcap-icmp examples/icmp_echo.pcap
cargo run -- observations /tmp/pi-icmp trial-000004 8 4
cargo run -- span /tmp/pi-icmp obs-000006-0010 6 8
cargo run -- diff /tmp/pi-icmp obs-000006-0008 obs-000006-0010
cargo run -- tag /tmp/pi-icmp obs-000006-0010 stimulus 'sequence 256'
cargo run -- analyze-investigation /tmp/pi-icmp trial-000004
cargo run -- evaluate /tmp/pi-icmp hyp-000002 0.9 obs-000006-0008,obs-000006-0010 -
cargo run -- decide /tmp/pi-icmp 'Repeat with another payload' obs-000006-0010
cargo run -- resume /tmp/pi-icmp
cargo run -- changes /tmp/pi-icmp 6
cargo run -- verify /tmp/pi-icmp
cargo run -- report /tmp/pi-icmp /tmp/pi-icmp-report.html
```

For a controlled comparison, the generator also writes `icmp_baseline_255.pcap` and `icmp_variant_256.pcap`. They hold identifier and payload constant while changing the sequence. Put them in separate `baseline` and `variant` trials, then run `compare-trials <dir> <baseline-trial-id> <variant-trial-id>`. It pairs observations by direction and source order, reports unmatched messages, and counts changed byte offsets across pairs. The fixture changes only one checksum byte at `[3, 4)` and the sequence at `[6, 8)`. The sequence changes from `00ff` to `0100`. Pairing is a descriptive assumption; confirm it before treating differences as causal evidence.

The `evaluate` score is supplied by the analyst or agent. The program validates its range and evidence IDs, but does **not** calculate a probability that the hypothesis is true. `analyze-investigation` stores a separate descriptive alignment result; it does not evaluate the semantic claim.

The JSON CLI is the current agent interface. `observations` returns at most 100 previews per call, with an offset for paging. `span` reads at most 4096 bytes from one observation, using half-open `[start, end)` message-byte offsets and reporting the original PCAP file offset when available. `diff` shows changed contiguous byte ranges at original message offsets. `resume` returns the current investigation summary; `changes` returns up to 100 events after a revision. `verify` replays the log, checks artifact hashes, and compares extracted observations with original capture bytes. Every record carries a stable ID and the event log has monotonically increasing revisions.

For a command that emits classic PCAP or hex lines on standard output, use `capture-command` instead of `import`:

```sh
cargo run -- capture-command /tmp/pi-icmp trial-000004 pcap-icmp -- cat examples/icmp_echo.pcap
```

The command runs locally, must exit successfully, and is stopped if output exceeds 32 MiB. It is a generic acquisition hook, not yet a managed network capture service. Capture commands should be chosen with care because they execute as the current user.

The generated report is a self-contained, read-only HTML view with experiments, actions, hypotheses, decisions, observation filters, tags, and a byte inspector. Regenerate it after new events. The append-only source record is `/tmp/pi-icmp/.pi/events.jsonl`; immutable raw captures and analysis JSON live under `/tmp/pi-icmp/.pi/artifacts/` with SHA-256 names. Keep the whole directory to preserve provenance.

## One-shot analysis

```sh
cargo run -- analyze examples/toy_messages.hex
cargo run -- analyze examples/toy_messages.hex --json
```

Hex input has one extracted message per line; spaces and colons are allowed. Blank lines and `#` comments are ignored. The analyzer compares position-preserving columns to a global star alignment, choosing the lower observed column entropy plus width penalty. This simple selection keeps fixed ICMP headers at their true offsets while allowing gaps in the variable-length toy example. The CPU pairwise aligner has a 25-million-cell limit. Column statistics are measurements, not field boundaries or meaning.

## Current scope and next work

Classic PCAP ingestion currently supports Ethernet, unfragmented IPv4, and ICMP messages. It does not support pcapng, VLANs, IPv6, TCP stream reassembly, file-format record boundaries, or managed live capture. The HTML view is read-only. The event log is intended for one writer; parallel agents need a transactional writer and stable action handles. The fixture tests parsing, exact source offsets, checksums, and the alignment strategy against independent known answers.

The next inference step is to compare controlled baseline and variant trials, cluster message roles before alignment, then test candidate lengths, counters, checksums, and request/response relations on held-out examples. See the [workflow](docs/iterative-workflow.md), [interface design](docs/interface-design.md), and [experiment lifecycle](docs/experiment-lifecycle.md) for the fuller direction. GPU acceleration can wait for representative CPU profiles.

## Licensing

This implementation is dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. The historical repository retains its own LGPL-2.1 terms.
