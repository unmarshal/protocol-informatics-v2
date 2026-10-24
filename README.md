# Protocol Informatics v2

A new Rust implementation inspired by [Marshall Beddoe's Protocol Informatics](https://github.com/unmarshal/protocol-informatics). It helps an analyst or agent collect examples, test protocol hypotheses, and retain the evidence behind each decision. This is an early working baseline, not a general protocol reverse engineering system. No historical LGPL code has been imported.

## Quick start: an ICMP investigation

The repository includes a deterministic, 24-packet Ethernet/IPv4/ICMP echo capture. `examples/generate_icmp_fixture.py` regenerates the PCAP and a separate known-answer manifest. The sequence numbers cross the `255 → 256` boundary, which makes byte order and field width visible.

The same packets are available in `examples/icmp_echo.pcapng`; replace `pcap-icmp examples/icmp_echo.pcap` with `pcapng-icmp examples/icmp_echo.pcapng` in the commands below to exercise that reader. The pcapng reader handles Section Header, Interface Description, and Enhanced Packet Blocks, including interface timestamp resolution and offset. Its field interpretation follows the [IETF pcapng draft](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-opsawg-pcapng-06.html).

```sh
cargo test --offline
cargo run -- init /tmp/pi-icmp 'Where is the ICMP sequence number?'
cargo run -- hypothesis /tmp/pi-icmp 'Bytes 6..8 are a big-endian sequence'
cargo run -- experiment /tmp/pi-icmp 'Cross the low-byte boundary' hyp-000002 'Byte 6 changes at 256'
cargo run -- trial /tmp/pi-icmp exp-000003 baseline 'sequence number'
cargo run -- mark /tmp/pi-icmp trial-000004 stimulus 'Generate echo traffic'
cargo run -- import /tmp/pi-icmp trial-000004 pcap-icmp examples/icmp_echo.pcap
cargo run -- value /tmp/pi-icmp obs-000006-0000 sequence 0 discovery
cargo run -- value /tmp/pi-icmp obs-000006-0002 sequence 1 discovery
cargo run -- value /tmp/pi-icmp obs-000006-0004 sequence 2 discovery
cargo run -- value /tmp/pi-icmp obs-000006-0008 sequence 255 discovery
cargo run -- value /tmp/pi-icmp obs-000006-0010 sequence 256 discovery
cargo run -- value /tmp/pi-icmp obs-000006-0012 sequence 257 validation
cargo run -- value /tmp/pi-icmp obs-000006-0022 sequence 65535 validation
cargo run -- infer-value /tmp/pi-icmp sequence
cargo run -- cluster /tmp/pi-icmp trial-000004 respect
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

`value` records an externally known unsigned value for an observation, in decimal or `0x` hex. `infer-value` searches fixed offsets for exact 1, 2, 4, or 8-byte encodings in both byte orders. It fits only the `discovery` examples, then reports matches and counterexamples from the `validation` examples. The ICMP sweep yields one candidate: `[6, 8)` in big-endian order, matching both held-out packets. This is evidence for a field location, not proof of its protocol meaning. A corrected annotation appends a new event and supersedes the earlier value in the current view.

`cluster` returns provisional format groups with member IDs, a representative message, stable header bytes, and members farthest from the representative. It separates ICMP request and reply directions into two groups. `cluster <dir> - ignore` ignores direction metadata. Pass a returned cluster ID to `analyze-cluster <dir> <cluster-id> [trial-id|-] [respect|ignore]` to align only that group. The analysis record retains its group scope and method version. Group IDs are hashes of their member IDs and can change when new observations arrive. The [clustering method](docs/clustering-method.md) explains its evidence rule and limits.

The JSON CLI is the current agent interface. `observations` returns at most 100 previews per call, with an offset for paging. `span` reads at most 4096 bytes from one observation, using half-open `[start, end)` message-byte offsets and reporting the original PCAP file offset when available. `diff` shows changed contiguous byte ranges at original message offsets. `resume` returns the current investigation summary; `changes` returns up to 100 events after a revision. `verify` replays the log, checks artifact hashes, and compares extracted observations with original capture bytes. Every record carries a stable ID and the event log has monotonically increasing revisions.

For a command that emits classic PCAP or hex lines on standard output, use `capture-command` instead of `import`:

```sh
cargo run -- capture-command /tmp/pi-icmp trial-000004 pcap-icmp -- cat examples/icmp_echo.pcap
```

The command runs locally, must exit successfully, and is stopped if output exceeds 32 MiB. It is a generic acquisition hook, not yet a managed network capture service. Capture commands should be chosen with care because they execute as the current user.

The generated report is a self-contained, read-only HTML view with experiments, actions, hypotheses, decisions, candidate format groups, observation filters, tags, candidate fields, and a byte inspector. A unique candidate that matches held-out values is outlined at its original byte offsets. Regenerate the report after new events. The append-only source record is `/tmp/pi-icmp/.pi/events.jsonl`; immutable raw captures and analysis JSON live under `/tmp/pi-icmp/.pi/artifacts/` with SHA-256 names. Keep the whole directory to preserve provenance.

## One-shot analysis

```sh
cargo run -- analyze examples/toy_messages.hex
cargo run -- analyze examples/toy_messages.hex --json
```

Hex input has one extracted message per line; spaces and colons are allowed. Blank lines and `#` comments are ignored. The analyzer compares position-preserving columns to a global star alignment, choosing the lower observed column entropy plus width penalty. This simple selection keeps fixed ICMP headers at their true offsets while allowing gaps in the variable-length toy example. The CPU pairwise aligner has a 25-million-cell limit. Column statistics are measurements, not field boundaries or meaning.

## Current scope and next work

Classic PCAP and pcapng ingestion currently support Ethernet, unfragmented IPv4, and ICMP messages. The pcapng reader accepts Enhanced Packet Blocks and rejects legacy packet blocks. It does not support VLANs, IPv6, TCP stream reassembly, file-format record boundaries, or managed live capture. The HTML view is read-only. Local event writers use file locks and assign IDs at commit time; the concurrent CLI test covers simultaneous hypotheses and imports. Distributed coordination, idempotent action handles, and interrupted-write recovery remain open work. The fixture tests parsing, exact source offsets, checksums, and the alignment strategy against independent known answers.

The next inference step is to measure cluster stability across new captures, then test candidate lengths, checksums, and request/response relations on held-out examples. See the [workflow](docs/iterative-workflow.md), [interface design](docs/interface-design.md), and [experiment lifecycle](docs/experiment-lifecycle.md) for the fuller direction. GPU acceleration can wait for representative CPU profiles.

## Licensing

This implementation is dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. The historical repository retains its own LGPL-2.1 terms.
