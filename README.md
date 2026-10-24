# Protocol Informatics v2

A new Rust implementation inspired by [Marshall Beddoe's Protocol Informatics](https://github.com/unmarshal/protocol-informatics). It helps an analyst or agent collect examples, test protocol hypotheses, and retain the evidence behind each decision. This is an early working baseline, not a general protocol reverse engineering system. No historical LGPL code has been imported.

## Quick start: an ICMP investigation

The repository includes a deterministic, 24-packet Ethernet/IPv4/ICMP echo capture. `examples/generate_icmp_fixture.py` regenerates the PCAP and a separate known-answer manifest. The sequence numbers cross the `255 → 256` boundary, which makes byte order and field width visible.

The same packets are available in `examples/icmp_echo.pcapng`; replace `pcap-icmp examples/icmp_echo.pcap` with `pcapng-icmp examples/icmp_echo.pcapng` in the commands below to exercise that reader. The pcapng reader handles Section Header, Interface Description, and Enhanced Packet Blocks, including interface timestamp resolution and offset. Its field interpretation follows the [IETF pcapng draft](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-opsawg-pcapng-06.html).

`examples/icmp_holdout.pcap` contains six additional packets with a new identifier, payloads, and sequence values. Use it as a separate validation trial for inference.

`examples/icmp_sweep_512.pcap` contains 512 deterministic request/reply pairs with a fixed identifier and payload. A separate `examples/icmp_sweep_512_holdout.pcap` covers sequences 512–1023. Together they exercise paged capture tags and sampled grouping across two 1,024-packet trials; `examples/icmp_sweep_512.truth.json` records the known field spans.

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
cargo run -- summary /tmp/pi-icmp
cargo run -- trials /tmp/pi-icmp 0 20
cargo run -- resume /tmp/pi-icmp
cargo run -- changes /tmp/pi-icmp 6
cargo run -- verify /tmp/pi-icmp
cargo run -- report /tmp/pi-icmp /tmp/pi-icmp-report.html
```

For a controlled comparison, the generator also writes `icmp_baseline_255.pcap` and `icmp_variant_256.pcap`. They hold identifier and payload constant while changing the sequence. Put them in separate `baseline` and `variant` trials, then run `compare-trials <dir> <baseline-trial-id> <variant-trial-id>`. It pairs observations by direction and source order, reports unmatched messages, and counts changed byte offsets across pairs. The fixture changes only one checksum byte at `[3, 4)` and the sequence at `[6, 8)`. The sequence changes from `00ff` to `0100`. Pairing is a descriptive assumption; confirm it before treating differences as causal evidence.

The `evaluate` score is supplied by the analyst or agent. The program validates its range and evidence IDs, but does **not** calculate a probability that the hypothesis is true. `analyze-investigation` stores a separate descriptive alignment result; it does not evaluate the semantic claim.

`value` records an externally known unsigned value for an observation, in decimal or `0x` hex. `infer-value` searches fixed offsets for exact 1, 2, 4, or 8-byte encodings in both byte orders. It fits only the `discovery` examples, then reports matches and counterexamples from the `validation` examples. The ICMP sweep yields one candidate: `[6, 8)` in big-endian order, matching both held-out packets. When several candidates pass validation, the shortest is marked `preferred` only if it is unique at that width; wider encodings remain visible because zero padding can make them equally consistent with observed values. This is evidence for a field location, not proof of its protocol meaning or full width. A corrected annotation appends a new event and supersedes the earlier value in the current view.

`infer-checksum <dir> <discovery-trial> <validation-trial> <baseline-trial> <variant-trial> <controlled-variable>` tests a whole-message 16-bit Internet checksum model. It uses a unique shortest held-out numeric field candidate and controlled trial comparison to distinguish a dependent checksum candidate from other words that satisfy the checksum equation. With the ICMP sweep, new holdout capture, controlled 255→256 pair, and annotated `sequence`, it reports six equation matches but only one intervention-supported field: `[2, 4)` big-endian. The [checksum method](docs/checksum-method.md) explains why the equation alone is ambiguous and lists the assumptions.

`cluster` returns provisional format groups with member IDs, a representative message, stable header bytes, and members farthest from the representative. It separates ICMP request and reply directions into two groups. Larger selections use a deterministic direction and length stratified sample of at most 512 observations, with sample and total counts disclosed; group membership describes that sample. `cluster <dir> - ignore` ignores direction metadata for grouping. Pass a returned cluster ID to `analyze-cluster <dir> <cluster-id> [trial-id|-] [respect|ignore]` to align only that group. `validate-clusters <dir> <discovery-trial> <validation-trial> [respect|ignore]` checks the discovered groups against a separate trial. It evaluates all held-out observations up to 10,000, reports assignment and rejection totals, and returns at most 512 detailed rows with counterexamples first. Larger validation trials use a disclosed sample. The analysis record retains its group scope and method version. Group IDs are hashes of their member IDs and can change when new observations arrive. The [clustering method](docs/clustering-method.md) explains its evidence rule and limits.

The JSON CLI is the current agent interface. Start with `summary` for a bounded corpus overview: raw and derived counts, byte lengths, timestamp coverage, formats, directions, recent trials, and reserved capture keys. It returns at most 20 directions, trials, and keys per group, with omitted counts; use paged `trials` to reach older trial IDs. Its `median` and `p90` use nearest-rank selection over raw observation lengths. The timestamp range uses decimal strings for exact nanoseconds in JavaScript clients. Reserved capture keys indicate an event-log reservation, so use `capture-status` for the current process state. `observations` returns at most 100 previews per call, with an offset for paging. `search-observations` accepts one JSON filter and returns the same bounded page, narrowing by experiment, trial, capture, committed framing key, format, direction, ports, timestamp, byte length, tags, or TCP gap marker. See the [agent query guide](docs/agent-query.md) for exact fields and examples. `span` reads at most 4096 bytes from one observation, using half-open `[start, end)` message-byte offsets and reporting the original PCAP file offset when available. `diff` shows changed contiguous byte ranges at original message offsets. `resume` returns the full investigation checkpoint; `changes` returns up to 100 events after a revision. `verify` replays the log, checks artifact hashes, and compares extracted observations with original capture bytes. Every record carries a stable ID and the event log has monotonically increasing revisions.

For a command that emits classic PCAP, hex lines, or a binary file on standard output, use `capture-command` for a synchronous run, or `capture-start` to return immediately while the command runs. Supply a stable key and a timeout in milliseconds:

```sh
cargo run -- capture-command /tmp/pi-icmp trial-000004 pcap-icmp icmp-sweep-1 5000 -- cat examples/icmp_echo.pcap
cargo run -- capture-status /tmp/pi-icmp icmp-sweep-1
```

For a live command, start it in the background, mark actions while it runs, then request a stop and poll for a terminal status:

```sh
cargo run -- capture-start /tmp/pi-icmp trial-000004 pcap-icmp icmp-live-1 30000 -- sh -c 'exec your-pcap-producing-command'
cargo run -- mark /tmp/pi-icmp trial-000004 stimulus 'Sent request'
cargo run -- capture-stop /tmp/pi-icmp icmp-live-1
cargo run -- capture-status /tmp/pi-icmp icmp-live-1
```

The command runs locally with a 1–600000 ms deadline and a 32 MiB output limit. On Unix, timeout, overflow, or a stop request terminates its process group. Stop is a durable request: `capture-status` may report `stopping` before it reaches `completed` or `failed`; a command that ignores the stop signal is killed after a short grace period. Valid output emitted before the stop is imported. Empty or invalid output leaves a failed run without a capture. The key reserves one run in the event log: a concurrent call sees `running` or `stopping`; a successful retry returns the original capture; a failed or interrupted key never executes again. Use a new key for an intentional repeat. `capture-status` can report `running`, `stopping`, `interrupted`, `completed`, or `failed`. Command arguments and the working directory are represented by a SHA-256 fingerprint in the log rather than stored verbatim. This is a command-backed acquisition hook; a dedicated network interface adapter and capture statistics are still future work. Capture commands execute as the current user.

For a repeatable experiment step, `capture-step <dir> <trial-id> <kind> <detail> <phase> <label> <step-key> <format> <timeout-ms> -- <program> [args...]` records a keyed action, performs the bounded capture, and attaches keyed capture-scope tags to all observations. It pages tag events in groups of at most 1000, including for untimed hex and binary data. A retry with the same step key reuses a completed action and capture, then finishes missing tag pages. The tags describe **capture scope**; they do not establish which messages are responses. Use `mark-keyed`, `capture-command`, and `tag-capture` separately when the action and capture need independent timing. See [the capture-step workflow](docs/capture-step.md).

`mark` records a stimulus with the current UTC time in nanoseconds. For an imported trace or another synchronized clock, `mark-at` accepts the exact UTC nanosecond timestamp. After importing the capture, `tag-window` tags observations in the action's trial with capture timestamps in the half-open interval `[action time, end time)`. Its stable key makes retries safe, including concurrent retries; `window-status` retrieves the recorded selection. A new key after a later import tags only matching observations not already tagged with the same action, phase, and label. Each window is limited to 1000 observations; divide larger intervals. Clock synchronization matters for live captures. A reassembled TCP run uses its earliest contributing packet timestamp; use segment observations when a time boundary falls inside a run.

```sh
cargo run -- init /tmp/pi-timed 'Which packets followed the stimulus?'
cargo run -- experiment /tmp/pi-timed 'Vary sequence' - 'Isolate the changed request'
cargo run -- trial /tmp/pi-timed exp-000002 stimulus 'sequence 255'
cargo run -- mark-at /tmp/pi-timed trial-000003 1700000004000000000 stimulus 'Set sequence to 255'
cargo run -- import /tmp/pi-timed trial-000003 pcap-icmp examples/icmp_echo.pcap
cargo run -- tag-window /tmp/pi-timed action-000004 1700000005000000000 stimulus 'sequence 255' sequence-255-window
cargo run -- window-status /tmp/pi-timed sequence-255-window
```

The generated report is a self-contained, read-only HTML view with experiments, capture command runs, timestamped actions, tagged action windows, hypotheses, decisions, candidate format groups, held-out grouping results, observation filters, tags, candidate fields, and a byte inspector. A unique shortest candidate that matches held-out values is outlined at its original byte offsets. Regenerate the report after new events. The append-only source record is `/tmp/pi-icmp/.pi/events.jsonl`; immutable raw captures and analysis JSON live under `/tmp/pi-icmp/.pi/artifacts/` with SHA-256 names. Keep the whole directory to preserve provenance.

If a process stops while appending the final event, `recover-tail <dir>` inspects the log without editing it. `recover-tail <dir> --apply` appends a missing newline to a complete valid event or backs up and removes an incomplete final line. It refuses to rewrite an invalid complete line or an invalid event sequence. See [event-tail recovery](docs/event-recovery.md).

## Second format: DNS over UDP

`examples/generate_dns_fixture.py` writes 12 DNS query and reply packets to classic PCAP and pcapng, with an independent truth manifest. The fixture follows [RFC 1035's message structure](https://www.rfc-editor.org/rfc/rfc1035.html); the importer extracts UDP application payloads without DNS-specific decoding. It keeps source and destination ports as metadata, plus timestamps and exact payload offsets in the capture. The controlled DNS transaction ID appears at payload offset `[0, 2)`.

```sh
python3 examples/generate_dns_fixture.py
cargo run -- init /tmp/pi-dns 'Where is the transaction ID?'
cargo run -- experiment /tmp/pi-dns 'Vary transaction ID and name' - 'Locate the ID'
cargo run -- trial /tmp/pi-dns exp-000002 sweep 'six query/reply pairs'
cargo run -- import /tmp/pi-dns trial-000003 pcap-udp examples/dns_udp.pcap
cargo run -- cluster /tmp/pi-dns trial-000003 respect
cargo run -- observations /tmp/pi-dns trial-000003 0 4
cargo run -- value /tmp/pi-dns obs-000004-0000 transaction_id 0 discovery
cargo run -- value /tmp/pi-dns obs-000004-0002 transaction_id 1 discovery
cargo run -- value /tmp/pi-dns obs-000004-0004 transaction_id 2 discovery
cargo run -- value /tmp/pi-dns obs-000004-0006 transaction_id 255 discovery
cargo run -- value /tmp/pi-dns obs-000004-0008 transaction_id 256 validation
cargo run -- value /tmp/pi-dns obs-000004-0010 transaction_id 257 validation
cargo run -- infer-value /tmp/pi-dns transaction_id
cargo run -- report /tmp/pi-dns /tmp/pi-dns-report.html
```

The two-byte candidate `[0, 2)` passes both held-out values. A one-byte `[1, 2)` candidate fits only the discovery values below 256 and fails the held-out examples. Use `pcapng-udp` with `examples/dns_udp.pcapng` for the equivalent pcapng capture.

## TCP application payloads

`pcap-tcp` and `pcapng-tcp` extract the application bytes of each nonempty TCP segment. The observation keeps its source and destination ports, TCP sequence number, timestamp, packet index, and exact file offset. Segments are separate observations, and retransmissions remain visible. These formats are useful for inspecting packet boundaries and TCP behavior.

`examples/generate_tcp_fixture.py` creates a synthetic, documented request/reply protocol with six controlled transaction IDs. ACK-only packets are excluded, and alternating TCP header lengths check that offsets point to application bytes. The request ID at `[4, 6)` is found using four discovery values and two held-out values without an application-specific decoder.

```sh
python3 examples/generate_tcp_fixture.py
cargo run -- init /tmp/pi-tcp 'Where is the transaction ID?'
cargo run -- experiment /tmp/pi-tcp 'Vary ID and payload length' - 'Locate the ID'
cargo run -- trial /tmp/pi-tcp exp-000002 sweep 'six exchanges'
cargo run -- import /tmp/pi-tcp trial-000003 pcap-tcp examples/tcp_payload.pcap
cargo run -- observations /tmp/pi-tcp trial-000003 0 4
cargo run -- value /tmp/pi-tcp obs-000004-0000 transaction_id 0 discovery
cargo run -- value /tmp/pi-tcp obs-000004-0002 transaction_id 1 discovery
cargo run -- value /tmp/pi-tcp obs-000004-0004 transaction_id 2 discovery
cargo run -- value /tmp/pi-tcp obs-000004-0006 transaction_id 255 discovery
cargo run -- value /tmp/pi-tcp obs-000004-0008 transaction_id 256 validation
cargo run -- value /tmp/pi-tcp obs-000004-0010 transaction_id 257 validation
cargo run -- infer-value /tmp/pi-tcp transaction_id
```

For split messages, use `pcap-tcp-stream` or `pcapng-tcp-stream`. This groups packets by directional IP address and port tuple, orders payloads by TCP sequence, removes byte-identical retransmissions, and emits one observation per contiguous run. A sequence gap starts another observation with `stream_gap_before: true`; conflicting overlap rejects the entire import. Every assembled observation has `source_spans` mapping message byte ranges back to packet indices and exact file offsets. `span` returns the portions of that map crossing the requested range. A stream observation has `source_offset: null` because its bytes may come from multiple locations in the capture. The HTML byte inspector exposes the provenance map.

The split fixture puts the transaction ID across two TCP packets, includes an out-of-order pair and a retransmission, and still yields the preferred `[4, 6)` field candidate:

```sh
python3 examples/generate_tcp_stream_fixture.py
cargo run -- init /tmp/pi-tcp-stream 'Can a split message be reconstructed?'
cargo run -- experiment /tmp/pi-tcp-stream 'Vary a split ID' - 'Recover the ID'
cargo run -- trial /tmp/pi-tcp-stream exp-000002 sweep 'six requests'
cargo run -- import /tmp/pi-tcp-stream trial-000003 pcap-tcp-stream examples/tcp_stream.pcap
cargo run -- span /tmp/pi-tcp-stream obs-000004-0000 4 6
```

This is contiguous byte reassembly, not application message framing. A SYN on a data-bearing segment consumes one sequence number before its payload. The reassembler does not use SYN/FIN to distinguish repeated connections with the same 4-tuple, nor does it fill missing bytes or accept contradictory retransmissions. Sequence comparison assumes each flow stays within a window smaller than 2³¹ bytes around the first observed segment. Keep packet-level observations when these assumptions do not fit the capture.

## IPv6 traffic

The same `pcap-udp`, `pcapng-udp`, `pcap-tcp`, and TCP stream formats accept IPv6 Ethernet frames. Use `pcap-icmpv6` or `pcapng-icmpv6` for ICMPv6 messages. The deterministic mixed fixture has 12 echo messages, eight UDP datagrams, and four TCP segments, including packets with Hop-by-Hop options. IPv6 addresses appear in the same `direction` field as IPv4 addresses; the byte-span response still points into the original capture.

```sh
python3 examples/generate_ipv6_fixture.py
cargo run -- init /tmp/pi-ipv6 'Where is the ICMPv6 sequence?'
cargo run -- experiment /tmp/pi-ipv6 'Sweep echo sequence' - 'Locate the two-byte field'
cargo run -- trial /tmp/pi-ipv6 exp-000002 sweep 'six request/reply pairs'
cargo run -- import /tmp/pi-ipv6 trial-000003 pcap-icmpv6 examples/ipv6_mixed.pcap
cargo run -- value /tmp/pi-ipv6 obs-000004-0000 sequence 0 discovery
cargo run -- value /tmp/pi-ipv6 obs-000004-0002 sequence 1 discovery
cargo run -- value /tmp/pi-ipv6 obs-000004-0004 sequence 255 discovery
cargo run -- value /tmp/pi-ipv6 obs-000004-0006 sequence 256 discovery
cargo run -- value /tmp/pi-ipv6 obs-000004-0008 sequence 1024 validation
cargo run -- value /tmp/pi-ipv6 obs-000004-0010 sequence 65535 validation
cargo run -- infer-value /tmp/pi-ipv6 sequence
```

The candidate `[6, 8)` big-endian matches both held-out values. IPv6 parsing follows bounded Hop-by-Hop, Routing, and Destination Options headers. It skips fragment headers and unsupported jumbograms, and rejects truncated extension headers. The current `infer-checksum` command tests the IPv4 ICMP whole-message model; ICMPv6 includes an IPv6 pseudo-header in its checksum, so use held-out value inference without applying that checksum command. See [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) and [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443).

## Standalone binary files

`binary` imports one file as one observation, keeping original byte offsets. It accepts nonempty files up to 1 MiB. Multiple files can be imported into the same trial, and all the usual tagging, grouping, byte-span, comparison, alignment, and inference commands apply.

`probe-framing` tests a length-prefix boundary model on one binary or TCP-stream observation. Its parameters are the first record offset, the length field's offset within each record, the field width and byte order, whether the value counts the entire record or just its payload, and record alignment. It returns half-open record spans, length values, previews, source offsets or packet spans, and a specific status if parsing stops early. It does not modify the investigation. At most 256 records and 16 source spans per record are returned; `source_span_count` and `source_spans_truncated` expose the limit. Use paged `span` calls for exact bytes and provenance in a long record.

`infer-framing` searches a bounded set of those models across two discovery observations or more in one trial. It requires each discovery observation to parse into at least two records with varying length values, then reports exact fits and counterexamples from a separate validation trial in the same experiment. Its search covers start offsets 0–8, length-field offsets 0–4, field widths 1/2/4, both byte orders where relevant, total/payload lengths, and alignments 1/2/4. It examines at most 16 observations per trial and 64 KiB per observation. A structural fit is a candidate, not proof that the bytes encode a length.

`probe-tlv` treats the bytes before the length field as a one- or two-byte raw type code and reports each element's type, value, logical, and padded spans with source provenance. `infer-tlv` searches those typed layouts on discovery files, checks the boundaries on held-out files, and counts recurring type codes and novel held-out codes. Type recurrence is descriptive evidence; it does not assign a meaning to a code or reject a valid new code. See [the TLV method](docs/tlv-method.md).

`probe-varint` tests unsigned LEB128 length prefixes with a variable number of encoded bytes. `infer-varint` searches candidate record starts, prefix offsets, length modes, and alignments; it requires a multibyte prefix in discovery and reports every discovery fit with held-out counterexamples. `commit-varint` persists a complete interpretation with retry-safe keys and stable frame IDs. Paged `frames`, `frame-span`, `frame-value`, and `infer-frame-value` work on these derived records. See [the varint method](docs/varint-method.md) and the independent four-file fixture in `examples/varint_*.bin`.

`commit-framing` records a complete model with at least two records for one observation. Its caller-supplied key makes retries safe; a different model cannot reuse the key. Commit-time frame IDs and half-open offsets persist in the event log, and replay checks them against the original observation. `framing-status` and paged `frames` expose the result; `frame-span` reads up to 4096 bytes per call in frame-relative coordinates, with the parent observation offsets and exact source-file or TCP packet provenance. Frames form a separate derived layer, so they are not silently counted as raw observations by clustering or alignment. The HTML report shows committed boundaries alongside proposed ones.

`frame-value` attaches a controlled unsigned value to a committed frame as discovery or validation evidence. `infer-frame-value` runs the same exact-match search as `infer-value`, using frame-relative logical bytes (excluding alignment padding) and returning frame IDs for held-out counterexamples. At least three discovery frames with two distinct values are required. Discovery and validation frames must come from separate captures; the result lists those capture IDs. A later annotation of the same variable on the same frame supersedes the earlier one in the materialized state, while both events remain in the log. The HTML report shows frame field candidates and highlights a unique shortest validated candidate in the parent observation.

```sh
python3 examples/generate_records_fixture.py
cargo run -- init /tmp/pi-records 'Where are record boundaries?'
cargo run -- experiment /tmp/pi-records 'Vary payload lengths' - 'Length prefix predicts boundaries'
cargo run -- trial /tmp/pi-records exp-000002 discovery 'two files'
cargo run -- trial /tmp/pi-records exp-000002 validation 'two held-out files'
cargo run -- import /tmp/pi-records trial-000003 binary examples/records_discovery_a.bin
cargo run -- import /tmp/pi-records trial-000003 binary examples/records_discovery_b.bin
cargo run -- import /tmp/pi-records trial-000004 binary examples/records_validation_a.bin
cargo run -- import /tmp/pi-records trial-000004 binary examples/records_validation_b.bin
cargo run -- infer-framing /tmp/pi-records trial-000003 trial-000004
cargo run -- infer-tlv /tmp/pi-records trial-000003 trial-000004
cargo run -- probe-framing /tmp/pi-records obs-000005-0000 4 1 2 big payload 2
cargo run -- probe-tlv /tmp/pi-records obs-000005-0000 4 1 2 big payload 2
cargo run -- commit-framing /tmp/pi-records obs-000005-0000 4 1 2 big payload 2 discovery-a-v1
cargo run -- commit-framing /tmp/pi-records obs-000008-0000 4 1 2 big payload 2 validation-b-v1
cargo run -- framing-status /tmp/pi-records discovery-a-v1
cargo run -- frames /tmp/pi-records discovery-a-v1 0 50
cargo run -- frame-span /tmp/pi-records frame-000009-0001 0 8
cargo run -- frame-value /tmp/pi-records frame-000009-0000 record_type 160 discovery
cargo run -- frame-value /tmp/pi-records frame-000009-0001 record_type 161 discovery
cargo run -- frame-value /tmp/pi-records frame-000009-0002 record_type 162 discovery
cargo run -- frame-value /tmp/pi-records frame-000010-0000 record_type 160 validation
cargo run -- frame-value /tmp/pi-records frame-000010-0001 record_type 161 validation
cargo run -- frame-value /tmp/pi-records frame-000010-0002 record_type 162 validation
cargo run -- infer-frame-value /tmp/pi-records record_type
```

The fixture has a four-byte preamble and three aligned records per file. Only one searched model fits both discovery files and both held-out files: a two-byte big-endian payload length at record offset 1, with two-byte alignment. The probe maps its first file's records to `[4, 8)`, `[8, 16)`, and `[16, 276)`.

For variable-width lengths, generate `examples/varint_*.bin` with `python3 examples/generate_varint_fixture.py`, import the two discovery and two validation files into separate trials as above, then run `infer-varint <dir> <discovery-trial> <validation-trial>` and `probe-varint <dir> <obs-id> 4 1 payload 2`. Two layouts fit the discovery files; only the layout starting at byte 4 validates on both held-out files. Its 128-byte payload uses a two-byte `8001` prefix.

```sh
cargo run -- commit-varint /tmp/pi-varint obs-000005-0000 4 1 payload 2 discovery-a-v1
cargo run -- varint-status /tmp/pi-varint discovery-a-v1
cargo run -- frames /tmp/pi-varint discovery-a-v1 0 50
cargo run -- frame-span /tmp/pi-varint frame-000009-0002 0 3
```

Use the actual frame IDs returned by `commit-varint`; they depend on the investigation revision. This run stores the byte boundaries and checks them against the original observation during event replay.

The [framing method](docs/framing-method.md) describes the evidence rule, counterexamples, and model families still to add.

The WAV fixture generator makes four tiny PCM files with the same sample data and different sample rates. Python's `wave` reader and the system `file` command independently recognize the outputs.

```sh
python3 examples/generate_wav_fixture.py
cargo run -- init /tmp/pi-wav 'Where is the sample rate?'
cargo run -- experiment /tmp/pi-wav 'Change sample rate' - 'Locate its bytes'
cargo run -- trial /tmp/pi-wav exp-000002 sweep 'four rates'
cargo run -- import /tmp/pi-wav trial-000003 binary examples/wav_rate_8000.wav
cargo run -- import /tmp/pi-wav trial-000003 binary examples/wav_rate_44100.wav
cargo run -- import /tmp/pi-wav trial-000003 binary examples/wav_rate_96000.wav
cargo run -- import /tmp/pi-wav trial-000003 binary examples/wav_rate_192000.wav
cargo run -- value /tmp/pi-wav obs-000004-0000 sample_rate 8000 discovery
cargo run -- value /tmp/pi-wav obs-000005-0000 sample_rate 44100 discovery
cargo run -- value /tmp/pi-wav obs-000006-0000 sample_rate 96000 discovery
cargo run -- value /tmp/pi-wav obs-000007-0000 sample_rate 192000 validation
cargo run -- infer-value /tmp/pi-wav sample_rate
```

The candidate `[24, 28)` little-endian matches the held-out rate. It remains a hypothesis about the format field even though the fixture generator has a known answer.

## One-shot analysis

```sh
cargo run -- analyze examples/toy_messages.hex
cargo run -- analyze examples/toy_messages.hex --json
```

Hex input has one extracted message per line; spaces and colons are allowed. Blank lines and `#` comments are ignored. The analyzer compares position-preserving columns to a global star alignment, choosing the lower observed column entropy plus width penalty. This simple selection keeps fixed ICMP headers at their true offsets while allowing gaps in the variable-length toy example. The CPU pairwise aligner has a 25-million-cell limit. Column statistics are measurements, not field boundaries or meaning.

## Current scope and next work

Classic PCAP and pcapng ingestion currently support Ethernet with up to four VLAN tags, unfragmented IPv4 and IPv6, ICMP and ICMPv6 messages, UDP application payloads, individual TCP segment payloads, and contiguous TCP runs with per-span provenance. The pcapng reader accepts Enhanced Packet Blocks and rejects legacy packet blocks. VLAN tags are unwrapped for transport extraction but their IDs are not yet exposed as observation metadata. UDP extraction checks the declared datagram length but does not verify its checksum or parse its application payload. TCP extraction validates its data offset and excludes empty payloads; its reassembly does not identify application message boundaries or connection lifetimes. Binary files are one observation each, with a 1 MiB limit until the event store can reference large byte spans without copying them into events. Length-prefix record boundaries can be probed, validated, and committed as a separate derived layer; other framing families remain open. A dedicated network interface capture adapter is also pending. The HTML view is read-only and pages bytes in 256-byte chunks. Local event writers use file locks and assign IDs at commit time; the concurrent CLI test covers simultaneous hypotheses, imports, and keyed capture retries. Explicit final-line recovery is available after an interrupted write; distributed coordination, a resumable live capture service, and broader transaction recovery remain open work. The fixtures test parsing, exact source offsets, ICMP checksums, and the alignment strategy against independent known answers.

The next inference step is to test candidate lengths and request/response relations on held-out examples, then compare group stability across independent capture settings. See the [workflow](docs/iterative-workflow.md), [interface design](docs/interface-design.md), and [experiment lifecycle](docs/experiment-lifecycle.md) for the fuller direction. GPU acceleration can wait for representative CPU profiles.

## Licensing

This implementation is dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. The historical repository retains its own LGPL-2.1 terms.
