# Agent evidence navigation

Start with `summary <dir>`, then use `experiments`, `trials`, `hypotheses`, and `decisions` with `[offset] [limit]` to page the investigation records. Use `search-observations <dir> <json-filter>` to narrow the corpus. Read exact bytes with `span <dir> <observation-id> <start> <end>`. Each record page and search returns `revision`, `total`, `offset`, `next_offset`, and at most 100 bounded previews. Results follow capture import order, so a new import can change page offsets; pin the revision while paging and restart if it changes.

After resuming, call `activity <dir> [after-revision] [limit] [through-revision|-]` or MCP `activity` to see compact events since your last checkpoint. The first page returns `through_revision`; pass it back on later pages to keep the snapshot fixed while new captures arrive. Continue from `next_after_revision` until it is null. Each event gives its kind, revision, timestamp, stable subject ID when available, and small type-specific details. For an imported capture, the details include its trial, format, observation count, and first three observation IDs; use `search-observations` with `capture_id` for the rest. The page never embeds captured bytes. `changes` remains the CLI command for full raw events and can return large responses.

Committed record interpretations have their own index: `frame-runs <dir> [trial-id|-] [fixed_width|unsigned_leb128|delimiter|-] [offset] [limit]`. It pages runs newest first across all three models, with the retry key, parent observation and capture, record count, first three frame IDs, and model configuration. Use the returned key with `frames <dir> <key> [offset] [limit]`, then `frame-span` for exact bytes. `cluster-frames <dir> <model> [trial-id|-] [respect|ignore] [comma-separated-run-keys|-]` groups logical bytes from committed records of one model and returns frame IDs; it is a provisional within-model analysis, with the same 512-record sampling cap as raw observation clustering. If two selected runs interpret the same observation, select one key per observation to avoid double counting. The MCP equivalents are `frame_runs`, `frames`, `frame_span`, and `cluster_frames`; pass `run_keys` as an array. Pin `revision` while paging the index.

Use `validate-frame-clusters <dir> <model> <discovery-trial> <validation-trial> [respect|ignore] [discovery-run-keys|-] [validation-run-keys|-]` to check the proposed record groups on committed frames from a distinct trial of the same experiment. The MCP `validate_frame_clusters` tool takes the same trial IDs and optional run-key arrays. Its `frames` rows carry frame IDs and explain rejected groups. Only committed frames enter this check; use `frame-runs` to confirm coverage before interpreting the counts.

Use `align-frame-cluster <dir> <model> <cluster-id> [trial-id|-] [respect|ignore] [run-keys|-]` to align the logical bytes in one group returned by `cluster-frames`. The read-only MCP equivalent is `align_frame_cluster`. `frame_ids` maps alignment row order to exact committed records, and `reference_frame_id` identifies the reference row. The response discloses any sampling and the current revision; recompute the group ID if the corpus changes.

To retain an alignment, call `record-frame-alignment` with the same arguments or MCP `record_frame_alignment`. This writes one analysis event and content-addressed JSON artifact; it has no retry key, so page `analyses <dir> [offset] [limit]` before repeating an uncertain write. `analysis-result <dir> <analysis-id> [column-offset] [column-limit] [row-offset] [row-limit]` reads hash-checked slices of either frame or observation alignments. The MCP equivalents are `analyses` and `analysis_result`; their maximum page sizes are 100 analysis previews, 256 columns, and 10 rows. Frame analysis rows retain frame IDs and the source revision even after more captures arrive.

Call `analysis-status <dir> <analysis-id>` or MCP `analysis_status` after later captures. It compares saved row IDs with the IDs selected by the same current scope. `same_selected_inputs` means the selected IDs still match; `selected_inputs_changed` includes bounded added and missing ID previews. `unselected_runs_in_scope` means the saved frame selection still matches but other committed interpretations now exist in the trial or corpus. The run keys may have existed before the save; inspect them before deciding whether to rerun. `comparison_unavailable` includes a reason, such as a group ID no longer found. This check does not read the saved artifact or validate an inferred field or protocol claim; use `analysis_result` or `verify` for artifact integrity and held-out tools for claims.

The filter is one JSON object. All supplied fields are combined with AND. Unknown field names and unknown experiment, trial, capture, or framing IDs are errors. An empty object returns the first 50 observations.

| Field | Meaning |
| --- | --- |
| `experiment_id`, `trial_id`, `capture_id` | Exact durable IDs |
| `framing_key` | Parent observation of one committed fixed-width, varint, or delimiter frame run |
| `format` | Exact capture format, such as `pcap-udp` |
| `direction` | Exact source-to-destination string from `summary`; use `<unknown>` for observations without direction metadata |
| `source_port`, `destination_port` | Exact unsigned 16-bit transport ports |
| `timestamp_start_ns`, `timestamp_end_ns` | Decimal UTC nanosecond strings; half-open `[start, end)` interval. Observations without timestamps do not match a timestamp bound |
| `min_bytes`, `max_bytes` | Inclusive raw observation length bounds |
| `tag_phase`, `tag_label` | Exact values; when both are supplied, one tag must match both |
| `stream_gap_before` | Boolean TCP reassembly gap marker |
| `offset`, `limit` | Result page; defaults 0 and 50, maximum limit 100 |

Examples:

```sh
cargo run -- summary /tmp/pi-icmp
cargo run -- experiments /tmp/pi-icmp 0 20
cargo run -- hypotheses /tmp/pi-icmp 0 20
cargo run -- decisions /tmp/pi-icmp 0 20
cargo run -- search-observations /tmp/pi-icmp '{"trial_id":"trial-000004","direction":"192.0.2.1 -> 192.0.2.2","min_bytes":8,"offset":0,"limit":20}'
cargo run -- search-observations /tmp/pi-icmp '{"tag_phase":"stimulus","tag_label":"sequence 256"}'
cargo run -- search-observations /tmp/pi-dns '{"format":"pcap-udp","destination_port":53}'
```

Use `next_offset` with the same filter and revision for the next page. A missing `next_offset` means the result is complete. Use `verify` separately to check the capture artifacts and extracted bytes; search only reads the replayed investigation state.
