# Agent evidence navigation

Start with `summary <dir>`, then use `experiments`, `trials`, `hypotheses`, and `decisions` with `[offset] [limit]` to page the investigation records. Use `search-observations <dir> <json-filter>` to narrow the corpus. Read exact bytes with `span <dir> <observation-id> <start> <end>`. Each record page and search returns `revision`, `total`, `offset`, `next_offset`, and at most 100 bounded previews. Results follow capture import order, so a new import can change page offsets; pin the revision while paging and restart if it changes.

The filter is one JSON object. All supplied fields are combined with AND. Unknown field names and unknown experiment, trial, capture, or framing IDs are errors. An empty object returns the first 50 observations.

| Field | Meaning |
| --- | --- |
| `experiment_id`, `trial_id`, `capture_id` | Exact durable IDs |
| `framing_key` | Parent observation of one committed fixed-width or varint framing run |
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
