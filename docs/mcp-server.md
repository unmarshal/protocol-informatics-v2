# MCP stdio server

`protocol-informatics-v2 mcp-stdio <investigation-dir>` exposes one existing investigation to an MCP client. Create the investigation with `init` first, then point the client's stdio server configuration at the compiled binary and that directory. The process reads JSON-RPC from standard input and writes protocol messages to standard output; diagnostics use standard error. The server uses the MCP 2025-11-25 initialization protocol through the official Rust SDK.

For example, after `cargo build --release`:

```json
{
  "command": "/absolute/path/to/protocol-informatics-v2/target/release/protocol-informatics-v2",
  "args": ["mcp-stdio", "/absolute/path/to/investigation"]
}
```

The directory is fixed for the lifetime of that server process. Each tool call reloads the current event-sourced investigation. Read tools return structured JSON plus text content and preserve the same IDs, revision, limits, and evidence coordinates as the CLI. Tool failures return MCP tool errors with the underlying validation message. A client can connect multiple investigations by configuring separate server processes.

## Agent workflow

1. Call `summary`, then `trials` and `search_observations` to narrow the evidence. Page search results with `next_offset`, checking `revision` between pages.
2. Call `span` to inspect exact message bytes and original source offsets. Use `pair_exchanges` and `cluster` for provisional patterns; use `validate_exchanges` and `validate_clusters` on separate trials to find counterexamples.
3. Call `create_experiment` and `create_trial` to record a falsifiable question and controlled condition. These creation calls have no retry key, so inspect `summary` or `trials` before repeating an uncertain call.
4. Use `capture_step` with a stable `step_key` to record an action, run a bounded local command that emits a supported capture format, import its bytes, and tag every resulting observation to that capture scope. The command is an argument array, without an inserted shell. It executes with the server process's user privileges. `mark_action`, `capture_start`, `capture_status`, `capture_stop`, and `tag_capture` support separate action and live capture timing.
5. The `capture_step` result gives the capture ID, observation count, up to 20 observation IDs, and compact tag-page records. Retrieve the remaining observations with `search_observations` filtered by `capture_id`.

Capture commands have the CLI's 1–600000 ms timeout and 32 MiB output limit. A capture-scope tag says that an observation came from the captured step; it does not assert that the observation is a reply. The keyed operations are retry-safe according to the [capture step workflow](capture-step.md). The MCP server delegates writes to the same CLI operations, so the append-only event log and artifact verification remain authoritative.

The server currently exposes 16 tools: `summary`, `trials`, `search_observations`, `span`, `pair_exchanges`, `validate_exchanges`, `cluster`, `validate_clusters`, `create_experiment`, `create_trial`, `mark_action`, `capture_step`, `capture_start`, `capture_status`, `capture_stop`, and `tag_capture`. Full hypothesis evaluation, decision recording, framing probes, and report generation remain available through the JSON CLI and are not yet MCP tools.
