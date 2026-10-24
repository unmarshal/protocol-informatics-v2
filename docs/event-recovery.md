# Event-tail recovery

An investigation is an append-only `.pi/events.jsonl` file plus immutable artifacts. Each event ends with a newline. Readers and writers now refuse an unterminated final line, including a syntactically valid JSON event without its newline, because appending another event would join the two records.

Run `recover-tail <dir>` to inspect the final line under the event-file lock. The JSON result reports the planned action, last valid revision, recovered revision, byte counts, and SHA-256 of the tail. It makes no changes. After reviewing that result, run `recover-tail <dir> --apply` to carry out one of these actions:

- `clean`: The log is already newline-terminated and replays successfully; nothing changes.
- `append_newline`: The final event, including a first event, is complete JSON and passes all event invariants. Recovery adds only its missing newline and keeps its revision.
- `truncate_partial_tail`: The final bytes cannot be parsed as an event. Recovery first writes those exact bytes to `.pi/recovery/tail-<last-revision>-<sha256>.bin`, then truncates the log to its last complete event. A retry can then append at the next revision.

The backup is written to a temporary file and synced before it receives its final name. Recovery holds an exclusive log lock and verifies replay after applying a change. It refuses a corrupt newline-terminated event, a bad earlier event, a syntactically valid but semantically invalid unterminated event, or an incomplete first event with no valid prefix to retain. The final-line scan is capped at 128 MiB; a larger tail requires manual inspection. Recovery does not interpret a damaged complete line as an interrupted append, and it does not repair arbitrary artifact corruption. Use `verify <dir>` after recovery to check the remaining evidence and capture artifacts.
