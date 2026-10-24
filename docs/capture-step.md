# Repeatable agent capture steps

An agent can run one synchronous step with:

```sh
cargo run -- capture-step <dir> <trial-id> stimulus 'payload 256' capture_scope 'payload 256' sweep-256 pcap-icmp 5000 -- /bin/cat examples/icmp_variant_256.pcap
```

The command records a keyed action with a UTC nanosecond timestamp, runs the same bounded acquisition as `capture-command`, and creates keyed capture tag batches linking every imported observation to that action and trial. Each batch contains at most 1000 observations. The response includes the action, capture, observation IDs, tag batches, revision, and whether all batches were replayed. A one-batch result also has a `tag_batch` field. The `capture_scope` phase records where those observations were acquired. Traffic in a packet capture can include background messages, so this tag is not evidence that each observation is a response to the stimulus.

The step key derives `<step-key>:action` and `<step-key>:capture`. Captures with at most 1000 observations use `<step-key>:tags`; larger captures use page keys derived from the SHA-256 of the step key and each page's starting index. Retrying the step reuses an existing action and completed capture, then records any missing tag pages if the client stopped between capture and tagging. A completed step returns the same capture and tag IDs without adding events. A reserved capture that ended unexpectedly remains inspectable through `capture-status`; use a new step key for an intentional repeat. A conflicting use of any key fails. Step keys are limited to 120 bytes so their action and capture keys fit the event store's 128-byte limit.

For separate timing or an existing capture, use `mark-keyed <dir> <trial-id> <kind> <detail> <key> [timestamp-ns]`, then `capture-command` or `import`, then `tag-capture <dir> <action-id> <capture-id> <phase> <label> <key> [offset count]`. `capture-tag-status` retrieves a completed batch. `tag-capture` requires the action and capture to share a trial and returns stable tag IDs. Without a range it selects the whole capture if it contains at most 1000 observations. For a larger capture, issue consecutive nonoverlapping ranges of at most 1000 observations, with a distinct key for each. It supports observations without trace timestamps. `tag-window` remains the more selective choice for timestamped capture traffic; leave unrelated traffic untagged when attribution is uncertain.
