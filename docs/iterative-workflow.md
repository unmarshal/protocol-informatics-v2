# Iterative investigation workflow

Status: partial implementation, October 2026. The Rust CLI now persists versioned investigation events, hypotheses, experiments, trials, captures, tags, analysis records, and decisions. Automated planning and managed live capture remain proposed.

## Unit of work

The durable unit is an **investigation**, not one capture or one analysis run. It has a question, a corpus of immutable observations, competing hypotheses, experiments, decisions, and open work. An agent or analyst can pause, resume, branch, and compare revisions.

One cycle is:

```text
inspect → propose → choose experiment → capture/import → tag/analyze
   ↑                                                  ↓
   └──── revise hypotheses ← compare predictions ────┘
```

The cycle is a guide, not a forced wizard. A new capture may arrive at any time, an analyst may correct a field boundary, and several experiments may run from the same hypothesis revision. Each change creates an event and updates only the analyses that depend on it.

## Checkpoints and decisions

An investigation revision records the current evidence set, analysis versions, hypothesis scores, unresolved contradictions, open questions, and queued next actions. A decision records the actor, chosen action, alternatives considered, evidence references, expected information gain or simpler rationale, and the revision it produced. The event log is append-only; a materialized view can make queries fast.

This gives an agent four essential questions after resuming:

1. What changed since my last checkpoint?
2. Which hypotheses are still plausible, and what evidence contradicts them?
3. What experiment would best distinguish the leading explanations?
4. What action is already running or waiting for a result?

Analysis results are keyed by input observation IDs, algorithm version, and parameters. The agent can reuse a prior result when those inputs match, or rerun an affected analysis when new data or a corrected tag changes the inputs. A derived claim always retains its source revision and exact supporting byte spans.

## Agent action contract

Each proposed action has a typed kind (`inspect`, `analyze`, `capture`, `tag`, `test`, or `ask_analyst`), target IDs, preconditions, estimated cost or duration, predicted observations, and a stopping condition. Execution returns a stable action ID, status, output IDs, and errors. Repeated calls use an idempotency key. Long-running actions can be inspected or stopped and survive an agent session ending.

The planner can rank actions by expected reduction in uncertainty, likely coverage of unseen message types, cost, and ability to produce a clear counterexample. This ranking is advisory; its inputs and rationale are inspectable. An agent may take a cheap inspection step before committing to a capture.

## Human collaboration

The viewer shows a chronological investigation history alongside the evidence graph. It should answer what each experiment changed, which hypothesis gained or lost support, and where a human correction affected downstream conclusions. Analysts can branch an investigation to test an alternative interpretation and later compare the branches. The agent sees corrections as new evidence events and can continue from the resulting revision.

## First implementation slice

The local investigation store, JSON `resume` and `changes` commands, and imported hex, standalone binary, PCAP, and pcapng samples are implemented. Classic PCAP and pcapng can extract ICMP, ICMPv6, UDP application payloads, individual TCP segment payloads, or contiguous TCP runs from Ethernet/IPv4 and IPv6 captures, including frames with up to four VLAN tags. Segment observations preserve a direct file offset; assembled runs preserve a list of message-byte to source-file spans. TCP sequence gaps split runs and contradictory retransmissions reject the import. `mark` and `mark-at` record timestamped actions, while `mark-keyed` makes a mark retry-safe. Keyed `tag-window` links observations in a trial and timestamp interval to an action; keyed `tag-capture` links all observations in one capture, including untimed data. `capture-step` composes a keyed action, capture, and replayable capture-scope tag pages. `pair-exchanges` pages provisional reciprocal-flow pairs and keeps ambiguous predecessors explicit. The `capture-command` hook executes a local command with a 32 MiB output cap, a time limit, a durable run reservation, and a retry key. `capture-start` runs the same command in the background; `capture-stop` records an explicit stop request; `capture-status` distinguishes running, stopping, interrupted, completed, and failed runs. Binary observations currently have a 1 MiB limit. `probe-framing` inspects a proposed length-prefix model with exact source spans; `infer-framing` searches bounded candidates in discovery trials and checks them on held-out trials. `probe-tlv` and `infer-tlv` test typed length-value records and report raw type recurrence. `probe-varint` and `infer-varint` test unsigned LEB128 length fields across encoding-width boundaries. `commit-framing` and `commit-varint` record stable derived frames, and `frame-value` plus `infer-frame-value` use them for controlled held-out field tests. Local writers lock the event file and assign IDs at commit time. Externally known values can be annotated for discovery or validation; exact numeric field candidates are tested on held-out observations or logical frames, with a minimal-width preference that leaves wider matches visible. Explicit `recover-tail` inspection and repair handles an unterminated final event without hiding complete-line corruption. Next add broader transaction recovery, further application framing models, a dedicated network capture adapter with interface and loss metadata, broader prediction checks, and derived-result invalidation.
