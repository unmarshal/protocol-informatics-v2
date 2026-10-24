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

The local investigation store, JSON `resume` and `changes` commands, and imported hex/classic-PCAP samples are implemented. The `capture-command` hook can execute a local command that writes up to 32 MiB to standard output. Local writers now lock the event file and assign IDs at commit time. Next add interrupted-write recovery, controlled capture processes, automatic prediction checks, and derived-result invalidation.
