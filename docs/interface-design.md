# Agent and human interface design

Status: partial implementation, October 2026. A JSON CLI and read-only HTML report now share the event-sourced investigation model. The rest of this document describes the planned agent tool server and deeper viewer.

## Principle

The Rust analysis engine produces one versioned, queryable evidence model. A CLI, an agent tool server, and a local human viewer use that model. Every visible highlight or agent explanation points to the same observation IDs and byte spans. Interface state never becomes a hidden source of truth. An [investigation](iterative-workflow.md) connects successive analyses, experiments, and decisions so the workflow can be resumed or branched.

```text
inspect evidence → propose hypotheses → plan trial → capture/import
       ↑                                           ↓
revise or branch ← compare predictions ← analyze and tag

           agent tools ↔ shared records ↔ human viewer
```

## Durable records

- **Artifact:** immutable original capture or file, content hash, source type, and import metadata.
- **Observation:** one candidate message or file record, exact source byte spans, payload reference, session/stream, direction, time, and message-boundary confidence. A packet is not assumed to be one message.
- **Analysis run:** algorithm version, parameters, input observation IDs, and output IDs. Rerunning an algorithm creates a new run.
- **Cluster:** member IDs, medoid or representative, outliers, defining features, and stability estimate.
- **Hypothesis:** a typed claim about a boundary, field, relation, message type, or state transition. Store confidence, status, supporting evidence, counterexamples, and competing hypotheses.
- **Experiment:** the input changed, predicted outcomes for competing hypotheses, actual observation IDs, and result.
- **Investigation revision:** a checkpoint of the current question, evidence, hypothesis frontier, open tasks, and decisions. Each revision links to its parent and the events that produced it.

An experiment can contain multiple baseline and variant trials, each with its own capture and action timeline. See [experiment-lifecycle.md](experiment-lifecycle.md) for the record model and agent operations.

Use small JSONL manifests for portable interchange and content-addressed binary blobs for payloads. Raw bytes remain lossless. Derived records are versioned separately; large corpora can add an indexed store without changing their meaning. All byte spans use half-open `[start, end)` offsets and name the source coordinate system.

An observation assembled from multiple TCP packets has no single source-file offset. Its `source_spans` map half-open message-byte ranges to packet indices and original file offsets. A `read_span` response clips that map to the requested bytes, so an agent can cite the exact packets behind an inferred field. Sequence gaps create distinct observations; conflicting retransmissions are reported as errors rather than silently choosing bytes.

## Agent navigation

Start with a structured JSON CLI. An agent tool server can expose the same operations later. Each operation needs a bounded result, stable IDs, schema version, explicit units, reproducible ordering, and a cursor for pagination.

| Operation | Minimum useful result |
| --- | --- |
| `summary` | bounded counts, length quantiles, timestamp coverage, formats, directions, recent trials, reserved capture keys |
| `list_observations` | filter by stream, direction, time, size, cluster, or field value; return IDs and compact previews |
| `read_span` | exact bytes, source offset, decoded interpretations, provenance |
| `list_clusters` / `compare_clusters` | representatives, distinguishing features, outliers, supporting observations |
| `list_hypotheses` / `explain_hypothesis` | claim, score, evidence, counterexamples, alternatives |
| `test_hypothesis` | deterministic checks on selected observations and held-out data |
| `trace_session` | ordered message types, request/response links, state candidates |
| `trials` / future `explain_experiment` | paged trial IDs and metadata; later add plan, capture status, action markers, tags, predictions, and outcomes |
| `resume_investigation` / `changes_since` | current checkpoint, open questions, new evidence, changed scores, and unfinished actions |
| `record_decision` | chosen next action, supporting evidence, expected outcome, and resulting revision |

An agent should be able to move from a summary to a cluster, one observation, a byte span, and the evidence for a claim without requesting an entire capture. The analysis tools return measurements; an agent can propose a hypothesis or experiment as a versioned record. Accepting, rejecting, or editing a hypothesis is an explicit operation recorded in an event log. The agent resumes from the durable investigation revision, not from an unstructured chat transcript.

## Human viewer

Build a local viewer over the same IDs and queries. The first version should have four linked views:

1. **Corpus and session map:** distributions of message length and direction, session timelines, and import/framing uncertainty.
2. **Cluster explorer:** representatives, outliers, distinguishing bytes, and side-by-side comparisons. Split or merge suggestions show their effect before acceptance.
3. **Byte inspector:** synchronized hex, ASCII, bits, candidate field overlays, decoded interpretations, and aligned peers. Selecting a field highlights the exact source bytes in every view.
4. **Hypothesis and experiment workbench:** supporting examples, counterexamples, score history, competing explanations, trial controls, captured data, and the next suggested experiment. Show what changed after each trial and why the next action was selected.

The viewer must allow a person to adjust a boundary or type, split or merge a cluster, and immediately see which claims change. Every automated suggestion needs a path back to raw bytes. A 2025 study of experienced protocol reverse engineers found a flexible, hypothesis-driven workflow and a need to validate automation interactively: https://www.eecs.tufts.edu/~dvotipka/files/papers/MatteiPRE2025.pdf

## First interface milestone

Stable IDs, versioned events, bounded `summary`, `observations` with pagination, `span` with exact byte offsets, `diff`, `compare-trials`, `cluster`, `analyze-cluster`, `resume`, known-value annotation, held-out unsigned field inference, length-prefix framing probes with held-out validation, intervention-tested Internet checksum candidates, and a read-only report are implemented. ICMP/ICMPv6 messages, IPv4/IPv6 UDP application payloads, and standalone binary files retain original capture or file offsets; UDP observations also expose both ports. TCP stream observations map message bytes to packet offsets through source spans for either IP version. Framing probes return proposed record spans in the observation coordinate system and clipped source spans for reassembled streams. Committed frames have stable IDs, paged listing, byte-span provenance, and held-out numeric field inference over logical frame bytes. Keyed capture commands have bounded execution, background start, durable stop requests, status queries, and retry-safe run records. Timestamped action markers and keyed time-window tags link stimuli to observations in one trial. The report displays command runs and stop requests, tagged action windows, candidate format groups, pages larger byte views, and outlines a unique shortest numeric field candidate when it matches held-out examples. Checksum inference is currently returned by the JSON CLI; editable field overlays remain interface work, along with a richer session map, hypothesis explanation, and a tool server over the same operations.
