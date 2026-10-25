# Experiment and capture lifecycle

Status: partial implementation, October 2026. Experiment, trial, keyed action marker, capture import, observation tag, hypothesis evaluation, read-only trial review, repeatable capture steps, and bounded keyed capture commands with background start and explicit stop exist. A dedicated network capture adapter remains a proposal.

## Model

An **experiment** tests a question. It owns competing hypotheses, predicted observations, and one or more **trials**. A trial records one controlled condition, such as a baseline payload and a changed payload. Each trial can own one or more **captures** and an ordered **action log**. Captures are immutable raw artifacts; derived observations and tags point back to exact source offsets.

This separation matters: an experiment can be repeated, a capture can contain unrelated traffic, and a trial can generate many request and response messages. Tagging an entire capture as a result would blur those distinctions.

| Record | Key fields |
| --- | --- |
| Experiment | ID, question, candidate hypothesis IDs, predicted outcomes, creator, status |
| Trial | ID, experiment ID, baseline/variant role, changed factors, environment, action driver, status |
| Capture | ID, trial ID, backend, target/interface, filter, start/stop times, raw artifact hash, capture statistics, status |
| Action event | ID, trial ID, action type, parameters or input artifact, wall and monotonic timestamps, result |
| Observation tag | observation ID, trial/action/phase link, label, author, timestamp, confidence, supporting evidence |

Phase labels include `baseline`, `stimulus`, `response`, and `background`. The agent can leave traffic unassigned until correlation is supported. Tags are versioned annotations, not edits to packet bytes. An action event may link a sent request to later responses even when the unknown protocol has no transaction identifier.

## Agent workflow

1. **Plan:** create an experiment with a falsifiable question, competing predictions, a target, capture scope, bounds, and a baseline/variant trial plan.
2. **Prepare:** validate the capture backend and target; record the tool version, interface, filter, clock information, and action driver. Start with a baseline trial when possible.
3. **Capture:** start the capture and receive a stable capture ID. Record precise action markers as the trial driver sends input or changes one controlled factor. Stop by explicit call or the planned duration/size/packet limit.
4. **Ingest:** hash and retain the original capture, extract streams and candidate messages, record packet loss and framing uncertainty, and link observations to capture spans.
5. **Tag:** associate observed messages with trial phases and action events using time windows, direction, and any inferred correlation fields. Show uncertain and unassigned observations explicitly.
6. **Evaluate:** compare observations with the predictions, including counterexamples, and update the investigation's hypothesis scores.
7. **Decide and repeat:** record which uncertainty remains, choose another trial or branch the investigation, and checkpoint the new revision. The next cycle can reuse earlier captures and tests without rerunning them.

The capture adapter and action driver are separate. A first network adapter can wrap `dumpcap` and keep its default pcapng output; the experiment metadata belongs in sidecar records so the model also works for imported captures, serial traces, IPC logs, and files. `dumpcap` supports capture filters and stop conditions for duration, size, and packet count: https://www.wireshark.org/docs/man-pages/dumpcap.html

## Agent operations

| Operation | Result |
| --- | --- |
| `create_experiment` | validated plan and experiment ID |
| `create_trial` | trial ID and controlled factors |
| `start_capture` | capture ID, backend status, start time, limits |
| `mark_action` | event ID and timestamp for a stimulus or environmental change |
| `stop_capture` | raw artifact ID, hash, end time, capture statistics |
| `import_capture` | artifact ID for an existing trace or file |
| `tag_observations` | versioned links to trial phase or action event |
| `compare_trials` | changed factors, matched observations, predicted and actual outcomes |
| `review_trials` | implemented read-only evidence summary, counterexample IDs, and next tool actions for one controlled pair |
| `evaluate_experiment` | planned prediction assessment and evidence for each hypothesis |
| `record_decision` | selected next action and a link to the new investigation revision |

Start and stop calls accept idempotency keys so retries do not create duplicate captures. Long-running captures return handles and status updates. Failed or interrupted captures remain inspectable with their partial artifact and failure reason.

## Human view

Show the experiment as a timeline: capture intervals, marked actions, message bursts, inferred request/response links, and phase tags. Let an analyst compare baseline and variant trials side by side, inspect exact bytes behind each claimed difference, and correct an assignment. The same corrected tag becomes available to the agent as versioned evidence.

## First implementation slice

Experiment, trial, capture, action, and tag records are implemented for hex lines, binary files, and Ethernet IPv4/IPv6 ICMP, ICMPv6, UDP, or TCP traffic in classic PCAP or pcapng, including VLAN-tagged frames. TCP observations can be individual segment payloads or contiguous directional runs with packet-level byte provenance. Connection lifetime detection remains open. `mark` records current UTC nanoseconds; `mark-at` accepts a known trace timestamp. `mark-keyed` adds retry-safe action identity. `tag-window` uses an action, trial, and half-open capture timestamp interval to attach versioned tags. `tag-capture` attaches a bounded page of observations from one capture to an action in the same trial, including untimed data; it describes acquisition scope, not causal response membership. `capture-step` composes a keyed mark, bounded capture, and all needed keyed capture tag pages with one step key. `capture-command` is a synchronous acquisition hook with a time limit, output limit, and durable run reservation. `capture-start` launches the same bounded command in the background, `capture-stop` durably requests its termination, and `capture-status` exposes the transition. Replaying a completed key returns the original capture; failed and interrupted keys cannot silently run again. Valid bytes emitted before a requested stop are imported. Partial output from a failed or invalid run is not retained. A dedicated `dumpcap` adapter and capture metadata such as loss, filter, and interface still need to be added.
