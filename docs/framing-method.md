# Length-prefix framing evidence

The framing tools test record-boundary hypotheses without changing raw captures. They work on a standalone binary observation or a contiguous TCP run. All returned offsets are half-open byte ranges in the parent observation. A probe also returns the original file offset for a contiguous source, or clipped packet source spans for a reassembled run.

## Model

One candidate specifies:

| Parameter | Meaning |
| --- | --- |
| `start_offset` | Where the first record begins after an optional preamble |
| `prefix_offset` | Where the length field begins relative to each record start |
| `prefix_width` | One, two, or four bytes |
| `byte_order` | Big or little endian |
| `length_mode` | `total`: the value is the logical record size; `payload`: add the bytes through the length field |
| `alignment` | Round each logical record size up to a 1, 2, 4, or 8 byte boundary |

The probe follows the model repeatedly. It reports both `logical_end` and `end`, so padding is visible. `complete` means the proposed records exactly consume the bytes after `start_offset`. Early stops distinguish an incomplete prefix, impossible length, truncated record, truncated padding, and the 256 record limit. No bytes are silently skipped between records.

## Experimental rule

`infer-framing` fits candidates only on a discovery trial containing at least two observations. Each must yield at least two complete records, and the length values must vary across the discovery set. A distinct validation trial in the same experiment supplies held-out observations. The result includes each candidate's validation matches and structured counterexamples with the failure status and offset. The command returns every surviving candidate up to a 100 candidate response cap; it never turns an exact fit into a semantic certainty.

Vary payload sizes across byte-width boundaries, include zero and maximum-length cases where safe, and vary unrelated type or counter fields. An accidental interpretation may end exactly at the file boundary once; it is less likely to keep fitting independent files with changed sizes. A single fully parsed record is weak evidence, which is why the inference command requires multiple records per discovery observation. An agent can probe each counterexample and inspect the exact source bytes with `span` before changing its hypothesis.

## Durable frames

After probing or validation, `commit-framing` stores one observation's complete framing result with a stable caller key. Commit does not require held-out validation; the key identifies a recorded interpretation rather than a proven grammar. It requires at least two records and checks every stored boundary and length against the immutable parent observation when replaying the event log. Repeating the key with the same observation and model returns the committed run without advancing the revision; reusing it with different arguments fails. `framing-status` retrieves the run, `frames` pages its stable frame IDs, and `frame-span` returns frame-relative bytes with parent offsets and source provenance. Padding is part of a frame's `end`, while `logical_end` marks the end of unpadded content. A committed frame is a derived view of a parent observation, not a new raw observation.

This first model does not search varints, sentinel delimiters, offset tables, checksummed envelopes, compression blocks, or nested TLV grammars. It does not yet feed committed frames into clustering, alignment, or field inference. Those are separate model families and analysis scopes to test against the same immutable artifacts and held-out trials.
