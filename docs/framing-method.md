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
| `length_adjustment` | Additional fixed bytes in each record that the length value does not count; zero by default, at most 16 |
| `alignment` | Round each logical record size up to a 1, 2, 4, or 8 byte boundary |

The probe follows the model repeatedly. It reports both `logical_end` and `end`, so padding is visible. `complete` means the proposed records exactly consume the bytes after `start_offset`. Early stops distinguish an incomplete prefix, impossible length, truncated record, truncated padding, and the 256 record limit. No bytes are silently skipped between records.

## Experimental rule

`infer-framing` fits candidates only on a discovery trial containing at least two observations. Each must yield at least two complete records, and the length values must vary across the discovery set. A distinct validation trial in the same experiment supplies held-out observations. The result includes each candidate's validation matches and structured counterexamples with the failure status and offset. The command returns every surviving candidate up to a 100 candidate response cap; it never turns an exact fit into a semantic certainty.

`infer-chunks` applies the same held-out rule while testing adjustments of 0, 1, 2, 4, 8, 12, and 16 bytes. `probe-framing` accepts the adjustment as an optional final argument; `commit-framing` accepts it after the retry key. The adjustment changes the computed record end, but does not locate or name the uncounted bytes. For PNG, a chunk has a 4-byte length, a 4-byte type, the counted data, and a 4-byte CRC. A payload-mode adjustment of 8 accounts for the type and CRC together. The three initial valid PNG files in `examples/png_chunk_*.png` vary their chunk lengths across the 255-byte boundary; `examples/png_chunks.truth.json` independently records the expected boundaries. Multiple models can still make the same predictions: payload mode with 8 extra bytes and total mode with 12 are algebraically equivalent here, while a 2-byte field can alias the low half of a 4-byte field until a larger chunk is tested. The tool reports each survivor. Exact boundaries across these files are evidence for those models, not evidence that a candidate CRC is correct.

Each candidate includes a `boundary_rule`: the byte position and width read, byte order, start offset, alignment, and total number of bytes added to the observed value. Descriptions with the same boundary rule always compute the same record ends; varying only length values cannot separate them. `identifiability` counts fully validated descriptions and distinct boundary rules before the 100-candidate response cap. When a narrow length field overlaps the low bytes of a wider surviving field, it recommends the smallest length value that would overflow the narrow field. The supplied 66 KiB follow-up PNGs cross 65,535 and remove the two-byte alias on discovery and held-out observations. Chunk inference accepts up to 128 KiB per observation to make that check possible. The recommendation is a structural experiment, subject to the target format's own size limits.

Vary payload sizes across byte-width boundaries, include zero and maximum-length cases where safe, and vary unrelated type or counter fields. An accidental interpretation may end exactly at the file boundary once; it is less likely to keep fitting independent files with changed sizes. A single fully parsed record is weak evidence, which is why the inference command requires multiple records per discovery observation. An agent can probe each counterexample and inspect the exact source bytes with `span` before changing its hypothesis.

## Durable frames

After probing or validation, `commit-framing` stores one observation's complete framing result with a stable caller key. Commit does not require held-out validation; the key identifies a recorded interpretation rather than a proven grammar. It requires at least two records and checks every stored boundary and length against the immutable parent observation when replaying the event log. Repeating the key with the same observation and model returns the committed run without advancing the revision; reusing it with different arguments fails. `framing-status` retrieves the run, `frames` pages its stable frame IDs, and `frame-span` returns frame-relative bytes with parent offsets and source provenance. Padding is part of a frame's `end`, while `logical_end` marks the end of unpadded content. A committed frame is a derived view of a parent observation, not a new raw observation.

`frame-value` annotates a committed frame with a controlled number and a discovery or validation role. `infer-frame-value` searches the logical bytes of those frames, excluding alignment padding. Discovery and validation frames must come from separate captures, preventing records from the same raw capture from serving as their own held-out check. Its candidate offsets are relative to each frame. Held-out failures name the exact frame IDs, and `frame-span` resolves them to original file or packet bytes. The report overlays a unique shortest validated field on the parent observation.

This fixed-width model does not search sentinel delimiters, offset tables, checksum algorithms, or compression blocks. Separate [delimiter probing](delimiter-method.md) checks short terminators, the [TLV view](tlv-method.md) tests typed records, and [unsigned LEB128 probing](varint-method.md) tests variable-width length fields. Recursive or nested TLV grammars remain future work. Committed frames can be grouped, checked on held-out trials, and aligned within a returned group; raw observations and derived records remain separate analysis layers over the same immutable artifacts.
