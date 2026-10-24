# Conservative message grouping

The current `cluster` command proposes **format groups**, not semantic message types. It exposes the observations and rule behind every group so an agent can inspect or challenge the split before aligning messages within it.

1. If requested, partition by the exact observed direction string. This is a useful capture prior, but can over-separate traffic from different host pairs. `ignore` removes it.
2. Within each group, consider low-cardinality bytes in the first 16 message bytes. A candidate needs 2–4 values, at least three observations per value, and another stable byte at least four positions away or a distinct, stable message length in each child. This avoids treating adjacent bytes of a multibyte identifier as independent proof of separate formats.
3. Repeat up to four levels, with at most 32 groups. Return all member IDs, the discriminator path, constant header bytes, a medoid representative, and the three farthest members. Similarity compares at most the first 256 bytes plus a length difference. Queries accept at most 512 observations.

The method deliberately favors **unassigned ambiguity over false precision**. An adjacent opcode and flag may be a real type distinction that this first rule misses. A counter, identifier, checksum, or correlated length may still cause a misleading split. The `respect` and `ignore` modes, split evidence, representative, and farthest members let an agent investigate such cases. Future work should measure stability across captures and use experiment outcomes and request/response relations before promoting a group to a message-type claim.

This is a small, original heuristic informed by [Discoverer's format distinguishers](https://www.usenix.org/conference/16th-usenix-security-symposium/presentation/discoverer-automatic-protocol-reverse-enginee) and [NetPlier's emphasis on uncertain type fields](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_4A-5_24531_paper.pdf). It does not implement either paper's full algorithm.
