# Protocol Informatics v2

A new Rust implementation of the ideas behind [Marshall Beddoe's Protocol Informatics project](https://github.com/unmarshal/protocol-informatics). The long-term aim is to help analysts and software agents infer network protocol and file-format structure from evidence, then test their hypotheses with new samples.

This repository is an **early working baseline**, not a complete protocol reverse-engineering system. It contains new Rust code; it does not import the original LGPL implementation.

## Try it

```sh
cargo run -- analyze examples/toy_messages.hex
cargo run -- analyze examples/toy_messages.hex --json
cargo test
```

The input is one extracted message per line in hexadecimal. Spaces and colons are allowed; blank lines and lines starting with `#` are ignored. For example:

```text
aa 03 41 42 43 ff
aa 01 44 ff
```

The CLI aligns messages and reports each aligned column's consensus byte, number of samples containing a byte, number of distinct byte values, and Shannon entropy. `--json` also returns the aligned samples as byte arrays with `null` gaps. The JSON uses zero-based column and reference-sample indexes.

## Current method and limits

- A deterministic, global Needleman–Wunsch CPU aligner uses match `+2`, mismatch `-1`, and gap `-2`.
- Multiple messages are aligned against the longest sample. Insertions at the same reference position are padded to a common width.
- The CPU backend limits its dynamic-programming matrix to 25 million cells to avoid unbounded allocation.
- Column statistics describe variation. They do **not** prove field boundaries or field meaning. In the toy example, even the length byte may shift into different aligned columns. Sample bias, repeated byte patterns, mixed message types, compression, and encryption can mislead this method.

The `PairwiseAligner` trait lets us compare alignment methods against the same corpus. For now, correctness and useful inference matter more than hardware acceleration. We will profile representative workloads before considering SIMD or GPU implementations.

## Next milestones

1. Add capture ingestion and TCP stream reassembly so messages can be extracted with direction, session, and timing metadata.
2. Cluster message types before alignment and add affine-gap or profile alignment for variable fields.
3. Infer and score testable hypotheses such as lengths, counters, checksums, delimiters, and request/response correlations.
4. Expose evidence and hypothesis tests through agent-friendly tools. Generate parsers and dissectors only after validating against held-out traffic.
5. Build a representative benchmark corpus and profile the CPU implementation. Consider acceleration only where measured workloads justify it.

## Licensing

This new implementation is dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. The historical repository remains under its own LGPL-2.1 terms.
