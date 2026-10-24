# Testing a checksum field with an intervention

`infer-checksum` tests a narrow hypothesis: a two-byte field holds the 16-bit Internet checksum of the **whole extracted message**, with that field zeroed during calculation. It searches field starts in the first 64 bytes, for both byte orders, using up to 4096 bytes per observation. Discovery requires at least three messages. A separate validation trial supplies at least one new byte sequence; the command reports exact-byte duplicates of discovery messages and rejects an all-duplicate holdout.

The checksum equation alone cannot locate the field. If a message has a valid one's-complement checksum, zeroing many other two-byte words and recomputing the checksum can reproduce the removed word. The command therefore returns **all equation matches**, including misleading ones.

To select an intervention-supported candidate, the command also needs:

1. A controlled variable whose exact unsigned field has one candidate matching held-out value annotations from `infer-value`.
2. Two matched trials in the same experiment where that variable changes. Pairs are matched by direction and source order; inspect the pairing before trusting the result.
3. In every pair, changes occur in both the controlled field and the proposed checksum field, with no other byte changes. The proposed field begins at an even byte offset, the alignment assumption used by this version.
4. The checksum equation matches every message in the separate validation trial.

The result lists the equation candidates and, for each one, the number of intervention pairs it explains, holdout counterexamples, word alignment, and `intervention_supported`. Multiple supported candidates must remain ambiguous. A single supported candidate is still a **checksum hypothesis**: another dependent field could behave similarly, and the whole-message coverage or pairing may be wrong. Repeat with other controlled changes, packet lengths, and payloads.

Run the included ICMP fixture after importing its sweep, holdout, baseline, and variant captures as separate trials and annotating the sequence values:

```sh
cargo run -- infer-checksum /tmp/pi-icmp <sweep-trial> <holdout-trial> <baseline-255-trial> <variant-256-trial> sequence
```

The ICMP fixture gives six equation candidates. The controlled 255→256 change and six new holdout packets leave one intervention-supported candidate: `[2, 4)` in big-endian order. This method is designed to avoid claiming the checksum field from a tautological whole-message validity check.
