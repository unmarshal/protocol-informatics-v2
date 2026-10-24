#!/usr/bin/env python3
"""Generate held-out binary files with aligned, length-prefixed records."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = {
    "discovery_a": (1, 4, 256),
    "discovery_b": (2, 7, 257),
    "validation_a": (3, 5, 260),
    "validation_b": (4, 9, 261),
}


def main():
    manifest = {"preamble_hex": b"PI2!".hex(), "cases": []}
    for name, lengths in CASES.items():
        raw = bytearray(b"PI2!")
        records = []
        for index, length in enumerate(lengths):
            start = len(raw)
            kind = 0xA0 + index
            raw.append(kind)
            raw.extend(length.to_bytes(2, "big"))
            raw.extend(bytes([0x30 + index]) * length)
            logical_end = len(raw)
            if (logical_end - start) % 2:
                raw.append(0xEE)
            records.append(
                {
                    "start": start,
                    "logical_end": logical_end,
                    "end": len(raw),
                    "length_field_start": start + 1,
                    "length": length,
                    "kind": kind,
                }
            )
        filename = f"records_{name}.bin"
        (ROOT / filename).write_bytes(raw)
        manifest["cases"].append({"file": filename, "length": len(raw), "records": records})
    (ROOT / "records.truth.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("wrote four length-prefixed binary files")


if __name__ == "__main__":
    main()
