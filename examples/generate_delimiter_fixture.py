#!/usr/bin/env python3
"""Generate independent known-answer delimiter-terminated record fixtures."""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = {
    "discovery_a": ([b"A", b"BCDE", b"FGH"], b"\r\n"),
    "discovery_b": ([b"B", b"CDEF", b"GHIJK"], b"\r\n"),
    "validation_a": ([b"C", b"DEFGH", b"IJKL"], b"\r\n"),
    "validation_b": ([b"D", b"EFG", b"HIJKLM"], b"\n"),
}


def make_case(name: str, payloads: list[bytes], delimiter: bytes) -> dict:
    data = bytearray()
    records = []
    for payload in payloads:
        start = len(data)
        data.extend(payload)
        payload_end = len(data)
        data.extend(delimiter)
        records.append(
            {
                "start": start,
                "payload_end": payload_end,
                "end": len(data),
                "payload_hex": payload.hex(),
            }
        )
    filename = f"delimiter_{name}.bin"
    (HERE / filename).write_bytes(data)
    return {"file": filename, "delimiter_hex": delimiter.hex(), "records": records}


def main() -> None:
    cases = [make_case(name, *definition) for name, definition in CASES.items()]
    unfinished = (HERE / "delimiter_validation_a.bin").read_bytes()[:-2]
    (HERE / "delimiter_unterminated.bin").write_bytes(unfinished)
    (HERE / "delimiter.truth.json").write_text(
        json.dumps(
            {
                "cases": cases,
                "unterminated_file": "delimiter_unterminated.bin",
                "discovery_model_hex": "0d0a",
                "held_out_supported_hex": "0a",
                "held_out_crlf_counterexample_file": "delimiter_validation_b.bin",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
