#!/usr/bin/env python3
"""Generate independent known-answer delimiter-terminated record fixtures."""

import json
import struct
from pathlib import Path

from generate_tcp_fixture import CLIENT, SERVER, SERVER_PORT, frame

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
    pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    parts = [b"A\r", b"\nBC\r\n"]
    spans = []
    sequence = 3000
    message_start = 0
    for packet_index, payload in enumerate(parts):
        raw = frame(CLIENT, SERVER, 43000, SERVER_PORT, sequence, 0, payload)
        file_offset = len(pcap) + 16 + 14 + 20 + 20
        pcap.extend(struct.pack("<IIII", 1_731_500_000 + packet_index, 0, len(raw), len(raw)))
        pcap.extend(raw)
        spans.append(
            {"packet_index": packet_index, "message_start": message_start,
             "message_end": message_start + len(payload), "file_offset": file_offset}
        )
        message_start += len(payload)
        sequence += len(payload)
    (HERE / "delimiter_split_tcp.pcap").write_bytes(pcap)
    (HERE / "delimiter_split_tcp.truth.json").write_text(
        json.dumps(
            {"observation_hex": b"".join(parts).hex(), "records": [
                {"start": 0, "payload_end": 1, "end": 3},
                {"start": 3, "payload_end": 5, "end": 7},
            ], "source_spans": spans}, indent=2
        ) + "\n"
    )


if __name__ == "__main__":
    main()
