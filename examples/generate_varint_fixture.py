"""Generate independent known-answer unsigned LEB128 record fixtures."""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREAMBLE = b"VI2!"


def encode_leb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def make_case(name: str, lengths: list[int], salt: int) -> dict:
    data = bytearray(PREAMBLE)
    records = []
    for index, length in enumerate(lengths):
        start = len(data)
        kind = 0x91 + index
        prefix = encode_leb128(length)
        data.append(kind)
        data.extend(prefix)
        data.extend(((salt + index * 47 + offset * 29) & 0xFF for offset in range(length)))
        logical_end = len(data)
        if (logical_end - start) % 2:
            data.append(0)
        records.append(
            {
                "start": start,
                "length_field_start": start + 1,
                "length_field_end": start + 1 + len(prefix),
                "prefix_hex": prefix.hex(),
                "length": length,
                "logical_end": logical_end,
                "end": len(data),
                "kind": kind,
            }
        )
    filename = f"varint_{name}.bin"
    (HERE / filename).write_bytes(data)
    return {"file": filename, "length": len(data), "records": records}


def main() -> None:
    cases = [
        make_case("discovery_a", [1, 4, 128], 7),
        make_case("discovery_b", [2, 7, 129], 11),
        make_case("validation_a", [3, 5, 130], 19),
        make_case("validation_b", [4, 9, 131], 23),
    ]
    (HERE / "varint.truth.json").write_text(
        json.dumps({"preamble_hex": PREAMBLE.hex(), "cases": cases}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
