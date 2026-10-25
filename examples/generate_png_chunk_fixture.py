"""Generate valid PNGs with independently recorded chunk boundaries."""

import json
import struct
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SIGNATURE = bytes.fromhex("89504e470d0a1a0a")


def chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(kind + data)
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def make_png(name: str, width: int, rows: list[bytes], note: bytes) -> dict:
    height = len(rows)
    if any(len(row) != 3 * width for row in rows):
        raise ValueError("each RGB row must contain three bytes per pixel")
    raw_pixels = b"".join(b"\x00" + row for row in rows)
    encoded = [
        chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
        chunk(b"tEXt", b"Comment\x00" + note),
        chunk(b"IDAT", zlib.compress(raw_pixels, level=6)),
        chunk(b"IEND", b""),
    ]
    png = SIGNATURE + b"".join(encoded)
    (ROOT / name).write_bytes(png)
    offset = len(SIGNATURE)
    records = []
    for index, encoded_chunk in enumerate(encoded):
        length = struct.unpack_from(">I", encoded_chunk)[0]
        kind = encoded_chunk[4:8]
        crc = struct.unpack_from(">I", encoded_chunk, 8 + length)[0]
        records.append(
            {
                "index": index,
                "start": offset,
                "end": offset + len(encoded_chunk),
                "length": length,
                "type": kind.decode("ascii"),
                "crc32": f"{crc:08x}",
            }
        )
        offset += len(encoded_chunk)
    if offset != len(png):
        raise AssertionError("chunk offsets do not cover PNG")
    return {"file": name, "width": width, "height": height, "chunks": records}


def validate_png(path: Path) -> None:
    data = path.read_bytes()
    if not data.startswith(SIGNATURE):
        raise AssertionError("PNG signature mismatch")
    cursor = len(SIGNATURE)
    chunks = []
    while cursor < len(data):
        length = struct.unpack_from(">I", data, cursor)[0]
        kind = data[cursor + 4 : cursor + 8]
        payload = data[cursor + 8 : cursor + 8 + length]
        crc = struct.unpack_from(">I", data, cursor + 8 + length)[0]
        if zlib.crc32(kind + payload) != crc:
            raise AssertionError("PNG chunk CRC mismatch")
        chunks.append((kind, payload))
        cursor += 12 + length
    if cursor != len(data) or chunks[0][0] != b"IHDR" or chunks[-1][0] != b"IEND":
        raise AssertionError("PNG chunks do not cover the file")
    width, height = struct.unpack_from(">II", chunks[0][1])
    pixels = zlib.decompress(next(payload for kind, payload in chunks if kind == b"IDAT"))
    if len(pixels) != height * (1 + 3 * width):
        raise AssertionError("PNG image payload size mismatch")


def main() -> None:
    files = [
        make_png("png_chunk_discovery_a.png", 1, [bytes.fromhex("ff0000")], b"red pixel"),
        make_png(
            "png_chunk_discovery_b.png",
            2,
            [bytes.fromhex("00ff000000ff")],
            b"green and blue pixels; " + b"d" * 280,
        ),
        make_png(
            "png_chunk_validation.png",
            1,
            [bytes.fromhex("00ffff"), bytes.fromhex("ffff00")],
            b"two independent rows; " + b"v" * 320,
        ),
    ]
    followup_files = [
        make_png(
            "png_chunk_large_discovery.png",
            1,
            [bytes.fromhex("804020")],
            b"length width discovery; " + b"D" * 66_000,
        ),
        make_png(
            "png_chunk_large_validation.png",
            1,
            [bytes.fromhex("208040")],
            b"length width validation; " + b"V" * 66_501,
        ),
    ]
    for file in files + followup_files:
        validate_png(ROOT / file["file"])
    (ROOT / "png_chunks.truth.json").write_text(
        json.dumps(
            {"signature_hex": SIGNATURE.hex(), "files": files, "followup_files": followup_files},
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
