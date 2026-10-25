"""Generate valid PCM WAV files with variable RIFF chunks and independent truth."""

import json
import struct
import wave
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def chunk(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack("<I", len(payload)) + payload + (b"\x00" if len(payload) % 2 else b"")


def make_wav(name: str, junk: bytes, samples: list[int]) -> dict:
    pcm = b"".join(struct.pack("<h", sample) for sample in samples)
    format_payload = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    encoded = [chunk(b"fmt ", format_payload), chunk(b"JUNK", junk), chunk(b"data", pcm)]
    body = b"WAVE" + b"".join(encoded)
    wav = b"RIFF" + struct.pack("<I", len(body)) + body
    path = ROOT / name
    path.write_bytes(wav)
    with wave.open(str(path), "rb") as reader:
        assert reader.getparams()[:4] == (1, 2, 8000, len(samples))
        assert reader.readframes(len(samples)) == pcm
    records = []
    offset = 12
    for index, encoded_chunk in enumerate(encoded):
        length = struct.unpack_from("<I", encoded_chunk, 4)[0]
        records.append(
            {
                "index": index,
                "start": offset,
                "logical_end": offset + 8 + length,
                "end": offset + len(encoded_chunk),
                "length": length,
                "type": encoded_chunk[:4].decode("ascii"),
            }
        )
        offset += len(encoded_chunk)
    assert offset == len(wav)
    return {"file": name, "frames": len(samples), "chunks": records}


def main() -> None:
    files = [
        make_wav("riff_chunk_discovery_a.wav", b"x", [0, 1000]),
        make_wav("riff_chunk_discovery_b.wav", b"xyz", [0, 1000, -1000, 0]),
        make_wav("riff_chunk_validation.wav", b"abcde", [0, 500, 1000, -500, -1000, 0]),
    ]
    followup_files = [
        make_wav("riff_chunk_large_discovery.wav", b"d" * 301, [0, 700, -700, 0]),
        make_wav("riff_chunk_large_validation.wav", b"v" * 303, [0, 300, 600, -300, -600, 0]),
    ]
    (ROOT / "riff_chunks.truth.json").write_text(
        json.dumps({"files": files, "followup_files": followup_files}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
