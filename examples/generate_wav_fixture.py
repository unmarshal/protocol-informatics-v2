"""Generate small controlled PCM WAV files for format-agnostic inference."""

import json
import struct
import wave
from pathlib import Path


HERE = Path(__file__).resolve().parent
RATES = [8000, 44100, 96000, 192000]
FRAMES = struct.pack("<256h", *(index * 101 - 700 for index in range(256)))


def main() -> None:
    cases = []
    for rate in RATES:
        name = f"wav_rate_{rate}.wav"
        with wave.open(str(HERE / name), "wb") as writer:
            writer.setnchannels(1)
            writer.setsampwidth(2)
            writer.setframerate(rate)
            writer.writeframes(FRAMES)
        raw = (HERE / name).read_bytes()
        cases.append({"file": name, "sample_rate": rate, "size": len(raw)})
    truth = {"format": "RIFF/WAVE PCM", "sample_rate_span": [24, 28],
             "byte_order": "little_endian", "cases": cases}
    (HERE / "wav_rates.truth.json").write_text(json.dumps(truth, indent=2) + "\n")


if __name__ == "__main__":
    main()
