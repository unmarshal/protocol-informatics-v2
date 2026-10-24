"""Generate two length-prefixed records crossing a TCP packet boundary."""

import struct
from pathlib import Path

from generate_tcp_fixture import CLIENT, SERVER, SERVER_PORT, frame


def main() -> None:
    payload = b"\x03abc\x02de"
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, part in enumerate((payload[:3], payload[3:])):
        packet = frame(CLIENT, SERVER, 43000, SERVER_PORT, 5000 + (0 if index == 0 else 3), 0, part)
        capture.extend(struct.pack("<IIII", 1_731_000_000 + index, 0, len(packet), len(packet)))
        capture.extend(packet)
    Path(__file__).with_name("framed_tcp.pcap").write_bytes(capture)


if __name__ == "__main__":
    main()
