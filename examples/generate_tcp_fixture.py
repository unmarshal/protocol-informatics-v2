"""Generate deterministic Ethernet/IPv4/TCP captures for generic payload inference.

The application bytes are intentionally invented. No application decoder is needed.
Each data frame contains one complete message; TCP stream reassembly is a separate task.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
CLIENT = bytes([192, 0, 2, 20])
SERVER = bytes([192, 0, 2, 80])
SERVER_PORT = 4242
CASES = [(0, b"a"), (1, b"longer"), (2, b"xx"),
         (255, b"delta"), (256, b"a"), (257, b"many")]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(source: bytes, destination: bytes, source_port: int, destination_port: int,
          sequence: int, acknowledgement: int, payload: bytes,
          options: bytes = b"") -> bytes:
    assert len(options) % 4 == 0
    header_length = 20 + len(options)
    flags = 0x18 if payload else 0x10
    tcp = struct.pack("!HHIIBBHHH", source_port, destination_port, sequence,
                      acknowledgement, header_length // 4 << 4, flags,
                      4096, 0, 0) + options + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     sequence & 0xFFFF, 0, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + tcp


def block(block_type: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def main() -> None:
    classic = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    enhanced = bytearray(
        block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        + block(1, struct.pack("<HHI", 1, 0, 65535))
    )
    truth = []
    packet_index = 0

    def add(raw: bytes, case: dict | None, header_bytes: int) -> None:
        nonlocal packet_index
        seconds = 1_730_000_000 + packet_index
        micros = 25_000 * (packet_index % 10)
        if case is not None:
            case["packet_index"] = packet_index
            case["source_offset"] = len(classic) + 16 + 14 + 20 + header_bytes
            truth.append(case)
        classic.extend(struct.pack("<IIII", seconds, micros, len(raw), len(raw)) + raw)
        ticks = seconds * 1_000_000 + micros
        enhanced.extend(block(6, struct.pack("<IIIII", 0, ticks >> 32,
                                              ticks & 0xFFFFFFFF, len(raw), len(raw)) + raw))
        packet_index += 1

    for index, (transaction_id, name) in enumerate(CASES):
        port = 41000 + index
        client_seq = 1000 + 100 * index
        server_seq = 9000 + 100 * index
        add(frame(CLIENT, SERVER, port, SERVER_PORT, client_seq, server_seq, b""), None, 20)
        request = b"PI2Q" + struct.pack("!H", transaction_id) + bytes([len(name)]) + name
        options = b"\x01\x01\x01\x01" if index % 2 == 0 else b""
        add(frame(CLIENT, SERVER, port, SERVER_PORT, client_seq, server_seq,
                  request, options), {
            "transaction_id": transaction_id,
            "response": False,
            "client_port": port,
            "tcp_sequence": client_seq,
            "tcp_header_bytes": 20 + len(options),
            "payload_hex": request.hex(),
        }, 20 + len(options))
        response = b"PI2R" + struct.pack("!H", transaction_id) + bytes([1, index + 1])
        add(frame(SERVER, CLIENT, SERVER_PORT, port, server_seq,
                  client_seq + len(request), response), {
            "transaction_id": transaction_id,
            "response": True,
            "client_port": port,
            "tcp_sequence": server_seq,
            "tcp_header_bytes": 20,
            "payload_hex": response.hex(),
        }, 20)

    (HERE / "tcp_payload.pcap").write_bytes(classic)
    (HERE / "tcp_payload.pcapng").write_bytes(enhanced)
    (HERE / "tcp_payload.truth.json").write_text(json.dumps({
        "format": "Ethernet/IPv4/TCP/invented application",
        "packet_count": packet_index,
        "observation_count": len(truth),
        "transaction_id_span": [4, 6],
        "cases": truth,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
