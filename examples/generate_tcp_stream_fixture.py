"""Generate split TCP messages, one out-of-order pair, and one retransmission."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from generate_tcp_fixture import CLIENT, SERVER, SERVER_PORT, block, frame


HERE = Path(__file__).resolve().parent
CASES = [(0, b"a"), (1, b"longer"), (2, b"xx"),
         (255, b"delta"), (256, b"a"), (257, b"many")]


def main() -> None:
    classic = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    enhanced = bytearray(
        block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        + block(1, struct.pack("<HHI", 1, 0, 65535))
    )
    packet_index = 0
    truth = []

    def add(raw: bytes) -> tuple[int, int]:
        nonlocal packet_index
        seconds = 1_731_000_000 + packet_index
        micros = 10_000 * (packet_index % 20)
        index = packet_index
        payload_offset = len(classic) + 16 + 14 + 20 + 20
        classic.extend(struct.pack("<IIII", seconds, micros, len(raw), len(raw)) + raw)
        ticks = seconds * 1_000_000 + micros
        enhanced.extend(block(6, struct.pack("<IIIII", 0, ticks >> 32,
                                              ticks & 0xFFFFFFFF, len(raw), len(raw)) + raw))
        packet_index += 1
        return index, payload_offset

    for index, (transaction_id, name) in enumerate(CASES):
        port = 42000 + index
        client_seq = 2000 + index * 100
        server_seq = 12000 + index * 100
        add(frame(CLIENT, SERVER, port, SERVER_PORT, client_seq, server_seq, b""))
        request = b"PI2Q" + struct.pack("!H", transaction_id) + bytes([len(name)]) + name
        parts = [(client_seq, request[:5]), (client_seq + 5, request[5:])]
        if index == 3:
            parts.reverse()
        source_parts = []
        for sequence, payload in parts:
            packet, offset = add(frame(CLIENT, SERVER, port, SERVER_PORT,
                                       sequence, server_seq, payload))
            source_parts.append({"packet_index": packet, "source_offset": offset,
                                 "sequence": sequence, "payload_hex": payload.hex()})
            if index == 2 and sequence == client_seq + 5:
                add(frame(CLIENT, SERVER, port, SERVER_PORT,
                          sequence, server_seq, payload))
        response = b"PI2R" + struct.pack("!H", transaction_id) + bytes([1, index + 1])
        response_packet, response_offset = add(frame(
            SERVER, CLIENT, SERVER_PORT, port, server_seq,
            client_seq + len(request), response,
        ))
        truth.append({
            "transaction_id": transaction_id,
            "client_port": port,
            "request_hex": request.hex(),
            "response_hex": response.hex(),
            "request_segments": sorted(source_parts, key=lambda part: part["sequence"]),
            "response_packet_index": response_packet,
            "response_source_offset": response_offset,
        })

    (HERE / "tcp_stream.pcap").write_bytes(classic)
    (HERE / "tcp_stream.pcapng").write_bytes(enhanced)
    (HERE / "tcp_stream.truth.json").write_text(json.dumps({
        "format": "Ethernet/IPv4/TCP/invented application",
        "packet_count": packet_index,
        "observation_count": len(CASES) * 2,
        "transaction_id_span": [4, 6],
        "cases": truth,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
