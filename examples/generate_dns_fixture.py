"""Generate deterministic DNS query/reply UDP captures using the standard library.

The names are under .example and the addresses are documentation addresses.
Packet structure follows RFC 1035; the tool extracts UDP datagrams without
assuming that their payload is DNS.
"""

import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
CLIENT = bytes([192, 0, 2, 10])
SERVER = bytes([192, 0, 2, 53])
CASES = [
    (0, "a.example"),
    (1, "longer.example"),
    (2, "x.example"),
    (255, "delta.example"),
    (256, "a.example"),
    (257, "many-labels.example"),
]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def qname(name: str) -> bytes:
    labels = name.split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"


def dns_message(transaction_id: int, name: str, response: bool, answer_octet: int) -> bytes:
    question = qname(name) + struct.pack("!HH", 1, 1)
    header = struct.pack(
        "!HHHHHH", transaction_id, 0x8180 if response else 0x0100,
        1, 1 if response else 0, 0, 0,
    )
    answer = (
        struct.pack("!HHHIH4B", 0xC00C, 1, 1, 60, 4, 203, 0, 113, answer_octet)
        if response else b""
    )
    return header + question + answer


def frame(transaction_id: int, name: str, response: bool, answer_octet: int, port: int) -> bytes:
    source, destination = (SERVER, CLIENT) if response else (CLIENT, SERVER)
    udp_payload = dns_message(transaction_id, name, response, answer_octet)
    udp_length = 8 + len(udp_payload)
    udp = struct.pack("!HHHH", 53 if response else port,
                      port if response else 53, udp_length, 0) + udp_payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), transaction_id,
                     0, 64, 17, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + udp


def pcapng_block(block_type: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def main() -> None:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    classic = bytearray(header)
    section = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    enhanced = bytearray(section + interface)
    truth = []
    for index, (transaction_id, name) in enumerate(CASES):
        port = 40000 + index
        for response in (False, True):
            raw = frame(transaction_id, name, response, index + 1, port)
            timestamp_us = index * 1_000_000 + (50_000 if response else 0)
            seconds = 1_720_000_000 + timestamp_us // 1_000_000
            micros = timestamp_us % 1_000_000
            classic.extend(struct.pack("<IIII", seconds, micros, len(raw), len(raw)) + raw)
            ticks = seconds * 1_000_000 + micros
            enhanced.extend(pcapng_block(
                6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                               len(raw), len(raw)) + raw,
            ))
            truth.append({"transaction_id": transaction_id, "name": name,
                          "response": response, "client_port": port,
                          "udp_length": len(raw) - 14 - 20})
    (HERE / "dns_udp.pcap").write_bytes(classic)
    (HERE / "dns_udp.pcapng").write_bytes(enhanced)
    (HERE / "dns_udp.truth.json").write_text(json.dumps({
        "format": "Ethernet/IPv4/UDP/DNS", "packet_count": len(truth),
        "transport_header_bytes": 8, "dns_transaction_id_span": [0, 2],
        "cases": truth,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
