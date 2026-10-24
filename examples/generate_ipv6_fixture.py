#!/usr/bin/env python3
"""Generate deterministic IPv6 ICMPv6, UDP, and TCP evidence in PCAP and pcapng."""

import ipaddress
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ipaddress.IPv6Address("2001:db8::1").packed
DESTINATION = ipaddress.IPv6Address("2001:db8::2").packed
BASE_MICROSECONDS = 1_700_001_000_000_000


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def transport_checksum(source, destination, protocol, message):
    pseudo = source + destination + struct.pack("!I3xB", len(message), protocol)
    return checksum(pseudo + message)


def icmpv6(source, destination, kind, sequence, payload):
    message = struct.pack("!BBHHH", kind, 0, 0, 0x2345, sequence) + payload
    value = transport_checksum(source, destination, 58, message)
    return message[:2] + struct.pack("!H", value) + message[4:]


def udp(source, destination, source_port, destination_port, data):
    message = struct.pack("!HHHH", source_port, destination_port, len(data) + 8, 0) + data
    value = transport_checksum(source, destination, 17, message) or 0xFFFF
    return message[:6] + struct.pack("!H", value) + data


def tcp(source, destination, source_port, destination_port, sequence, acknowledgment, data):
    message = struct.pack(
        "!HHIIHHHH", source_port, destination_port, sequence, acknowledgment, 0x5018, 4096, 0, 0
    ) + data
    value = transport_checksum(source, destination, 6, message)
    return message[:16] + struct.pack("!H", value) + message[18:]


def ipv6_frame(source, destination, protocol, message, option_header=False):
    extension = bytes([protocol, 0, 0, 0, 0, 0, 0, 0]) if option_header else b""
    header = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        len(extension) + len(message),
        0 if option_header else protocol,
        64,
        source,
        destination,
    )
    frame = bytes.fromhex("020000000002 020000000001 86dd") + header + extension + message
    return frame, len(extension)


def block(kind, body):
    body += b"\0" * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def main():
    packets = []
    for index, sequence in enumerate((0, 1, 255, 256, 1024, 65535)):
        payload = bytes([index + 1]) * (index % 3)
        for reply in (False, True):
            source, destination = (DESTINATION, SOURCE) if reply else (SOURCE, DESTINATION)
            message = icmpv6(source, destination, 129 if reply else 128, sequence, payload)
            frame, extension_length = ipv6_frame(
                source, destination, 58, message, option_header=sequence == 256
            )
            packets.append((frame, extension_length, 0, "icmpv6", message, sequence, source, destination))

    for index, transaction_id in enumerate((0x0100, 0x0101, 0x01FF, 0x0200)):
        for reply in (False, True):
            source, destination = (DESTINATION, SOURCE) if reply else (SOURCE, DESTINATION)
            source_port, destination_port = (7000, 40000) if reply else (40000, 7000)
            data = b"PI2" + transaction_id.to_bytes(2, "big") + (b"R" if reply else b"Q")
            message = udp(source, destination, source_port, destination_port, data)
            frame, extension_length = ipv6_frame(
                source, destination, 17, message, option_header=index == 2
            )
            packets.append((frame, extension_length, 8, "udp", data, transaction_id, source, destination))

    tcp_parts = (
        (SOURCE, DESTINATION, 5000, 6000, 1000, 7000, b"PI2Q\0\0"),
        (SOURCE, DESTINATION, 5000, 6000, 1006, 7000, b"\x01a"),
        (DESTINATION, SOURCE, 6000, 5000, 7000, 1008, b"PI2R\0\0"),
        (DESTINATION, SOURCE, 6000, 5000, 7006, 1008, b"\x01b"),
    )
    for source, destination, source_port, destination_port, sequence, acknowledgment, data in tcp_parts:
        message = tcp(source, destination, source_port, destination_port, sequence, acknowledgment, data)
        frame, extension_length = ipv6_frame(source, destination, 6, message)
        packets.append((frame, extension_length, 20, "tcp", data, sequence, source, destination))

    classic = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    enhanced = bytearray()
    enhanced.extend(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    enhanced.extend(block(1, struct.pack("<HHI", 1, 0, 65535)))
    truth = []
    for index, (frame, extension_length, transport_header_length, kind, data, value, source, destination) in enumerate(packets):
        timestamp_us = BASE_MICROSECONDS + index * 100_000
        seconds, fraction = divmod(timestamp_us, 1_000_000)
        classic_packet_start = len(classic)
        classic.extend(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
        classic.extend(frame)
        enhanced_packet_start = len(enhanced)
        body = struct.pack("<IIIII", 0, timestamp_us >> 32, timestamp_us & 0xFFFFFFFF, len(frame), len(frame)) + frame
        enhanced.extend(block(6, body))
        frame_offset = 14 + 40 + extension_length + transport_header_length
        truth.append({
            "packet_index": index,
            "kind": kind,
            "value": value,
            "timestamp_ns": timestamp_us * 1000,
            "source_ip": str(ipaddress.IPv6Address(source)),
            "destination_ip": str(ipaddress.IPv6Address(destination)),
            "bytes_hex": data.hex(),
            "pcap_source_offset": classic_packet_start + 16 + frame_offset,
            "pcapng_source_offset": enhanced_packet_start + 28 + frame_offset,
        })

    (ROOT / "ipv6_mixed.pcap").write_bytes(classic)
    (ROOT / "ipv6_mixed.pcapng").write_bytes(enhanced)
    (ROOT / "ipv6_mixed.truth.json").write_text(json.dumps({"cases": truth}, indent=2) + "\n")
    print(f"wrote {len(packets)} IPv6 packets")


if __name__ == "__main__":
    main()
