"""Generate deterministic Ethernet/IPv4/ICMP echo traffic for regression tests.

Uses only the Python standard library. The addresses are TEST-NET-1 examples.
"""

import json
import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
REQUEST_SOURCE = bytes([192, 0, 2, 1])
REPLY_SOURCE = bytes([192, 0, 2, 2])
SEQUENCES = [0, 1, 2, 7, 255, 256, 257, 513, 1024, 4096, 32768, 65535]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(icmp_type: int, identifier: int, sequence: int, payload: bytes) -> bytes:
    source, destination = (
        (REQUEST_SOURCE, REPLY_SOURCE)
        if icmp_type == 8
        else (REPLY_SOURCE, REQUEST_SOURCE)
    )
    icmp_header = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence)
    icmp = icmp_header + payload
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(icmp), sequence, 0, 64, 1, 0, source, destination
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip_header + icmp


def pcapng_block(block_type: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def main() -> None:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    capture = bytearray(header)
    section = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    capture_ng = bytearray(section + interface)
    isolated = {255: bytearray(header), 256: bytearray(header)}
    cases = []
    for index, sequence in enumerate(SEQUENCES):
        identifier = 0x1234 if index < 6 else 0x2345
        payload = bytes((index + offset) % 256 for offset in range(index % 7))
        # Hold payload and identifier constant across 255 -> 256. That pair
        # isolates the sequence change (plus its dependent checksum).
        if sequence == 256:
            payload = bytes((4 + offset) % 256 for offset in range(4))
        for icmp_type in (8, 0):
            frame = packet(icmp_type, identifier, sequence, payload)
            timestamp_us = index * 1_000_000 + (0 if icmp_type == 8 else 50_000)
            record = struct.pack("<IIII", 1_700_000_000 + timestamp_us // 1_000_000,
                                 timestamp_us % 1_000_000, len(frame), len(frame)) + frame
            capture.extend(record)
            ticks = 1_700_000_000 * 1_000_000 + timestamp_us
            capture_ng.extend(pcapng_block(6, struct.pack("<IIIII", 0, ticks >> 32,
                                                          ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame))
            if sequence in isolated:
                isolated[sequence].extend(record)
            cases.append({"type": icmp_type, "identifier": identifier,
                          "sequence": sequence, "payload_length": len(payload)})
    (HERE / "icmp_echo.pcap").write_bytes(capture)
    (HERE / "icmp_echo.pcapng").write_bytes(capture_ng)
    (HERE / "icmp_baseline_255.pcap").write_bytes(isolated[255])
    (HERE / "icmp_variant_256.pcap").write_bytes(isolated[256])
    sweep = bytearray(header)
    for sequence in range(512):
        for icmp_type in (8, 0):
            frame = packet(icmp_type, 0x4567, sequence, bytes.fromhex("11223344"))
            timestamp_us = sequence * 100_000 + (0 if icmp_type == 8 else 50_000)
            sweep.extend(
                struct.pack(
                    "<IIII",
                    1_720_000_000 + timestamp_us // 1_000_000,
                    timestamp_us % 1_000_000,
                    len(frame),
                    len(frame),
                )
                + frame
            )
    (HERE / "icmp_sweep_512.pcap").write_bytes(sweep)
    sweep_holdout = bytearray(header)
    for sequence in range(512, 1024):
        for icmp_type in (8, 0):
            frame = packet(icmp_type, 0x4567, sequence, bytes.fromhex("11223344"))
            timestamp_us = (sequence - 512) * 100_000 + (0 if icmp_type == 8 else 50_000)
            sweep_holdout.extend(
                struct.pack(
                    "<IIII",
                    1_721_000_000 + timestamp_us // 1_000_000,
                    timestamp_us % 1_000_000,
                    len(frame),
                    len(frame),
                )
                + frame
            )
    (HERE / "icmp_sweep_512_holdout.pcap").write_bytes(sweep_holdout)
    (HERE / "icmp_sweep_512.truth.json").write_text(
        json.dumps(
            {
                "packet_count": 1024,
                "sequence_range": [0, 511],
                "holdout_capture": "icmp_sweep_512_holdout.pcap",
                "holdout_sequence_range": [512, 1023],
                "request_type": 8,
                "reply_type": 0,
                "identifier": 0x4567,
                "payload_hex": "11223344",
                "sequence_span": [6, 8],
                "checksum_span": [2, 4],
            },
            indent=2,
        )
        + "\n"
    )
    holdout = bytearray(header)
    mismatched_reply = bytearray(header)
    for index, sequence in enumerate((3, 258, 4097)):
        payload = bytes([0xA0 + index, 0xB0, 0xC0 + index]) + bytes(range(index))
        for icmp_type in (8, 0):
            frame = packet(icmp_type, 0x3456, sequence, payload)
            changed_frame = packet(
                icmp_type, 0x3456,
                sequence + (1 if index == 1 and icmp_type == 0 else 0), payload,
            )
            timestamp_us = index * 1_000_000 + (0 if icmp_type == 8 else 50_000)
            holdout.extend(struct.pack("<IIII", 1_710_000_000 + timestamp_us // 1_000_000,
                                      timestamp_us % 1_000_000, len(frame), len(frame)) + frame)
            mismatched_reply.extend(
                struct.pack("<IIII", 1_710_000_000 + timestamp_us // 1_000_000,
                            timestamp_us % 1_000_000, len(changed_frame), len(changed_frame))
                + changed_frame
            )
    (HERE / "icmp_holdout.pcap").write_bytes(holdout)
    (HERE / "icmp_mismatched_reply.pcap").write_bytes(mismatched_reply)
    truth = {"capture_format": "pcap", "alternate_capture_format": "pcapng",
             "linktype": 1, "packet_count": len(cases),
             "holdout_capture": "icmp_holdout.pcap",
             "controlled_pair": ["icmp_baseline_255.pcap", "icmp_variant_256.pcap"],
             "icmp_fields": {"type": [0, 1], "code": [1, 2],
                             "checksum": [2, 4], "identifier": [4, 6],
                             "sequence": [6, 8], "payload": [8, None]},
             "cases": cases}
    (HERE / "icmp_echo.truth.json").write_text(json.dumps(truth, indent=2) + "\n")


if __name__ == "__main__":
    main()
