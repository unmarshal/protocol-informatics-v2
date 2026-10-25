#!/usr/bin/env python3
"""Optional controlled IPv4 ICMP capture; requires raw socket/capture privileges."""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface")
    parser.add_argument("target", type=lambda text: socket.inet_ntoa(socket.inet_aton(text)))
    parser.add_argument("investigation", type=Path)
    parser.add_argument("cli", type=lambda text: str(Path(text).resolve()))
    args = parser.parse_args()
    if args.investigation.exists():
        parser.error("use an unused investigation directory")

    def cli(command, *values):
        output = subprocess.check_output([args.cli, command, str(args.investigation), *map(str, values)])
        return json.loads(output)

    # Establish raw-socket permission before writing the investigation.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sender:
        if hasattr(socket, "SO_BINDTODEVICE"):
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode() + b"\0")
        cli("init", "Does ICMP sequence 255 to 256 change request and reply bytes?")
        experiment = cli("experiment", "Cross the ICMP low-byte boundary", "-", "Requests and replies carry the changed sequence")
        experiment_id = experiment["event"]["experiment"]["id"]
        trial_ids = []
        matches = []
        for role, sequence in [("baseline", 255), ("variant", 256)]:
            trial = cli("trial", experiment_id, role, "ICMP sequence")
            trial_id = trial["event"]["trial"]["id"]
            trial_ids.append(trial_id)
            key = f"live-{sequence}"
            cli("network-capture-start", trial_id, key, args.interface,
                f"icmp and host {args.target}", 4000, 1048576, "-", "pcapng-icmp")
            time.sleep(1)
            status = cli("capture-status", key)
            if status["status"] != "running":
                raise RuntimeError(f"backend not running before stimulus: {status}")
            packet = struct.pack("!BBHHH", 8, 0, 0, 0x1234, sequence) + b"pi-smoke"
            total = sum(struct.unpack(f"!{len(packet)//2}H", packet))
            while total >> 16:
                total = (total & 0xffff) + (total >> 16)
            packet = packet[:2] + struct.pack("!H", (~total) & 0xffff) + packet[4:]
            action = cli("mark-keyed", trial_id, "stimulus",
                         json.dumps({"target": args.target, "interface": args.interface,
                                     "icmp_hex": packet.hex(), "sequence": sequence}),
                         f"{key}-action", time.time_ns())
            sender.sendto(packet, (args.target, 0))
            deadline = time.monotonic() + 10
            while True:
                status = cli("capture-status", key)
                if status["status"] == "completed":
                    break
                if status["status"] in ("failed", "interrupted") or time.monotonic() > deadline:
                    raise RuntimeError(status)
                time.sleep(0.1)
            cli("tag-capture", action["action"]["id"], status["capture"]["id"],
                "capture_scope", f"ICMP sequence {sequence} acquisition", f"{key}-tags")
            # Read the portable log locally to inspect all observations, avoiding pagination limits.
            observations = []
            for line in (args.investigation / ".pi/events.jsonl").read_text().splitlines():
                event = json.loads(line)["event"]
                if event.get("capture", {}).get("id") == status["capture"]["id"]:
                    observations = event["observations"]
            requests, replies = [], []
            for observation in observations:
                data = bytes.fromhex(observation["bytes_hex"])
                if len(data) >= 8 and data[4:] == packet[4:]:
                    if data[0] == 8:
                        requests.append(observation["id"])
                    elif data[0] == 0:
                        replies.append(observation["id"])
            matches.append({"sequence": sequence, "request_ids": requests, "reply_ids": replies,
                            "outcome": "observed" if requests and replies else "inconclusive"})
        comparison = cli("compare-trials", *trial_ids)
        cli("verify")
        cli("report", args.investigation / "report.html")
        result = {"matched_echoes": matches, "comparison": comparison}
        (args.investigation / "smoke-result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
