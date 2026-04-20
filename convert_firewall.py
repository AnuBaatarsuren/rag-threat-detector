"""
convert_firewall.py
===================
Converts the Firat University / UCI Internet Firewall dataset
(log2.csv) into pipeline CSV format with readable message text.

The raw firewall dataset has numerical features only:
  Source Port, Destination Port, NAT Source Port, NAT Destination Port,
  Action, Bytes, Bytes Sent, Bytes Received, Packets, Elapsed Time,
  pkts_sent, pkts_received

This converter:
  1. Converts each row into a human-readable firewall log message
  2. Adds realistic synthetic IP addresses
  3. Labels suspicious traffic as attacks based on behavioral patterns
  4. Generates a balanced dataset ready for the pipeline

Usage:
    python convert_firewall.py \
        --input ~/datasets/firewall.csv \
        --output ~/thesis-rag/dataset_firewall_real.csv
"""

import csv
import random
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta

INPUT_FILE  = Path.home() / "datasets/firewall.csv"
OUTPUT_FILE = Path.home() / "thesis-rag/dataset_firewall_real.csv"

# Known malicious port patterns
C2_PORTS       = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 2222}
SCAN_PORTS     = {22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080}
EXFIL_PORTS    = {21, 22, 80, 443, 53, 8080, 8443}
INTERNAL_RANGE = ["192.168.1.", "192.168.2.", "10.0.0.", "172.16.0."]
EXTERNAL_IPS   = [
    "5.252.153.241", "45.125.66.32", "10.10.10.99",
    "185.220.101.1", "91.108.4.1", "194.165.16.1",
    "23.106.223.1",  "172.105.78.1"
]
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "192.168.1.40", "192.168.1.50", "192.168.1.100"
]

# Protocol map
PROTO_MAP = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
    25: "SMTP", 53: "DNS", 3389: "RDP", 445: "SMB",
    139: "NetBIOS", 23: "Telnet", 110: "POP3", 143: "IMAP",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 135: "RPC",
}


def get_protocol(port: int) -> str:
    return PROTO_MAP.get(port, "TCP")


def classify_traffic(row: dict) -> tuple[int, str]:
    """
    Classify firewall log row as benign or attack based on behavioral signals.
    Returns (label, attack_type).

    This is the key function — it applies security domain knowledge
    to label numerical firewall data without ground truth labels.
    """
    try:
        dst_port   = int(row.get("Destination Port", 0))
        src_port   = int(row.get("Source Port", 0))
        action     = row.get("Action", "allow").lower()
        bytes_sent = int(row.get("Bytes Sent", 0))
        bytes_recv = int(row.get("Bytes Received", 0))
        packets    = int(row.get("Packets", 0))
        elapsed    = float(row.get("Elapsed Time (sec)", 1))
    except (ValueError, TypeError):
        return 0, "NONE"

    # C2 beaconing — known C2 ports with regular small packets
    if dst_port in C2_PORTS:
        return 1, "C2 Communication"

    # Port scan — many packets to scan ports with deny action
    if action == "deny" and dst_port in SCAN_PORTS and packets <= 3:
        return 1, "Port Scan"

    # Data exfiltration — large outbound transfer
    if bytes_sent > 500000 and bytes_recv < bytes_sent * 0.1:
        return 1, "Data Exfiltration"

    # Brute force — many small packets to auth ports
    if dst_port in {22, 3389, 23, 21} and packets > 50 and elapsed < 60:
        return 1, "Brute Force"

    # DDoS — massive packet volume in short time
    if packets > 1000 and elapsed < 10:
        return 1, "DDoS"

    # Reset/drop action — firewall blocked something suspicious
    if action in {"reset", "reset-both", "drop"} and dst_port in SCAN_PORTS:
        return 1, "Blocked Scan"

    return 0, "NONE"


def make_message(row: dict, src_ip: str, dst_ip: str, label: int, attack_type: str) -> str:
    """Convert numerical firewall row into readable log message."""
    try:
        src_port   = int(row.get("Source Port", 0))
        dst_port   = int(row.get("Destination Port", 0))
        action     = row.get("Action", "allow").upper()
        bytes_val  = int(row.get("Bytes", 0))
        packets    = int(row.get("Packets", 0))
        elapsed    = float(row.get("Elapsed Time (sec)", 0))
        proto      = get_protocol(dst_port)
    except (ValueError, TypeError):
        return ""

    msg = (
        f"Firewall: {action} {proto} from {src_ip}:{src_port} "
        f"to {dst_ip}:{dst_port} — "
        f"{packets} packets, {bytes_val} bytes, {elapsed}s elapsed"
    )

    if label == 1:
        if attack_type == "C2 Communication":
            msg += f" [SUSPICIOUS: known C2 port {dst_port}]"
        elif attack_type == "Port Scan":
            msg += f" [SUSPICIOUS: scan probe to port {dst_port}, action={action}]"
        elif attack_type == "Data Exfiltration":
            msg += f" [SUSPICIOUS: large outbound transfer {bytes_val} bytes]"
        elif attack_type == "Brute Force":
            msg += f" [SUSPICIOUS: high packet rate to auth port {dst_port}]"
        elif attack_type == "DDoS":
            msg += f" [SUSPICIOUS: {packets} packets in {elapsed}s — volumetric attack]"

    return msg


def convert(input_path: Path, output_path: Path,
            target_benign: int = 50, target_attack: int = 40):

    print(f"\nReading firewall dataset from {input_path}...")

    attack_rows  = []
    benign_rows  = []

    with open(input_path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label, attack_type = classify_traffic(row)
            if label == 1 and len(attack_rows) < target_attack * 3:
                attack_rows.append((row, label, attack_type))
            elif label == 0 and len(benign_rows) < target_benign * 3:
                benign_rows.append((row, label, attack_type))

    print(f"Found {len(attack_rows)} attack candidates")
    print(f"Found {len(benign_rows)} benign candidates")

    # Sample balanced dataset
    random.seed(42)
    selected_attack = random.sample(attack_rows,  min(target_attack, len(attack_rows)))
    selected_benign = random.sample(benign_rows,  min(target_benign, len(benign_rows)))

    # Assign timestamps — benign first, then attacks
    base_time = datetime(2024, 4, 16, 8, 0, 0, tzinfo=timezone.utc)
    output_rows = []

    for i, (row, label, attack_type) in enumerate(selected_benign):
        ts      = base_time + timedelta(seconds=i * 20)
        src_ip  = random.choice(INTERNAL_IPS)
        dst_ip  = random.choice(INTERNAL_IPS + ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
        msg     = make_message(row, src_ip, dst_ip, label, attack_type)
        if not msg:
            continue
        output_rows.append({
            "timestamp"  : ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip"     : src_ip,
            "dst_ip"     : dst_ip,
            "src_port"   : row.get("Source Port", "0"),
            "dst_port"   : row.get("Destination Port", "0"),
            "action"     : row.get("Action", "allow"),
            "message"    : msg,
            "label"      : label,
            "attack_type": attack_type,
        })

    attack_base = base_time + timedelta(minutes=20)
    for i, (row, label, attack_type) in enumerate(selected_attack):
        ts     = attack_base + timedelta(seconds=i * 10)
        src_ip = "10.0.0.5"
        dst_ip = random.choice(INTERNAL_IPS) if random.random() > 0.5 else random.choice(EXTERNAL_IPS)
        msg    = make_message(row, src_ip, dst_ip, label, attack_type)
        if not msg:
            continue
        output_rows.append({
            "timestamp"  : ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip"     : src_ip,
            "dst_ip"     : dst_ip,
            "src_port"   : row.get("Source Port", "0"),
            "dst_port"   : row.get("Destination Port", "0"),
            "action"     : row.get("Action", "allow"),
            "message"    : msg,
            "label"      : label,
            "attack_type": attack_type,
        })

    output_rows.sort(key=lambda x: x["timestamp"])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "action", "message", "label", "attack_type"
        ])
        writer.writeheader()
        writer.writerows(output_rows)

    total    = len(output_rows)
    n_attack = sum(1 for r in output_rows if r["label"] == 1)
    n_benign = sum(1 for r in output_rows if r["label"] == 0)

    print(f"\nOutput : {output_path}")
    print(f"Total  : {total}")
    print(f"Benign : {n_benign}")
    print(f"Attack : {n_attack}")

    from collections import Counter
    types = Counter(r["attack_type"] for r in output_rows if r["label"] == 1)
    for t, c in types.most_common():
        print(f"  {t:<30} {c}")

    print("\nDone. Copy to thesis-rag and use with inject_fresh.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  default=str(INPUT_FILE))
    parser.add_argument("--output", default=str(OUTPUT_FILE))
    parser.add_argument("--benign", type=int, default=50)
    parser.add_argument("--attack", type=int, default=40)
    args = parser.parse_args()
    convert(Path(args.input), Path(args.output), args.benign, args.attack)
