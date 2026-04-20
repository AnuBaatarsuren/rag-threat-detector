"""
convert_otrf.py
===============
Converts OTRF Security Datasets (JSON format) into pipeline CSV format.

The OTRF JSON files contain real Windows Event Logs from simulated attacks.
Each line is one JSON event with a rich "Message" field — exactly what
the LLM needs for semantic reasoning.

Usage:
    python convert_otrf.py --output ~/thesis-rag/dataset_windows_real.csv

What it does:
    - Scans all JSON files in the OTRF windows attack folders
    - Extracts EventID, Hostname, Message, timestamp, source IP
    - Labels attack events as malicious (label=1)
    - Adds synthetic benign events for baseline context
    - Outputs a balanced CSV ready for inject_fresh.py
"""

import json
import os
import csv
import argparse
import random
from pathlib import Path
from datetime import datetime, timezone, timedelta

OTRF_BASE   = Path.home() / "datasets/otrf/datasets/atomic/windows"
OUTPUT_FILE = Path.home() / "thesis-rag/dataset_windows_real.csv"

# Map folder names to attack type labels
ATTACK_FOLDER_MAP = {
    "credential_access" : "Credential Access",
    "lateral_movement"  : "Lateral Movement",
    "privilege_escalation": "Privilege Escalation",
    "execution"         : "Execution",
    "persistence"       : "Persistence",
    "defense_evasion"   : "Defense Evasion",
    "discovery"         : "Discovery",
}

# Event IDs we care about — security-relevant
SECURITY_EVENT_IDS = {
    4624, 4625, 4627, 4634, 4647, 4648, 4649, 4657, 4663,
    4672, 4673, 4674, 4688, 4689, 4697, 4698, 4699, 4700,
    4701, 4702, 4720, 4722, 4724, 4725, 4726, 4728, 4732,
    4738, 4740, 4756, 4768, 4769, 4770, 4771, 4776, 4778,
    4779, 4798, 4799, 5140, 5145, 7034, 7035, 7036, 7045,
    1102, 4104, 4103,
}


def extract_src_ip(event: dict) -> str:
    """Try to extract a source IP from various OTRF field names."""
    for field in ["IpAddress", "SourceAddress", "WorkstationName",
                  "CallerProcessName", "SubjectUserSid"]:
        val = event.get(field, "")
        if val and val not in ("-", "::1", "LOCAL", ""):
            # Return only if it looks like an IP
            parts = str(val).split(".")
            if len(parts) == 4:
                return val
    return "10.0.0.5"  # default attacker IP for OTRF simulations


def clean_message(msg: str) -> str:
    """Clean up Windows event message for LLM readability."""
    if not msg:
        return ""
    # Remove excessive whitespace and carriage returns
    msg = msg.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    msg = " ".join(msg.split())
    # Truncate to reasonable length
    return msg[:300]


def iter_json_lines(path: Path):
    """
    Yield JSON lines from a file — handles:
      - plain .json files
      - .zip archives containing .json files
      - .tar.gz archives containing .json files
    """
    import zipfile
    import tarfile
    import io

    suffix = path.suffix.lower()
    name   = path.name.lower()

    try:
        if suffix == ".zip":
            with zipfile.ZipFile(path, "r") as zf:
                for inner in zf.namelist():
                    if inner.endswith(".json"):
                        with zf.open(inner) as jf:
                            for line in io.TextIOWrapper(jf, encoding="utf-8", errors="ignore"):
                                yield line.strip()

        elif name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(path, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.name.endswith(".json"):
                        f = tf.extractfile(member)
                        if f:
                            for line in io.TextIOWrapper(f, encoding="utf-8", errors="ignore"):
                                yield line.strip()

        elif suffix == ".json":
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line.strip()

    except Exception:
        return


def load_otrf_events(max_per_folder: int = 15) -> list[dict]:
    """
    Load attack events from OTRF Security Datasets.
    Handles .json, .zip, and .tar.gz files automatically.
    Takes up to max_per_folder events per attack category.
    """
    events = []
    seen_messages = set()

    for folder_name, attack_label in ATTACK_FOLDER_MAP.items():
        folder_path = OTRF_BASE / folder_name
        if not folder_path.exists():
            continue

        folder_events = []

        # Collect all files — json, zip, tar.gz
        all_files = (
            list(folder_path.rglob("*.json")) +
            list(folder_path.rglob("*.zip")) +
            list(folder_path.rglob("*.tar.gz")) +
            list(folder_path.rglob("*.tgz"))
        )

        for file_path in all_files:
            if len(folder_events) >= max_per_folder:
                break

            for line in iter_json_lines(file_path):
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Try EventID field — OTRF uses both "EventID" and "EventId"
                eid = 0
                for key in ("EventID", "EventId", "event_id"):
                    val = event.get(key)
                    if val:
                        try:
                            eid = int(val)
                            break
                        except (ValueError, TypeError):
                            pass

                # If no EventID match, still include if Message exists
                # OTRF sometimes has rich Message without standard EventID
                msg = clean_message(event.get("Message", ""))
                if not msg:
                    continue

                # Skip if EventID present but not security relevant
                if eid != 0 and eid not in SECURITY_EVENT_IDS:
                    continue

                if msg in seen_messages:
                    continue

                seen_messages.add(msg)

                folder_events.append({
                    "timestamp"  : event.get("@timestamp", "2024-04-15T08:00:00Z"),
                    "src_ip"     : extract_src_ip(event),
                    "username"   : event.get("SubjectUserName",
                                   event.get("TargetUserName", "UNKNOWN")),
                    "computer"   : event.get("Hostname",
                                   event.get("host", "DC01")),
                    "event_id"   : eid if eid else 4688,
                    "message"    : msg,
                    "label"      : 1,
                    "attack_type": attack_label,
                })

                if len(folder_events) >= max_per_folder:
                    break

        print(f"  {folder_name}: {len(folder_events)} events")
        events.extend(folder_events)

    return events


def generate_benign_events(count: int, base_time: datetime) -> list[dict]:
    """
    Generate realistic benign Windows events for baseline context.
    These simulate normal user activity before the attack starts.
    """
    users    = ["alice", "bob", "carol", "dave"]
    machines = ["DESKTOP-ALICE", "DESKTOP-BOB", "DESKTOP-CAROL", "DESKTOP-DAVE"]
    ips      = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40"]

    benign_templates = [
        (4624, "An account was successfully logged on. Subject: Security ID: DOMAIN\\{user} Logon Type: 3 Source Network Address: {ip}"),
        (4634, "An account was logged off. Subject: Security ID: DOMAIN\\{user} Logon Type: 3"),
        (4688, "A new process has been created. Creator Subject: DOMAIN\\{user} Process Name: C:\\Windows\\System32\\cmd.exe"),
        (4688, "A new process has been created. Creator Subject: DOMAIN\\{user} Process Name: C:\\Windows\\System32\\notepad.exe"),
        (4688, "A new process has been created. Creator Subject: DOMAIN\\{user} Process Name: C:\\Windows\\System32\\chrome.exe"),
        (4688, "A new process has been created. Creator Subject: DOMAIN\\{user} Process Name: C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE"),
        (4672, "Special privileges assigned to new logon. Subject: Security ID: DOMAIN\\{user} Privileges: SeBackupPrivilege SeChangeNotifyPrivilege"),
        (4688, "A new process has been created. Creator Subject: DOMAIN\\{user} Process Name: C:\\Windows\\System32\\powershell.exe CommandLine: Get-EventLog -LogName Security -Newest 10"),
        (4624, "An account was successfully logged on. Subject: Security ID: DOMAIN\\{user} Logon Type: 2 Source Network Address: {ip}"),
        (4688, "A new process has been created. Creator Subject: DOMAIN\\{user} Process Name: C:\\Windows\\System32\\mmc.exe"),
    ]

    events = []
    for i in range(count):
        idx     = i % len(users)
        user    = users[idx]
        machine = machines[idx]
        ip      = ips[idx]
        ts      = base_time + timedelta(seconds=i * 15)
        eid, tmpl = random.choice(benign_templates)
        msg     = tmpl.format(user=user, ip=ip)

        events.append({
            "timestamp"  : ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip"     : ip,
            "username"   : user,
            "computer"   : machine,
            "event_id"   : eid,
            "message"    : msg,
            "label"      : 0,
            "attack_type": "NONE",
        })

    return events


def convert(output_path: Path, max_attack: int = 15, benign_count: int = 45):
    print(f"\nLoading OTRF attack events from {OTRF_BASE}...")
    attack_events = load_otrf_events(max_per_folder=max_attack)
    print(f"Total attack events loaded: {len(attack_events)}")

    print(f"\nGenerating {benign_count} benign baseline events...")
    base_time = datetime(2024, 4, 15, 8, 0, 0, tzinfo=timezone.utc)
    benign_events = generate_benign_events(benign_count, base_time)

    # Assign attack timestamps after benign period
    attack_base = base_time + timedelta(minutes=12)
    for i, ev in enumerate(attack_events):
        ev["timestamp"] = (attack_base + timedelta(seconds=i * 8)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        ev["src_ip"] = "10.0.0.5"

    all_events = benign_events + attack_events
    all_events.sort(key=lambda x: x["timestamp"])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "src_ip", "username", "computer",
            "event_id", "message", "label", "attack_type"
        ])
        writer.writeheader()
        writer.writerows(all_events)

    total    = len(all_events)
    n_attack = sum(1 for e in all_events if e["label"] == 1)
    n_benign = sum(1 for e in all_events if e["label"] == 0)

    print(f"\nOutput: {output_path}")
    print(f"Total logs : {total}")
    print(f"Benign     : {n_benign}")
    print(f"Attack     : {n_attack}")

    # Attack type breakdown
    from collections import Counter
    types = Counter(e["attack_type"] for e in all_events if e["label"] == 1)
    for t, c in types.most_common():
        print(f"  {t:<30} {c}")

    print("\nDone. Copy to thesis-rag and use with inject_fresh.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(OUTPUT_FILE))
    parser.add_argument("--max-attack", type=int, default=15,
                        help="Max attack events per category")
    parser.add_argument("--benign", type=int, default=45,
                        help="Number of benign events to generate")
    args = parser.parse_args()
    convert(Path(args.output), args.max_attack, args.benign)
