"""
inject_fresh.py
===============
Reads dataset_fresh_test.csv and writes each log line
to logs/linux.log for Filebeat to pick up.

Writes logs with a small delay to simulate real-time arrival.
Sets llm_analyzed=false on each doc after Filebeat ingests it.
"""

import csv
import time
import os
import sys

CSV_FILE = sys.argv[1] if len(sys.argv) > 1 else "./dataset_fresh_test.csv"
LOG_FILE = "./logs/linux.log"
DELAY    = 0.3

os.makedirs("./logs", exist_ok=True)

print(f"Reading: {CSV_FILE}")
print(f"Writing to: {LOG_FILE}")
print(f"Delay between logs: {DELAY}s\n")

with open(CSV_FILE, newline="") as f:
    reader = list(csv.DictReader(f))

total = len(reader)
print(f"Total logs to inject: {total}\n")

with open(LOG_FILE, "a") as logfile:
    for i, row in enumerate(reader, 1):
        line = row["message"].strip()
        logfile.write(line + "\n")
        logfile.flush()

        label  = row.get("label", "0")
        attack = row.get("attack_type", "NONE")
        tag    = f"[{attack}]" if label == "1" else "[BENIGN]"

        print(f"  [{i:>3}/{total}] {tag} {line[:70]}")
        time.sleep(DELAY)

print(f"\nDone — {total} logs injected into {LOG_FILE}")
