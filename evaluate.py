"""
evaluate.py
===========
Compares LLM verdicts in Elasticsearch against ground truth labels.
Works with all three dataset types.

Usage:
    python evaluate.py                              # Linux auth logs (default)
    python evaluate.py dataset_windows_real.csv     # Windows Event Logs
    python evaluate.py dataset_firewall_real.csv    # Firewall logs
"""

import csv
import sys
import json
from elasticsearch import Elasticsearch

ES_HOST   = "http://localhost:9200"
RAW_INDEX = "thesis-simulation-*"
CSV_FILE  = sys.argv[1] if len(sys.argv) > 1 else "./dataset_fresh_test.csv"

es = Elasticsearch(ES_HOST)


def fetch_all_verdicts() -> dict:
    query = {
        "size": 1000,
        "query": {"term": {"llm_analyzed": "true"}},
        "_source": ["message", "llm_verdict", "attack_type", "confidence"]
    }
    res    = es.search(index=RAW_INDEX, body=query)
    hits   = res["hits"]["hits"]
    result = {}
    for h in hits:
        src = h["_source"]
        msg = src.get("message", "").strip()
        result[msg] = {
            "verdict"    : src.get("llm_verdict", "NO"),
            "attack_type": src.get("attack_type", "NONE"),
            "confidence" : src.get("confidence", "LOW"),
        }
    return result


def load_ground_truth() -> list:
    rows = []
    with open(CSV_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({
                "message"    : row["message"].strip(),
                "label"      : int(row["label"]),
                "attack_type": row["attack_type"],
            })
    return rows


def evaluate():
    print("\n" + "=" * 60)
    print("  EVALUATION — RAG+LLM vs Ground Truth")
    print("=" * 60)

    verdicts     = fetch_all_verdicts()
    ground_truth = load_ground_truth()

    total     = len(ground_truth)
    matched   = 0
    not_found = 0

    TP_raw = FP_raw = TN_raw = FN_raw = 0
    TP_fil = FP_fil = TN_fil = FN_fil = 0

    attack_results = {}

    for row in ground_truth:
        msg    = row["message"]
        label  = row["label"]
        attack = row["attack_type"]

        if msg not in verdicts:
            not_found += 1
            continue

        matched    += 1
        verdict     = verdicts[msg]["verdict"]
        confidence  = verdicts[msg]["confidence"]

        predicted_raw = 1 if verdict == "YES" else 0
        predicted_fil = 1 if (verdict == "YES" and confidence == "HIGH") else 0

        if label == 1 and predicted_raw == 1:
            TP_raw += 1
        elif label == 0 and predicted_raw == 1:
            FP_raw += 1
        elif label == 0 and predicted_raw == 0:
            TN_raw += 1
        elif label == 1 and predicted_raw == 0:
            FN_raw += 1

        if label == 1 and predicted_fil == 1:
            TP_fil += 1
        elif label == 0 and predicted_fil == 1:
            FP_fil += 1
        elif label == 0 and predicted_fil == 0:
            TN_fil += 1
        elif label == 1 and predicted_fil == 0:
            FN_fil += 1

        if attack != "NONE":
            if attack not in attack_results:
                attack_results[attack] = {"TP": 0, "FN": 0}
            if predicted_fil == 1:
                attack_results[attack]["TP"] += 1
            else:
                attack_results[attack]["FN"] += 1

    def metrics(TP, FP, TN, FN, n):
        acc  = (TP + TN) / n if n else 0
        prec = TP / (TP + FP) if (TP + FP) > 0 else 0
        rec  = TP / (TP + FN) if (TP + FN) > 0 else 0
        f1   = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
        return acc, prec, rec, f1

    acc_r, prec_r, rec_r, f1_r = metrics(TP_raw, FP_raw, TN_raw, FN_raw, matched)
    acc_f, prec_f, rec_f, f1_f = metrics(TP_fil, FP_fil, TN_fil, FN_fil, matched)

    print(f"\n  Dataset      : {CSV_FILE}")
    print(f"  Total logs   : {total}")
    print(f"  Matched in ES: {matched}")
    print(f"  Not found    : {not_found}")

    print(f"\n{'─'*40}")
    print(f"  RAW (all YES verdicts)")
    print(f"{'─'*40}")
    print(f"  TP={TP_raw}  FP={FP_raw}  TN={TN_raw}  FN={FN_raw}")
    print(f"  Accuracy  : {acc_r*100:.2f}%")
    print(f"  Precision : {prec_r*100:.2f}%")
    print(f"  Recall    : {rec_r*100:.2f}%")
    print(f"  F1 Score  : {f1_r*100:.2f}%")

    print(f"\n{'─'*40}")
    print(f"  FILTERED (HIGH confidence only)")
    print(f"{'─'*40}")
    print(f"  TP={TP_fil}  FP={FP_fil}  TN={TN_fil}  FN={FN_fil}")
    print(f"  Accuracy  : {acc_f*100:.2f}%")
    print(f"  Precision : {prec_f*100:.2f}%")
    print(f"  Recall    : {rec_f*100:.2f}%")
    print(f"  F1 Score  : {f1_f*100:.2f}%")

    print(f"\n{'─'*40}")
    print(f"  Per Attack Type (HIGH confidence)")
    print(f"{'─'*40}")
    for attack, counts in sorted(attack_results.items()):
        tp  = counts["TP"]
        fn  = counts["FN"]
        tot = tp + fn
        r   = tp / tot * 100 if tot else 0
        print(f"  {attack:<30} detected {tp}/{tot} ({r:.0f}% recall)")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    evaluate()
