"""
build_chromadb.py
=================
Reads MITRE ATT&CK JSON, loads ALL techniques (all platforms),
converts each to a vector, stores in ChromaDB.

Changes from v2:
  - Removed Linux-only filter — now loads ALL MITRE techniques
  - Covers Windows, Linux, macOS, network, cloud platforms
  - Improves Windows Event Log and firewall log detection
  - Total techniques: ~700+ (was 369 Linux-only)

Run once — takes about 10-15 minutes.
"""

import json
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

MITRE_FILE = "./mitre_attack.json"
DB_PATH    = "./threat_db"
COLLECTION = "mitre_patterns"


def build_chromadb():
    print("Loading MITRE ATT&CK dataset...")
    with open(MITRE_FILE) as f:
        data = json.load(f)

    # Extract ALL attack-pattern objects — no platform filter
    techniques = [
        obj for obj in data["objects"]
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]
    print(f"Total techniques found: {len(techniques)}")

    # ── Embedder — MUST match llm_watcher.py ────────────────────────────────
    print("\nLoading embedding model (all-mpnet-base-v2)...")
    embedder = SentenceTransformer("all-mpnet-base-v2")

    # ── ChromaDB setup ───────────────────────────────────────────────────────
    print(f"Setting up ChromaDB at {DB_PATH}...")
    client = chromadb.PersistentClient(path=DB_PATH)

    try:
        client.delete_collection(COLLECTION)
        print("Deleted existing collection (rebuilding with all techniques)")
    except Exception:
        pass

    collection = client.create_collection(COLLECTION)

    # ── Process techniques ───────────────────────────────────────────────────
    print("\nEmbedding and storing techniques...")
    ids        = []
    documents  = []
    metadatas  = []
    embeddings = []

    for tech in tqdm(techniques):
        refs    = tech.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in refs if r.get("source_name") == "mitre-attack"),
            "UNKNOWN"
        )

        kill_chain = tech.get("kill_chain_phases", [])
        tactic     = kill_chain[0]["phase_name"] if kill_chain else "unknown"

        platforms  = ", ".join(tech.get("x_mitre_platforms", []))
        name       = tech.get("name", "")
        desc       = tech.get("description", "")[:800]
        detection  = tech.get("x_mitre_detection", "")[:200]

        # Include platform info in document for better retrieval
        doc_text = f"{name} [{platforms}]: {desc}"
        if detection:
            doc_text += f" Detection: {detection}"

        vector = embedder.encode(doc_text).tolist()

        ids.append(tech_id + "_" + tech["id"][-8:])
        documents.append(doc_text)
        metadatas.append({
            "id"       : tech_id,
            "technique": name,
            "tactic"   : tactic,
            "platforms": platforms,
        })
        embeddings.append(vector)

    # ── Store in batches ─────────────────────────────────────────────────────
    batch_size = 50
    for i in range(0, len(ids), batch_size):
        collection.add(
            ids        = ids[i:i+batch_size],
            documents  = documents[i:i+batch_size],
            metadatas  = metadatas[i:i+batch_size],
            embeddings = embeddings[i:i+batch_size]
        )

    print(f"\nChromaDB built successfully!")
    print(f"Total techniques stored: {collection.count()}")

    # ── Verification tests ───────────────────────────────────────────────────
    print("\nTesting retrieval across all log types...")
    tests = [
        ("Linux brute force",    "Failed password for root from 192.168.1.5 port 22 ssh2"),
        ("Windows logon failure","An account failed to log on. Account Name: administrator Source: 10.0.0.5"),
        ("Firewall port scan",   "Firewall: DENY TCP from 10.0.0.5:52020 to 192.168.1.10:22 scan probe"),
        ("Windows process",      "A new process has been created. Process Name: mimikatz.exe"),
        ("Privilege escalation", "sudo: www-data TTY=pts/1 COMMAND=/usr/bin/python3 -c import pty"),
    ]

    for label, test_log in tests:
        vec     = embedder.encode(test_log).tolist()
        results = collection.query(query_embeddings=[vec], n_results=3)
        print(f"\n{label}:")
        for i in range(3):
            meta = results["metadatas"][0][i]
            print(f"  [{meta['id']}] {meta['technique']} ({meta['tactic']}) — {meta['platforms']}")

    print("\nChromaDB is ready. Run llm_watcher.py to start analysis.")


if __name__ == "__main__":
    build_chromadb()
