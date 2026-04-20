"""
build_chromadb_with_sigma.py
============================
Rebuilds ChromaDB with TWO knowledge sources combined:
  1. MITRE ATT&CK techniques (abstract technique descriptions)
  2. Sigma detection rules (concrete log patterns per attack)

Why this improves detection:
  MITRE alone: "Adversaries may attempt to dump credentials..."
  Sigma adds:  "Detects mimikatz.exe OR sekurlsa::logonpasswords in
                Windows Security Event logs — T1003.001 — HIGH"

When a Windows log containing "mimikatz.exe" arrives, the embedder
now finds the Sigma rule directly. The LLM gets both abstract technique
context AND concrete detection pattern — enabling higher confidence.

Coverage:
  - MITRE: ~700 techniques (all platforms)
  - Sigma windows: ~2000+ rules
  - Sigma linux:   ~300+ rules
  - Sigma network/firewall: ~200+ rules

Total ChromaDB entries: ~3000+ (was 369)

Run once — takes about 20-30 minutes.
"""

import json
import yaml
import chromadb
from pathlib import Path
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

MITRE_FILE  = "./mitre_attack.json"
SIGMA_BASE  = Path.home() / "datasets/sigma/rules"
DB_PATH     = "./threat_db"
COLLECTION  = "mitre_patterns"

# Sigma rule folders to load — covers all three log types
SIGMA_FOLDERS = [
    "windows",   # Windows Event Logs
    "linux",     # Linux auth/syslog
    "network",   # Firewall / network logs
    "category",  # Cross-platform rules
]

# Only load rules at these severity levels
SIGMA_LEVELS = {"high", "critical", "medium"}


def load_mitre_techniques(mitre_file: str) -> list[dict]:
    """Load all non-deprecated MITRE ATT&CK techniques."""
    print("Loading MITRE ATT&CK techniques...")
    with open(mitre_file) as f:
        data = json.load(f)

    techniques = [
        obj for obj in data["objects"]
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]
    print(f"  Loaded {len(techniques)} MITRE techniques")
    return techniques


def mitre_to_document(tech: dict) -> tuple[str, str, dict] | None:
    """Convert MITRE technique to (id, document_text, metadata)."""
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

    doc_text = f"[MITRE] {name} [{platforms}] ({tactic}): {desc}"
    if detection:
        doc_text += f" Detection hints: {detection}"

    uid = f"mitre_{tech_id}_{tech['id'][-8:]}"

    return uid, doc_text, {
        "id"       : tech_id,
        "technique": name,
        "tactic"   : tactic,
        "platforms": platforms,
        "source"   : "mitre",
    }


def load_sigma_rules(sigma_base: Path, folders: list[str], levels: set[str]) -> list[dict]:
    """
    Load Sigma YAML rules from specified folders.
    Converts each rule into a text document for embedding.
    """
    print(f"\nLoading Sigma rules from {sigma_base}...")
    rules = []
    skipped = 0

    for folder in folders:
        folder_path = sigma_base / folder
        if not folder_path.exists():
            print(f"  {folder}: NOT FOUND — skipping")
            continue

        yaml_files = list(folder_path.rglob("*.yml"))
        folder_rules = 0

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, encoding="utf-8", errors="ignore") as f:
                    # Sigma files can have multiple documents
                    docs = list(yaml.safe_load_all(f))

                for doc in docs:
                    if not isinstance(doc, dict):
                        continue

                    # Filter by level
                    level = doc.get("level", "").lower()
                    if level not in levels:
                        skipped += 1
                        continue

                    # Skip deprecated/unsupported
                    status = doc.get("status", "")
                    if status in ("deprecated", "unsupported"):
                        skipped += 1
                        continue

                    title       = doc.get("title", "")
                    description = doc.get("description", "")[:400]
                    tags        = doc.get("tags", [])
                    falsepositives = doc.get("falsepositives", [])

                    # Extract log source info
                    logsource = doc.get("logsource", {})
                    product   = logsource.get("product", "")
                    category  = logsource.get("category", "")
                    service   = logsource.get("service", "")

                    # Extract detection keywords/patterns
                    detection = doc.get("detection", {})
                    det_text  = _extract_detection_text(detection)

                    # Extract MITRE technique IDs from tags
                    mitre_tags = [t for t in tags if t.startswith("attack.t")]
                    technique_ids = [t.replace("attack.", "").upper() for t in mitre_tags]

                    if not title:
                        continue

                    # Build document text — concrete and specific
                    log_source_desc = " ".join(filter(None, [product, category, service]))
                    doc_text = (
                        f"[SIGMA] {title} ({log_source_desc}) — Level: {level.upper()}\n"
                        f"Description: {description}\n"
                    )
                    if det_text:
                        doc_text += f"Detection pattern: {det_text}\n"
                    if technique_ids:
                        doc_text += f"MITRE techniques: {', '.join(technique_ids)}\n"
                    if falsepositives:
                        fp_str = ", ".join(str(f) for f in falsepositives[:3])
                        doc_text += f"False positives: {fp_str}"

                    uid = f"sigma_{yaml_file.stem}_{folder_rules}"

                    rules.append({
                        "uid"     : uid,
                        "text"    : doc_text,
                        "metadata": {
                            "id"       : ", ".join(technique_ids) if technique_ids else "NONE",
                            "technique": title,
                            "tactic"   : category or product,
                            "platforms": product,
                            "source"   : "sigma",
                            "level"    : level,
                        }
                    })
                    folder_rules += 1

            except Exception:
                continue

        print(f"  {folder}: {folder_rules} rules loaded")

    print(f"  Total Sigma rules: {len(rules)} (skipped {skipped} low/info level)")
    return rules


def _extract_detection_text(detection: dict) -> str:
    """Extract human-readable detection pattern from Sigma detection block."""
    if not isinstance(detection, dict):
        return ""

    parts = []
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, dict):
            for field, pattern in value.items():
                if isinstance(pattern, list):
                    parts.append(f"{field}=({' OR '.join(str(p) for p in pattern[:5])})")
                else:
                    parts.append(f"{field}={pattern}")
        elif isinstance(value, list):
            parts.append(f"keywords=({' OR '.join(str(v) for v in value[:5])})")

    return " AND ".join(parts[:6])


def build_combined_chromadb():
    print("=" * 60)
    print("  Building ChromaDB: MITRE ATT&CK + Sigma Rules")
    print("=" * 60)

    # ── Load sources ──────────────────────────────────────────────────────────
    mitre_techniques = load_mitre_techniques(MITRE_FILE)
    sigma_rules      = load_sigma_rules(SIGMA_BASE, SIGMA_FOLDERS, SIGMA_LEVELS)

    # ── Embedder ──────────────────────────────────────────────────────────────
    print(f"\nLoading embedder (all-mpnet-base-v2)...")
    embedder = SentenceTransformer("all-mpnet-base-v2")

    # ── ChromaDB setup ────────────────────────────────────────────────────────
    print(f"Setting up ChromaDB at {DB_PATH}...")
    client = chromadb.PersistentClient(path=DB_PATH)
    try:
        client.delete_collection(COLLECTION)
        print("Deleted existing collection")
    except Exception:
        pass
    collection = client.create_collection(COLLECTION)

    # ── Embed and store MITRE techniques ──────────────────────────────────────
    print(f"\nEmbedding {len(mitre_techniques)} MITRE techniques...")
    ids = []; documents = []; metadatas = []; embeddings = []

    for tech in tqdm(mitre_techniques, desc="MITRE"):
        result = mitre_to_document(tech)
        if not result:
            continue
        uid, doc_text, meta = result
        vec = embedder.encode(doc_text).tolist()
        ids.append(uid)
        documents.append(doc_text)
        metadatas.append(meta)
        embeddings.append(vec)

    # ── Embed and store Sigma rules ───────────────────────────────────────────
    print(f"\nEmbedding {len(sigma_rules)} Sigma rules...")
    for rule in tqdm(sigma_rules, desc="Sigma"):
        vec = embedder.encode(rule["text"]).tolist()
        ids.append(rule["uid"])
        documents.append(rule["text"])
        metadatas.append(rule["metadata"])
        embeddings.append(vec)

    # ── Store in batches ──────────────────────────────────────────────────────
    print(f"\nStoring {len(ids)} total entries in ChromaDB...")
    batch_size = 100
    for i in tqdm(range(0, len(ids), batch_size), desc="Storing"):
        collection.add(
            ids        = ids[i:i+batch_size],
            documents  = documents[i:i+batch_size],
            metadatas  = metadatas[i:i+batch_size],
            embeddings = embeddings[i:i+batch_size]
        )

    print(f"\nChromaDB built successfully!")
    print(f"Total entries: {collection.count()}")

    mitre_count = sum(1 for m in metadatas if m.get("source") == "mitre")
    sigma_count = sum(1 for m in metadatas if m.get("source") == "sigma")
    print(f"  MITRE techniques : {mitre_count}")
    print(f"  Sigma rules      : {sigma_count}")

    # ── Verification tests ────────────────────────────────────────────────────
    print("\nVerification — testing retrieval across all log types...")
    tests = [
        ("Linux brute force",
         "Failed password for root from 192.168.1.5 port 22 ssh2"),
        ("Windows failed logon",
         "An account failed to log on. Account Name: administrator Source: 10.0.0.5"),
        ("Windows mimikatz",
         "A new process has been created. Process Name: mimikatz.exe CommandLine: sekurlsa::logonpasswords"),
        ("Firewall port scan",
         "Firewall: DENY TCP from 10.0.0.5:52020 to 192.168.1.10:22 scan probe"),
        ("Windows lateral movement",
         "A new service was installed. Service Name: PSExecSvc Service File: PSEXESVC.EXE"),
        ("Windows credential dump",
         "A privileged service was called. Process Name: lsass.exe"),
    ]

    for label, test_log in tests:
        vec     = embedder.encode(test_log).tolist()
        results = collection.query(query_embeddings=[vec], n_results=4)
        print(f"\n{label}:")
        for i in range(4):
            meta   = results["metadatas"][0][i]
            source = meta.get("source", "?").upper()
            level  = f"[{meta.get('level','').upper()}]" if meta.get("level") else ""
            print(f"  [{source}] {meta['technique'][:60]} {level}")

    print(f"\nDone. Run llm_watcher.py to start analysis with enhanced RAG.")


if __name__ == "__main__":
    build_combined_chromadb()
