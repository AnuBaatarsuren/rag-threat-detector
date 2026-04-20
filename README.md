# RAG Threat Detector

**LLM-based security log analysis using Retrieval-Augmented Generation (RAG)**

Detects threats that rule-based systems miss by reasoning over behavioral patterns using a combined MITRE ATT&CK + Sigma rules knowledge base with Qwen3, DeepSeek, or Claude.

---

## What it does

- Polls your log source continuously for new security logs
- Groups logs by source IP into behavioral sessions (±10 minute windows)
- Retrieves relevant MITRE ATT&CK techniques and Sigma detection rules via RAG (3112 entries)
- Compares session behavior against a learned per-IP baseline normality model
- Asks an LLM to reason about whether the activity is malicious
- Writes enriched verdicts with attack type, MITRE ID, confidence level, and reasoning
- Generates an HTML report viewable in any browser

## Why it's different from rule-based systems

Rule-based systems detect threats by matching known signatures. This system detects threats by **reasoning over behavioral patterns** — catching slow brute force, unknown C2 infrastructure, and multi-step attack chains that produce no matching rule.

**Proven results on Linux auth logs:**

| Configuration | Precision | Recall | F1 |
|--------------|-----------|--------|----|
| No RAG (4B model) | 100% | 22% | 36% |
| RAG + 4B model | 95% | 77% | 85% |
| RAG + 14B + session grouping | 66% | 100% | 79% |
| RAG + 14B + session + baseline | **100%** | **84%** | **91.8%** |

**Windows Event Log results (MITRE + Sigma):**

| Configuration | Precision | Recall | F1 |
|--------------|-----------|--------|----|
| MITRE only | 100% | 19.6% | 32.8% |
| MITRE + Sigma rules | **73.6%** | **69.6%** | **71.6%** |

---

## Quick start

### 1. Clone and install

```bash
git clone https://github.com/AnuBaatarsuren/rag-threat-detector
cd rag-threat-detector
pip install -r requirements.txt
```

### 2. Download MITRE ATT&CK data

Download the MITRE ATT&CK JSON from https://attack.mitre.org/resources/attack-data-and-tools/
Save as `mitre_attack.json` in the project root.

### 3. Download Sigma rules

```bash
git clone https://github.com/SigmaHQ/sigma ~/datasets/sigma
```

### 4. Build the knowledge base

```bash
python main.py --build-rag
```

This takes 20-30 minutes. Builds ChromaDB with 3112 entries (700 MITRE techniques + 2400+ Sigma rules).

### 5. Run setup wizard

```bash
python main.py --setup
```

The wizard asks:
- Where are your logs? (ELK or log file)
- Which LLM? (Ollama local or cloud API)
- What type of logs? (Linux / Windows)

### 6. Start analysis

**With ELK:**
```bash
python main.py
```

**With a log file (no ELK needed):**
```bash
python file_adapter.py --file /var/log/auth.log
```

Open `output/report.html` in your browser to view results.

---

## Supported log types

| Log type | Session grouping | Tested dataset |
|----------|-----------------|----------------|
| Linux auth / syslog | src_ip | Linux-APT-2024 |
| Windows Event Logs | src_ip | OTRF Security Datasets |
| Firewall logs | src_ip | Firat University dataset |

---

## Supported LLM providers

| Provider | Type | Notes |
|----------|------|-------|
| Ollama + Qwen3:14b | Local | Recommended — free, private, needs GPU |
| Ollama + Qwen3:4b | Local | Faster, lower accuracy, needs 8GB VRAM |
| DeepSeek API | Cloud | Cheapest cloud option |
| Claude API | Cloud | Highest accuracy |

---

## Project structure

```
rag-threat-detector/
├── main.py                         # Entry point — setup, build-rag, evaluate, run
├── setup_wizard.py                 # First-run configuration wizard
├── llm_watcher.py                  # Core ELK pipeline (RAG + LLM + baseline)
├── file_adapter.py                 # File-based pipeline (no ELK required)
├── baseline.py                     # Per-IP behavioral normality model
├── app.py                          # Flask web UI (localhost:5000)
├── build_chromadb.py               # Build MITRE-only knowledge base
├── build_chromadb_with_sigma.py    # Build MITRE + Sigma knowledge base
├── evaluate.py                     # Evaluate against labeled datasets
├── inject_fresh.py                 # Inject test datasets into ELK
├── convert_otrf.py                 # Convert OTRF Windows datasets
├── convert_firewall.py             # Convert firewall datasets
├── requirements.txt
├── README.md
├── dataset/
│   ├── dataset_fresh_test.csv      # Linux auth log test dataset (78 logs)
│   ├── dataset_windows_real.csv    # Windows Event Log dataset (116 logs)
│   └── dataset_firewall_real.csv   # Firewall log dataset (90 logs)
└── kibana_dashboard/
    └── dashboard.ndjson            # Pre-built Kibana dashboard (import ready)
```

---

## Commands reference

```bash
# First-time setup
python main.py --setup

# Build MITRE + Sigma knowledge base
python main.py --build-rag

# Start live analysis (ELK mode)
python main.py

# Analyze a log file (no ELK needed)
python file_adapter.py --file /var/log/auth.log

# Analyze existing logs then stop
python file_adapter.py --file /var/log/auth.log --once

# Evaluate against labeled dataset
python main.py --evaluate dataset/dataset_fresh_test.csv
python main.py --evaluate dataset/dataset_windows_real.csv

# Web UI dashboard
python app.py
# then open http://localhost:5000
```

---

## Kibana Dashboard

Import the pre-built dashboard into your Kibana:

1. Open Kibana → Stack Management → Saved Objects
2. Click Import
3. Select `kibana_dashboard/dashboard.ndjson`
4. Click Import

---

## Hardware requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 16GB | 32GB |
| GPU VRAM | 8GB (for 7B model) | 24GB (for 14B model) |
| Storage | 20GB | 50GB |
| OS | Ubuntu 20.04+ | Ubuntu 22.04+ |

**No GPU?** Use DeepSeek or Claude API instead of Ollama — any machine with 8GB RAM and internet works.

---

## Architecture

```
Log sources (ELK / Log files / Future: Loki, Graylog)
        ↓
Adapter layer (elasticsearch_adapter / file_adapter)
        ↓
Session grouper (±10 min per src_ip)
Baseline model  (per-IP normality)
RAG retriever   (MITRE + Sigma → ChromaDB)
        ↓
LLM analysis (Qwen3:14b / DeepSeek / Claude)
        ↓
Output (Kibana dashboard / HTML report / Flask UI)
```

The adapter layer is pluggable — adding Loki, Graylog, or Splunk support requires implementing three methods: `poll()`, `get_session()`, `mark_analyzed()`.

---

## Research contributions

1. **Session-based behavioral grouping** — grouping logs by IP into time windows enables detection of multi-step attack patterns invisible to per-event analysis
2. **Baseline normality model** — per-IP behavioral statistics reduce false positives by giving the LLM context about what is normal for each source
3. **Combined MITRE + Sigma RAG** — augmenting abstract MITRE technique descriptions with concrete Sigma detection patterns improves LLM confidence calibration (Windows F1: 32% → 71%)
4. **Cross-log-type generalization** — same pipeline analyzes Linux, Windows, and firewall logs without retraining

---

## Limitations

- 5-8 seconds per log with 14B model — not true real-time streaming
- Firewall log confidence calibration is weak (MITRE/Sigma biased toward host-level events)
- Baseline quality depends on clean learning period — corrupted if attack traffic present during setup
- Scale ceiling: ~2000 logs/hour before falling behind

---

## Citation

If you use this system in your research, please cite:

```
Baatarsuren, A., "RAG-Augmented LLM Analysis for Security Log Threat Detection", 2025
```
