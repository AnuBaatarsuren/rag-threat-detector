# RAG Threat Detector

A security log analysis system that uses large language models (LLMs) and Retrieval-Augmented Generation (RAG) to detect potential threats. This project was developed as part of my undergraduate thesis research.

The main idea is to move beyond fixed detection rules. Instead of matching logs against predefined patterns, the system analyzes logs as behavioral activity, retrieves relevant MITRE ATT&CK techniques and Sigma rules, and uses an LLM to reason about whether the activity may be malicious.

---

## Why I built this

Most open-source threat detection tools rely on rule-based approaches. These work well for known attacks, but they often struggle to detect new or unknown behaviors.

This project explores whether an LLM can identify threats by understanding behavioral patterns in logs, rather than relying only on signatures. The results suggest that this approach can be effective, especially when combined with additional context such as MITRE ATT&CK and Sigma rules.

---

## Results

Tested on multiple log types using labeled datasets.

**Linux auth logs (78 logs, 4 attack categories):**

| Setup | Precision | Recall | F1 |
|-------|-----------|--------|----|
| No RAG, small model (4B) | 100% | 22% | 36% |
| RAG + small model (4B) | 95% | 77% | 85% |
| RAG + large model (14B) + session grouping | 66% | 100% | 79% |
| RAG + large model + session + baseline model | **100%** | **84.8%** | **91.8%** |

**Windows Event Logs (116 logs, 7 attack categories):**

| Setup | Precision | Recall | F1 |
|-------|-----------|--------|----|
| MITRE ATT&CK only | 100% | 19.6% | 32.8% |
| MITRE + Sigma rules combined | **73.6%** | **69.6%** | **71.6%** |

Combining Sigma rules with MITRE ATT&CK significantly improved detection performance on Windows logs.

---

## How it works

1. Reads logs from ELK or directly from a log file
2. Groups logs by source IP into short time windows (behavioral sessions)
3. Retrieves relevant MITRE ATT&CK techniques and Sigma rules from ChromaDB (3112 entries)
4. Builds a simple baseline model to understand what "normal" looks like per IP
5. Sends the context to an LLM and asks it to evaluate whether the activity is suspicious
6. Outputs the result with attack type, MITRE ID, confidence level, and reasoning

---

## Key ideas explored

- **Session-based analysis** — logs are analyzed as grouped behavioral activity, not individual lines
- **Baseline behavior modeling** — helps the LLM distinguish real threats from normal admin activity
- **RAG with MITRE + Sigma** — provides structured security knowledge to the model at inference time
- **LLM-based reasoning** — detection is based on context and behavior, not fixed rules
- **Pluggable adapter layer** — works with ELK, flat log files, and can be extended to other backends

---

## Getting started

### Install

```bash
git clone https://github.com/AnuBaatarsuren/rag-threat-detector
cd rag-threat-detector
pip install -r requirements.txt
```

### Download MITRE ATT&CK data

```bash
wget -O mitre_attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

### Download Sigma rules

```bash
git clone https://github.com/SigmaHQ/sigma ~/datasets/sigma
```

### Build the knowledge base (run once, takes ~20 min)

```bash
python main.py --build-rag
```

### Configure

```bash
python main.py --setup
```

Asks three questions: where your logs are, which LLM to use, what type of logs you have. Writes `config.yaml`. No need to edit Python files after this.

### Run

**With ELK:**
```bash
python main.py
```

**With a log file (no ELK needed):**
```bash
python file_adapter.py --file /var/log/auth.log
```

Open `output/report.html` in your browser to see results. Auto-refreshes every 10 seconds.

---

## LLM options

| Option | Cost | Privacy | Notes |
|--------|------|---------|-------|
| Ollama + Qwen3:14b | Free | Full — local | Recommended, needs ~24GB VRAM |
| Ollama + Qwen3:4b | Free | Full — local | Faster, needs ~8GB VRAM |
| DeepSeek API | ~$0.008/1000 | Cloud | Good option without GPU |
| Claude API | Paid | Cloud | Most accurate |

---

## Supported log types

| Type | Tested dataset |
|------|---------------|
| Linux auth / syslog | Linux-APT-2024 |
| Windows Event Logs | OTRF Security Datasets |
| Firewall logs | Firat University dataset |

---

## Commands

```bash
# First-time setup
python main.py --setup

# Build knowledge base
python main.py --build-rag

# Start live analysis (ELK mode)
python main.py

# Analyze a log file directly
python file_adapter.py --file /var/log/auth.log

# Analyze existing file then stop
python file_adapter.py --file /var/log/auth.log --once

# Evaluate against labeled dataset
python main.py --evaluate dataset/dataset_fresh_test.csv

# Optional web dashboard
python app.py   # open http://localhost:5000
```

---

## Kibana dashboard

If you use ELK, import the pre-built dashboard:

1. Kibana → Stack Management → Saved Objects → Import
2. Select `kibana_dashboard/dashboard.ndjson`

---

## Hardware requirements

| | Minimum | Recommended |
|-|---------|-------------|
| RAM | 16GB | 32GB |
| GPU VRAM | 8GB (4B model) | 24GB (14B model) |
| Storage | 20GB | 50GB |
| OS | Ubuntu 20.04+ | Ubuntu 22.04+ |

No GPU? Use DeepSeek or Claude API — works on any machine with internet.

---

## Project structure

```
rag-threat-detector/
├── main.py                        # Entry point
├── setup_wizard.py                # First-run configuration wizard
├── llm_watcher.py                 # ELK analysis pipeline
├── file_adapter.py                # File-based pipeline (no ELK needed)
├── baseline.py                    # Per-IP normality model
├── app.py                         # Optional Flask web UI
├── build_chromadb_with_sigma.py   # Builds MITRE + Sigma knowledge base
├── build_chromadb.py              # Builds MITRE-only knowledge base
├── evaluate.py                    # Evaluation script
├── inject_fresh.py                # Test dataset injector
├── convert_otrf.py                # OTRF dataset converter
├── convert_firewall.py            # Firewall dataset converter
├── requirements.txt
├── dataset/                       # Labeled test datasets
└── kibana_dashboard/              # Pre-built Kibana dashboard
```

---

## Limitations

This is a research prototype, not a production system:

- **Slow** — ~5-8 seconds per log with 14B model
- **Not scalable** — handles ~2000 logs/hour before falling behind
- **Firewall logs** — detection works but confidence calibration is inconsistent
- **Baseline sensitivity** — wrong "clean" period corrupts the baseline
- **LLM hallucination** — occasional incorrect reasoning or MITRE ID labeling

---

## Citation

```
Baatarsuren, A. (2025). AI Log Analyzer for Threat Detection. Undergraduate thesis.
```

---

*Built as part of my thesis research. Feel free to open an issue or reach out if you have questions.*
