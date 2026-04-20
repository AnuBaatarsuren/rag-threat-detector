"""
setup_wizard.py
===============
First-run setup wizard for RAG Threat Detector.
Asks questions, tests connections, writes config.yaml.

Run once:
    python setup_wizard.py
    OR
    python main.py --setup

Then start:
    python main.py
"""

import sys
import yaml
import requests
from pathlib import Path

CONFIG_FILE = "./config.yaml"


def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║          RAG Threat Detector — Setup Wizard              ║
║    LLM-based security log analysis with MITRE+Sigma      ║
╚══════════════════════════════════════════════════════════╝
""")


def ask(prompt: str, default: str = "") -> str:
    """Ask for required input. If default provided, pressing Enter uses it."""
    if default:
        val = input(f"  {prompt} [{default}]: ").strip()
        return val if val else default
    while True:
        val = input(f"  {prompt}: ").strip()
        if val:
            return val
        print("  Please enter a value.")


def ask_optional(prompt: str) -> str:
    """Ask for optional input. Pressing Enter returns empty string."""
    return input(f"  {prompt} (press Enter to skip): ").strip()


def choose(prompt: str, options: list) -> int:
    print(f"\n  {prompt}")
    for i, opt in enumerate(options, 1):
        print(f"    {i}. {opt}")
    while True:
        try:
            c = int(input("  Enter number: ").strip())
            if 1 <= c <= len(options):
                return c
        except ValueError:
            pass
        print(f"  Enter a number between 1 and {len(options)}")


def test_elasticsearch(host: str, index: str, user: str = "", pwd: str = "") -> bool:
    print(f"\n  Testing connection to {host}...")
    try:
        auth = (user, pwd) if user else None
        resp = requests.get(f"{host}/_cluster/health", auth=auth, timeout=5)
        if resp.status_code == 200:
            count_resp = requests.get(f"{host}/{index}/_count", auth=auth, timeout=5)
            count = count_resp.json().get("count", "?") if count_resp.status_code == 200 else "?"
            print(f"  ✓ Connected — {index} has {count} documents")
            return True
        print(f"  ✗ HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"  ✗ {e}")
        return False


def test_ollama(host: str, model: str) -> bool:
    print(f"\n  Testing Ollama at {host}...")
    try:
        resp = requests.get(f"{host}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            if any(model in m for m in models):
                print(f"  ✓ {model} is ready")
                return True
            print(f"  ✗ {model} not found. Available: {', '.join(models[:5]) or 'none'}")
            print(f"  Run: ollama pull {model}")
            return False
        print(f"  ✗ HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"  ✗ Ollama not running: {e}")
        return False


def pull_model(host: str, model: str):
    print(f"\n  Downloading {model} (this may take several minutes)...")
    try:
        resp = requests.post(f"{host}/api/pull", json={"name": model}, stream=True, timeout=600)
        for line in resp.iter_lines():
            if line:
                import json
                try:
                    data = json.loads(line)
                    status = data.get("status", "")
                    if "pulling" in status or "downloading" in status:
                        print(f"  .. {status}", end="\r")
                except Exception:
                    pass
        print(f"\n  ✓ {model} downloaded")
        return True
    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        return False


def test_deepseek(api_key: str) -> bool:
    print(f"\n  Testing DeepSeek API key...")
    try:
        resp = requests.post(
            "https://api.deepseek.com/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "deepseek-chat", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5},
            timeout=10,
        )
        if resp.status_code == 200:
            print(f"  ✓ API key valid")
            return True
        print(f"  ✗ HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"  ✗ {e}")
        return False


def test_claude(api_key: str, model: str) -> bool:
    print(f"\n  Testing Claude API key...")
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
            json={"model": model, "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]},
            timeout=10,
        )
        if resp.status_code == 200:
            print(f"  ✓ API key valid")
            return True
        print(f"  ✗ HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"  ✗ {e}")
        return False



def _pick_index(host: str, user: str = "", pwd: str = "") -> str:
    """
    Ask user which log shipper they use — friendly names first.
    Falls back to raw index list if they want to pick manually.
    """

    # ── Step 1: Ask by log shipper name ──────────────────────────────────────
    # Map friendly names to their ES index patterns
    SHIPPERS = [
        ("Filebeat",    "filebeat-*",    "most common — tails log files on your server"),
        ("Logstash",    "logstash-*",    "processes and transforms logs before storing"),
        ("Winlogbeat",  "winlogbeat-*",  "Windows Event Logs"),
        ("Metricbeat",  "metricbeat-*",  "system and service metrics"),
        ("Custom",      None,            "let me pick from all available indices"),
    ]

    print("\n  Which log shipper are you using?")
    for i, (name, _, desc) in enumerate(SHIPPERS, 1):
        print(f"    {i}. {name:<12} — {desc}")

    while True:
        try:
            c = int(input("  Enter number: ").strip())
            if 1 <= c <= len(SHIPPERS):
                name, pattern, _ = SHIPPERS[c - 1]
                break
        except ValueError:
            pass
        print(f"  Enter a number between 1 and {len(SHIPPERS)}")

    # If a known shipper was selected, verify it exists in ES
    if pattern:
        auth = (user, pwd) if user else None
        try:
            resp = requests.get(
                f"{host}/{pattern}/_count",
                auth=auth, timeout=5
            )
            if resp.status_code == 200:
                count = resp.json().get("count", 0)
                if count > 0:
                    print(f"  ✓ Found {count} documents in {pattern}")
                    return pattern
                else:
                    print(f"  ⚠  {pattern} exists but has 0 documents.")
                    print("     Make sure your log shipper is running and sending logs.")
                    cont = input("  Use it anyway? (y/n): ").strip().lower()
                    if cont == "y":
                        return pattern
            else:
                print(f"  ⚠  {pattern} not found in your Elasticsearch.")
        except Exception:
            pass
    # ── Step 2: Show all available indices (fallback / Custom) ───────────────
    print("\n  Detecting available indices in your Elasticsearch...")
    try:
        auth = (user, pwd) if user else None
        resp = requests.get(
            f"{host}/_cat/indices?h=index,docs.count&s=docs.count:desc",
            auth=auth, timeout=5
        )
        if resp.status_code != 200:
            raise Exception(f"HTTP {resp.status_code}")

        lines = [l.strip() for l in resp.text.strip().splitlines() if l.strip()]
        indices = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("."):
                indices.append((parts[0], parts[1]))

        if not indices:
            print("  No indices found.")
            return ask("Enter index pattern manually", "logstash-*")

        # Group by prefix
        seen = set()
        options = []
        for name, count in indices[:15]:
            parts = name.split("-")
            prefix = "-".join(parts[:-1]) + "-*" if len(parts) > 1 else name
            if prefix not in seen:
                seen.add(prefix)
                options.append((prefix, count))

        print("\n  Available indices:")
        for i, (prefix, count) in enumerate(options, 1):
            print(f"    {i}. {prefix}  ({count} docs)")
        print(f"    {len(options)+1}. Enter manually")

        while True:
            try:
                c = int(input("  Select index: ").strip())
                if 1 <= c <= len(options):
                    chosen = options[c-1][0]
                    print(f"  ✓ Selected: {chosen}")
                    return chosen
                elif c == len(options) + 1:
                    return ask("Index pattern (use * as wildcard)", "logstash-*")
            except ValueError:
                pass
            print(f"  Enter a number between 1 and {len(options)+1}")

    except Exception as e:
        print(f"  Could not detect indices: {e}")
        return ask("Index pattern (use * as wildcard)", "logstash-*")


def run_wizard():
    banner()
    config = {}

    # ══════════════════════════════════════════════════════════
    # STEP 1 — LOG SOURCE
    # ══════════════════════════════════════════════════════════
    print("─" * 58)
    print("  STEP 1 — How do you want to connect your logs?")
    print("─" * 58)

    log_source = choose(
        "Select your log source:",
        [
            "Elasticsearch / ELK stack  (I have ELK running)",
            "Log file                   (I have a log file, no log server)",
            "Skip for now               (configure later)",
        ]
    )

    if log_source == 1:
        # ELK setup
        print("")
        local = input("  Is Elasticsearch running on this machine? (y/n): ").strip().lower()
        if local == "y" or local == "":
            es_host = "http://localhost:9200"
            print(f"  ✓ Using {es_host}")
        else:
            print("""
  Common formats:
    Remote server : http://192.168.1.100:9200
    HTTPS         : https://myelk.company.com:9200
    Elastic Cloud : https://abc123.es.us-east-1.aws.elastic-cloud.com:443
""")
            es_host = ask("Elasticsearch host (include http:// and port)")

        print("""
  Authentication (leave blank if your ELK has no password):""")
        es_user = ask_optional("Username")
        es_pass = ask_optional("Password") if es_user else ""

        # Auto-detect available indices
        es_index = _pick_index(es_host, es_user, es_pass)

        ok = test_elasticsearch(es_host, es_index, es_user, es_pass)
        if not ok:
            if input("\n  Continue anyway? (y/n): ").strip().lower() != "y":
                print("  Fix your ELK connection and re-run the wizard.")
                sys.exit(1)

        config["log_source"] = "elasticsearch"
        config["elasticsearch"] = {
            "host"    : es_host,
            "index"   : es_index,
            "username": es_user,
            "password": es_pass,
        }

    elif log_source == 2:
        # File adapter setup
        print("\n  Log file configuration:")
        print("  Examples: /var/log/auth.log  /var/log/syslog  /opt/app/app.log")
        log_path = ask("Path to your log file")

        if not Path(log_path).exists():
            print(f"  ⚠  Warning: {log_path} does not exist yet.")
            print("     The system will wait for the file to appear.")

        config["log_source"] = "file"
        config["file"] = {"path": log_path}
        config["elasticsearch"] = {"host": "", "index": "", "username": "", "password": ""}

    else:
        # Skip
        config["log_source"] = "elasticsearch"
        config["elasticsearch"] = {
            "host" : "http://localhost:9200",
            "index": "logstash-*",
            "username": "", "password": "",
        }
        print("\n  Skipped. Edit config.yaml manually before starting.")

    # ══════════════════════════════════════════════════════════
    # STEP 2 — LLM PROVIDER
    # ══════════════════════════════════════════════════════════
    print("\n" + "─" * 58)
    print("  STEP 2 — Which LLM do you want to use?")
    print("─" * 58)

    llm_choice = choose(
        "Select your LLM:",
        [
            "Ollama — local, free, private (recommended)",
            "Cloud API — no GPU needed (DeepSeek / Claude)",
        ]
    )

    if llm_choice == 1:
        # Ollama — hardcode localhost, no need to ask
        ollama_host = "http://localhost:11434"
        print(f"\n  Using Ollama at {ollama_host}")
        print("  (To use a remote Ollama server, edit config.yaml after setup)")

        model_choice = choose(
            "Select a model:",
            [
                "qwen3:14b  — best accuracy, needs ~24GB VRAM (recommended)",
                "qwen3:4b   — faster, needs ~8GB VRAM",
                "Download a different model",
            ]
        )

        if model_choice == 1:
            model = "qwen3:14b"
        elif model_choice == 2:
            model = "qwen3:4b"
        else:
            print("\n  Available models to download:")
            alt_choice = choose(
                "Select a model to download:",
                [
                    "llama3.1:8b  — Meta, good general reasoning, ~8GB VRAM",
                    "mistral:7b   — Mistral, fast and capable, ~8GB VRAM",
                    "Enter model name manually",
                ]
            )
            if alt_choice == 1:
                model = "llama3.1:8b"
            elif alt_choice == 2:
                model = "mistral:7b"
            else:
                model = ask("Model name (e.g. phi3:mini)")

        ok = test_ollama(ollama_host, model)
        if not ok:
            dl = input(f"\n  Download {model} now? (y/n): ").strip().lower()
            if dl == "y":
                pull_model(ollama_host, model)
            else:
                print(f"  Run later: ollama pull {model}")

        config["llm"] = {
            "provider"    : "ollama",
            "ollama_host" : ollama_host,
            "ollama_model": model,
        }

    else:
        # Cloud API
        cloud_choice = choose(
            "Select cloud provider:",
            [
                "DeepSeek — cheapest (~$0.008/1000 analyses)",
                "Claude   — highest accuracy",
            ]
        )

        if cloud_choice == 1:
            api_key = ask("DeepSeek API key")
            test_deepseek(api_key)
            config["llm"] = {"provider": "deepseek", "deepseek_api_key": api_key}
        else:
            api_key   = ask("Claude API key")
            cl_model  = ask("Claude model", "claude-sonnet-4-6")
            test_claude(api_key, cl_model)
            config["llm"] = {
                "provider"      : "claude",
                "claude_api_key": api_key,
                "claude_model"  : cl_model,
            }

    # ══════════════════════════════════════════════════════════
    # STEP 3 — LOG TYPE
    # ══════════════════════════════════════════════════════════
    print("\n" + "─" * 58)
    print("  STEP 3 — What type of logs are you analyzing?")
    print("─" * 58)
    print("  This sets the confidence threshold automatically.")

    log_type_choice = choose(
        "Select log type:",
        [
            "Linux auth / syslog  (e.g. /var/log/auth.log, SSH, sudo)",
            "Windows Event Logs   (Event IDs 4624, 4625, 4688, etc.)",
            "Mixed / not sure     (uses conservative threshold)",
        ]
    )

    log_type_map = {1: "linux", 2: "windows", 3: "linux"}
    log_type = log_type_map[log_type_choice]
    config["log_type"] = log_type

    # ── Baseline — always auto, last 2 hours, no user input needed ──────────
    config["baseline"] = {"mode": "auto", "hours": 2, "before": None}

    # ── Analysis settings (hardcoded — not exposed to user) ──────────────────
    # 10-minute session window proven optimal in experiments
    # 3-second poll interval is always appropriate
    config["analysis"] = {
        "session_window_minutes": 10,
        "poll_interval_seconds" : 3,
        "top_k_chunks"          : 4,
    }

    # ══════════════════════════════════════════════════════════
    # FIXED SETTINGS
    # ══════════════════════════════════════════════════════════
    config["rag"] = {
        "db_path"   : "./threat_db",
        "collection": "mitre_patterns",
        "embed_model": "all-mpnet-base-v2",
    }

    config["output"] = {
        "analyzed_index": "rag-analyzed",
        "log_file"      : "./logs/watcher.log",
    }

    # ══════════════════════════════════════════════════════════
    # WRITE CONFIG
    # ══════════════════════════════════════════════════════════
    print("\n" + "─" * 58)
    print("  Saving configuration...")
    print("─" * 58)

    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"\n  ✓ Config saved to {CONFIG_FILE}")
    print(f"""
  Setup complete. Next steps:

  1. Build the knowledge base (first time only):
         python main.py --build-rag

  2. Start live analysis:
         python main.py

  3. Evaluate against a labeled dataset:
         python main.py --evaluate dataset/dataset_fresh_test.csv
""")


if __name__ == "__main__":
    run_wizard()
