"""
file_adapter.py — File-based log analysis (no ELK required)
============================================================
Reads a log file continuously (like tail -f), analyzes each new line
with the RAG+LLM pipeline, and writes results to:
  - output/results.json   (machine-readable, all verdicts)
  - output/report.html    (human-readable, threats only, auto-refreshes)

Usage:
    python file_adapter.py --file /var/log/auth.log
    python file_adapter.py --file /var/log/auth.log --once

No Elasticsearch, Kibana, Logstash or Filebeat needed.
"""

import time
import json
import re
import argparse
import requests
import chromadb
from pathlib import Path
from datetime import datetime, timezone
from sentence_transformers import SentenceTransformer


OUTPUT_DIR   = Path("./output")
RESULTS_FILE = OUTPUT_DIR / "results.json"
REPORT_FILE  = OUTPUT_DIR / "report.html"
IP_PATTERN   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def load_config() -> dict:
    import yaml
    cfg_path = Path("./config.yaml")
    if not cfg_path.exists():
        print("[!] Config not found. Run: python main.py --setup")
        raise SystemExit(1)
    with open(cfg_path) as f:
        return yaml.safe_load(f)


def extract_ip(line: str) -> str:
    for m in IP_PATTERN.findall(line):
        if not m.startswith("127.") and not m.startswith("0."):
            return m
    return "unknown"


def extract_timestamp(line: str) -> str:
    m = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if m:
        return m.group(1)
    m = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
    if m:
        return m.group(1)
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SessionBuffer:
    """Rolling per-IP session buffer — replaces Elasticsearch session queries."""
    def __init__(self, window_minutes: int = 10):
        self.window = window_minutes
        self.buffer : list[dict] = []

    def add(self, line: str, ip: str):
        self.buffer.append({"line": line, "ip": ip, "time": time.time()})
        cutoff = time.time() - (self.window * 60)
        self.buffer = [e for e in self.buffer if e["time"] >= cutoff]

    def get_session(self, ip: str) -> tuple[str, dict]:
        messages = [e["line"] for e in self.buffer if e["ip"] == ip]
        if not messages:
            return f"No recent activity for {ip}.", {}

        total   = len(messages)
        failed  = sum(1 for m in messages if any(k in m.lower() for k in ["failed","invalid","denied","refused"]))
        success = sum(1 for m in messages if any(k in m.lower() for k in ["accepted","success","opened"]))
        sudo    = sum(1 for m in messages if "sudo" in m.lower())
        wget    = sum(1 for m in messages if any(k in m.lower() for k in ["wget","curl","download"]))
        ratio   = round(failed / total * 100, 1) if total > 0 else 0

        stats   = {"failed": failed, "success": success, "sudo": sudo, "wget": wget}
        summary  = f"=== Session for {ip} (last {self.window} min) ===\n"
        summary += f"Total={total} Failed={failed}({ratio}%) Success={success} Sudo={sudo} Downloads={wget}\n"
        summary += "Recent events:\n"
        for m in messages[-8:]:
            summary += f"  > {m[:120]}\n"
        return summary, stats


class FileBaseline:
    """Learns normal behavior from first N lines of log file."""
    def __init__(self):
        self.baseline : dict[str, dict] = {}
        self.built = False

    def build(self, filepath: Path, lines: int = 500):
        print(f"  Learning baseline from first {lines} lines...")
        counts: dict[str, dict] = {}
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= lines:
                        break
                    ip = extract_ip(line)
                    if ip == "unknown":
                        continue
                    if ip not in counts:
                        counts[ip] = {"failed": 0, "success": 0, "sudo": 0, "wget": 0}
                    counts[ip]["failed"]  += 1 if any(k in line.lower() for k in ["failed","invalid","denied"]) else 0
                    counts[ip]["success"] += 1 if any(k in line.lower() for k in ["accepted","success"]) else 0
                    counts[ip]["sudo"]    += 1 if "sudo" in line.lower() else 0
                    counts[ip]["wget"]    += 1 if any(k in line.lower() for k in ["wget","curl","download"]) else 0

            for ip, c in counts.items():
                self.baseline[ip] = {k: round(v / 1, 2) for k, v in c.items()}
            self.built = True
            print(f"  ✓ Baseline built for {len(self.baseline)} IPs")
        except Exception as e:
            print(f"  ⚠  Baseline failed: {e}")

    def get_context(self, ip: str, stats: dict) -> str:
        if not self.built:
            return ""
        if ip not in self.baseline:
            if any(stats.get(k, 0) > 0 for k in ["failed","success"]):
                return f"Baseline: {ip} is a previously unseen source — treat with elevated suspicion."
            return ""
        b = self.baseline[ip]
        lines = [f"Baseline context for {ip}:"]; anomalies = []
        for label, key in [("Failed logins","failed"),("Successful","success"),("Sudo","sudo"),("Downloads","wget")]:
            cur = stats.get(key, 0); base_val = b.get(key, 0)
            if base_val == 0 and cur > 0:
                anomalies.append(f"{label}: {cur} (never seen before) ANOMALOUS")
                lines.append(f"  {label}: {cur} — FIRST TIME SEEN ⚠")
            elif base_val > 0 and cur > 0:
                ratio = round(cur / base_val, 1)
                tag = f" ⚠ ({ratio}x above baseline)" if ratio >= 3 else " (normal)"
                lines.append(f"  {label}: current={cur}, baseline={base_val}{tag}")
                if ratio >= 3:
                    anomalies.append(f"{label}: {ratio}x above baseline ANOMALOUS")
            else:
                lines.append(f"  {label}: current={cur}, baseline={base_val} (normal)")
        if anomalies:
            lines.append(f"\nANOMALIES: {'; '.join(anomalies)}")
        return "\n".join(lines)


def call_llm(cfg: dict, log_line: str, mitre_ctx: str, session_ctx: str, baseline_ctx: str) -> tuple:
    baseline_section = f"\nBaseline deviation:\n{baseline_ctx}\n" if baseline_ctx else ""
    prompt = f"""You are a senior security analyst specializing in threat detection.

MITRE ATT&CK and Sigma detection rules most relevant to this log:
{mitre_ctx}

Behavioral session context:
{session_ctx}
{baseline_section}
Log entry under analysis:
{log_line}

Reply in this exact format:
THREAT_DETECTED: YES or NO
ATTACK_TYPE: technique name or NONE
MITRE_ID: MITRE ID or NONE
CONFIDENCE: HIGH or MEDIUM or LOW
REASONING: Two to three sentences explaining your conclusion."""

    llm = cfg["llm"]
    try:
        if llm["provider"] == "ollama":
            resp = requests.post(
                f"{llm['ollama_host']}/api/chat",
                json={"model": llm["ollama_model"],
                      "messages": [{"role":"user","content":prompt},{"role":"assistant","content":"THREAT_DETECTED:"}],
                      "stream": False, "think": False,
                      "options": {"temperature": 0, "num_predict": 300}},
                timeout=180)
            raw = "THREAT_DETECTED:" + resp.json().get("message",{}).get("content","").strip()
        elif llm["provider"] == "deepseek":
            resp = requests.post("https://api.deepseek.com/chat/completions",
                headers={"Authorization":f"Bearer {llm['deepseek_api_key']}","Content-Type":"application/json"},
                json={"model":"deepseek-chat","messages":[{"role":"user","content":prompt}],"temperature":0,"max_tokens":300},
                timeout=60)
            raw = resp.json()["choices"][0]["message"]["content"].strip()
            if not raw.startswith("THREAT_DETECTED:"): raw = "THREAT_DETECTED:" + raw
        elif llm["provider"] == "claude":
            resp = requests.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key":llm["claude_api_key"],"anthropic-version":"2023-06-01","Content-Type":"application/json"},
                json={"model":llm.get("claude_model","claude-sonnet-4-6"),"max_tokens":300,
                      "messages":[{"role":"user","content":prompt}]},
                timeout=60)
            raw = resp.json()["content"][0]["text"].strip()
            if not raw.startswith("THREAT_DETECTED:"): raw = "THREAT_DETECTED:" + raw
        else:
            return "ERROR","ERROR","NONE","LOW",f"Unknown provider"

        verdict="NO"; attack="NONE"; mitre_id="NONE"; confidence="LOW"; reasoning="NONE"
        for line in raw.splitlines():
            l = line.strip()
            if l.startswith("THREAT_DETECTED:"): verdict = "YES" if "YES" in l.upper() else "NO"
            elif l.startswith("ATTACK_TYPE:"): attack = l.split(":",1)[1].strip()
            elif l.startswith("MITRE_ID:"): mitre_id = l.split(":",1)[1].strip()
            elif l.startswith("CONFIDENCE:"): confidence = l.split(":",1)[1].strip().upper()
            elif l.startswith("REASONING:"): reasoning = l.split(":",1)[1].strip()
        return verdict, attack, mitre_id, confidence, reasoning
    except Exception as e:
        return "ERROR","ERROR","NONE","LOW",str(e)


class ResultsWriter:
    def __init__(self):
        OUTPUT_DIR.mkdir(exist_ok=True)
        self.results: list[dict] = []
        if RESULTS_FILE.exists():
            try:
                with open(RESULTS_FILE) as f:
                    self.results = json.load(f)
            except Exception:
                self.results = []

    def add(self, result: dict):
        self.results.append(result)
        self._save_json()
        self._save_html()

    def _save_json(self):
        with open(RESULTS_FILE, "w") as f:
            json.dump(self.results, f, indent=2)

    def _save_html(self):
        threats = [r for r in self.results if r["verdict"] == "YES"]
        total   = len(self.results)
        high    = sum(1 for r in threats if r["confidence"] == "HIGH")
        medium  = sum(1 for r in threats if r["confidence"] == "MEDIUM")
        rows = ""
        for r in reversed(threats):
            clr = "#c0392b" if r["confidence"] == "HIGH" else "#e67e22"
            rows += f"""<tr>
              <td>{r['timestamp']}</td><td>{r['src_ip']}</td>
              <td><span style="color:{clr};font-weight:600">{r['confidence']}</span></td>
              <td>{r['attack_type']}</td><td>{r['mitre_id']}</td>
              <td style="font-size:12px;color:#555">{r['reasoning'][:120]}...</td>
            </tr>"""
        html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta http-equiv="refresh" content="10">
<title>RAG Threat Detector</title>
<style>
body{{font-family:-apple-system,sans-serif;margin:0;background:#f5f5f5;color:#333}}
.hdr{{background:#1a1a2e;color:white;padding:24px 32px}}
.hdr h1{{margin:0;font-size:22px;font-weight:500}}
.hdr p{{margin:4px 0 0;opacity:.6;font-size:13px}}
.stats{{display:flex;gap:16px;padding:20px 32px}}
.stat{{background:white;border-radius:8px;padding:16px 24px;flex:1;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.stat .num{{font-size:32px;font-weight:600}}
.stat .lbl{{font-size:12px;color:#888;margin-top:4px}}
.red .num{{color:#c0392b}}.amber .num{{color:#e67e22}}
.content{{padding:0 32px 32px}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#f8f8f8;padding:12px 16px;text-align:left;font-size:12px;color:#888;font-weight:500;border-bottom:1px solid #eee}}
td{{padding:12px 16px;font-size:13px;border-bottom:1px solid #f0f0f0}}
tr:last-child td{{border-bottom:none}}
.empty{{text-align:center;padding:48px;color:#aaa;font-size:14px}}
.foot{{font-size:11px;color:#aaa;text-align:right;padding:8px 32px}}
</style></head><body>
<div class="hdr"><h1>RAG Threat Detector</h1>
<p>Auto-refreshes every 10 seconds &mdash; {total} logs analyzed</p></div>
<div class="stats">
<div class="stat"><div class="num">{total}</div><div class="lbl">Logs analyzed</div></div>
<div class="stat red"><div class="num">{high}</div><div class="lbl">HIGH threats</div></div>
<div class="stat amber"><div class="num">{medium}</div><div class="lbl">MEDIUM threats</div></div>
<div class="stat"><div class="num">{total-len(threats)}</div><div class="lbl">Clean</div></div>
</div>
<div class="content"><table>
<thead><tr><th>Time</th><th>Source IP</th><th>Confidence</th>
<th>Attack type</th><th>MITRE ID</th><th>Reasoning</th></tr></thead>
<tbody>{"<tr><td colspan='6' class='empty'>No threats detected yet</td></tr>" if not threats else rows}</tbody>
</table></div>
<div class="foot">Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</body></html>"""
        with open(REPORT_FILE, "w") as f:
            f.write(html)


def run(filepath: Path, once: bool = False):
    cfg        = load_config()
    rag_cfg    = cfg["rag"]
    embedder   = SentenceTransformer(rag_cfg["embed_model"])
    chroma     = chromadb.PersistentClient(path=rag_cfg["db_path"])
    collection = chroma.get_collection(rag_cfg["collection"])
    window     = cfg["analysis"]["session_window_minutes"]
    session    = SessionBuffer(window_minutes=window)
    base       = FileBaseline()
    base.build(filepath, lines=500)
    writer     = ResultsWriter()
    log_type   = cfg.get("log_type", "linux")
    thresholds = {"linux": "HIGH", "windows": "MEDIUM", "firewall": "MEDIUM"}
    min_conf   = thresholds.get(log_type, "HIGH")

    print(f"""
{'='*58}
  RAG Threat Detector — File Mode
  File    : {filepath}
  LLM     : {cfg['llm']['provider']} / {cfg['llm'].get('ollama_model','')}
  RAG     : {collection.count()} entries
  Baseline: {len(base.baseline)} IPs profiled
  Report  : {REPORT_FILE.resolve()}
  Open the report file in your browser to view results
{'='*58}
""")

    analyzed = threats = 0

    def process_line(line: str):
        nonlocal analyzed, threats
        line = line.strip()
        if not line:
            return
        analyzed += 1
        src_ip = extract_ip(line)
        ts     = extract_timestamp(line)
        session.add(line, src_ip)
        session_ctx, session_stats = session.get_session(src_ip)
        vec       = embedder.encode(line).tolist()
        rag_res   = collection.query(query_embeddings=[vec], n_results=cfg["analysis"]["top_k_chunks"])
        mitre_ctx = "\n".join(
            f"[{rag_res['metadatas'][0][i]['id']}] {rag_res['metadatas'][0][i]['technique']}: {rag_res['documents'][0][i][:150]}"
            for i in range(len(rag_res["ids"][0])))
        baseline_ctx = base.get_context(src_ip, session_stats)
        verdict, attack, mitre_id, confidence, reasoning = call_llm(cfg, line, mitre_ctx, session_ctx, baseline_ctx)
        writer.add({"timestamp":ts,"src_ip":src_ip,"message":line,"verdict":verdict,
                    "attack_type":attack,"mitre_id":mitre_id,"confidence":confidence,
                    "reasoning":reasoning,"analyzed_at":datetime.now(timezone.utc).isoformat()})
        if verdict == "YES":
            threats += 1
            print(f"  ⚠  [{confidence}] {attack} | {src_ip}")
            print(f"  ↳ {reasoning[:100]}")
        else:
            print(f"\r  ✓ [{analyzed}] analyzed — {threats} threats found", end="", flush=True)

    if once:
        print("  Analyzing existing logs...")
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                process_line(line)
        print(f"\n\n  Done — {analyzed} logs analyzed, {threats} threats found")
        print(f"  Open in browser: {REPORT_FILE.resolve()}")
        return

    print("  Watching for new entries... (Ctrl+C to stop)\n")
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                process_line(line)
            else:
                time.sleep(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAG Threat Detector — File Mode")
    parser.add_argument("--file", required=True, help="Path to log file to analyze")
    parser.add_argument("--once", action="store_true", help="Analyze existing logs then stop")
    args = parser.parse_args()
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"[!] File not found: {args.file}")
        raise SystemExit(1)
    run(filepath, once=args.once)
