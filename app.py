"""
app.py — Flask Web UI for RAG Threat Detector
==============================================
Simple dashboard showing analysis results from both ELK and file adapter.
Runs on http://localhost:5000

Usage:
    pip install flask
    python app.py
"""

from flask import Flask, render_template_string, jsonify
from pathlib import Path
from datetime import datetime
import json
import yaml

app = Flask(__name__)

CONFIG_FILE  = "./config.yaml"
RESULTS_FILE = "./output/results.json"


def load_config() -> dict:
    try:
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


def load_results() -> list:
    """Load results from file adapter output."""
    try:
        with open(RESULTS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def load_elk_results(cfg: dict) -> list:
    """Load results from Elasticsearch (ELK mode)."""
    try:
        from elasticsearch import Elasticsearch
        es_cfg = cfg.get("elasticsearch", {})
        host   = es_cfg.get("host", "http://localhost:9200")
        user   = es_cfg.get("username", "")
        pwd    = es_cfg.get("password", "")

        if user and pwd:
            es = Elasticsearch(host, basic_auth=(user, pwd))
        else:
            es = Elasticsearch(host)

        out_index = cfg.get("output", {}).get("analyzed_index", "rag-analyzed")
        res = es.search(index=out_index, body={
            "size": 200,
            "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "src_ip", "message", "llm_verdict",
                       "attack_type", "mitre_id", "confidence", "llm_reasoning"],
        })

        results = []
        for hit in res["hits"]["hits"]:
            src = hit["_source"]
            results.append({
                "timestamp"  : src.get("@timestamp", ""),
                "src_ip"     : src.get("src_ip", ""),
                "message"    : src.get("message", ""),
                "verdict"    : src.get("llm_verdict", "NO"),
                "attack_type": src.get("attack_type", "NONE"),
                "mitre_id"   : src.get("mitre_id", "NONE"),
                "confidence" : src.get("confidence", "LOW"),
                "reasoning"  : src.get("llm_reasoning", ""),
            })
        return results
    except Exception:
        return []


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RAG Threat Detector</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #0d0f14;
    --bg2:     #13161d;
    --bg3:     #1a1e28;
    --border:  #252a38;
    --text:    #e2e8f0;
    --muted:   #6b7280;
    --red:     #ef4444;
    --amber:   #f59e0b;
    --green:   #10b981;
    --blue:    #3b82f6;
    --accent:  #6366f1;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 32px;
    border-bottom: 1px solid var(--border);
    background: var(--bg2);
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .logo-icon {
    width: 36px; height: 36px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }
  .logo h1 {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: -0.02em;
  }
  .logo p {
    font-size: 11px;
    color: var(--muted);
    margin-top: 1px;
    font-family: 'DM Mono', monospace;
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; }
    50%      { opacity: 0.4; }
  }
  .status-label {
    font-size: 12px;
    color: var(--muted);
    font-family: 'DM Mono', monospace;
  }
  .refresh-btn {
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 12px;
    cursor: pointer;
    font-family: 'DM Mono', monospace;
    transition: border-color 0.2s;
  }
  .refresh-btn:hover { border-color: var(--accent); }

  /* ── Stats ── */
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    padding: 24px 32px;
  }
  .stat {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
  }
  .stat::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }
  .stat.total::before  { background: var(--blue); }
  .stat.high::before   { background: var(--red); }
  .stat.medium::before { background: var(--amber); }
  .stat.clean::before  { background: var(--green); }
  .stat .num {
    font-size: 36px;
    font-weight: 700;
    letter-spacing: -0.03em;
    line-height: 1;
    margin-bottom: 6px;
  }
  .stat.high .num   { color: var(--red); }
  .stat.medium .num { color: var(--amber); }
  .stat.clean .num  { color: var(--green); }
  .stat .lbl {
    font-size: 11px;
    color: var(--muted);
    font-family: 'DM Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  /* ── Table section ── */
  .section {
    padding: 0 32px 32px;
  }
  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
  }
  .section-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-family: 'DM Mono', monospace;
  }
  .filter-tabs {
    display: flex;
    gap: 8px;
  }
  .tab {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-family: 'DM Mono', monospace;
    cursor: pointer;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted);
    transition: all 0.2s;
  }
  .tab.active { background: var(--accent); border-color: var(--accent); color: white; }
  .tab:hover:not(.active) { border-color: var(--accent); color: var(--text); }

  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }
  thead th {
    padding: 12px 16px;
    text-align: left;
    font-size: 10px;
    color: var(--muted);
    font-family: 'DM Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-bottom: 1px solid var(--border);
    font-weight: 500;
    background: var(--bg3);
  }
  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: var(--bg3); }
  td {
    padding: 12px 16px;
    font-size: 13px;
    vertical-align: top;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-family: 'DM Mono', monospace;
    font-weight: 500;
    letter-spacing: 0.04em;
  }
  .badge.HIGH   { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
  .badge.MEDIUM { background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }
  .badge.LOW    { background: rgba(107,114,128,0.15);color: #9ca3af; border: 1px solid rgba(107,114,128,0.3); }
  .mitre-tag {
    font-family: 'DM Mono', monospace;
    font-size: 11px;
    color: var(--accent);
    background: rgba(99,102,241,0.1);
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid rgba(99,102,241,0.2);
  }
  .ip {
    font-family: 'DM Mono', monospace;
    font-size: 12px;
    color: var(--text);
  }
  .ts {
    font-family: 'DM Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    white-space: nowrap;
  }
  .reasoning {
    font-size: 12px;
    color: var(--muted);
    line-height: 1.5;
    max-width: 320px;
  }
  .attack-name { font-size: 13px; font-weight: 600; color: var(--text); }
  .empty {
    text-align: center;
    padding: 64px;
    color: var(--muted);
    font-family: 'DM Mono', monospace;
    font-size: 13px;
  }
  .empty .icon { font-size: 32px; margin-bottom: 12px; opacity: 0.3; }
</style>
</head>
<body>

<div class="header">
  <div class="logo">
    <div class="logo-icon">⚡</div>
    <div>
      <h1>RAG Threat Detector</h1>
      <p>MITRE + Sigma · LLM-based analysis</p>
    </div>
  </div>
  <div class="header-right">
    <div class="status-dot"></div>
    <span class="status-label">{{ source_label }}</span>
    <button class="refresh-btn" onclick="location.reload()">↻ Refresh</button>
  </div>
</div>

<div class="stats">
  <div class="stat total">
    <div class="num">{{ total }}</div>
    <div class="lbl">Logs analyzed</div>
  </div>
  <div class="stat high">
    <div class="num">{{ high }}</div>
    <div class="lbl">HIGH threats</div>
  </div>
  <div class="stat medium">
    <div class="num">{{ medium }}</div>
    <div class="lbl">MEDIUM threats</div>
  </div>
  <div class="stat clean">
    <div class="num">{{ clean }}</div>
    <div class="lbl">Clean logs</div>
  </div>
</div>

<div class="section">
  <div class="section-header">
    <span class="section-title">Detections</span>
    <div class="filter-tabs">
      <button class="tab active" onclick="filterTable('ALL', this)">All</button>
      <button class="tab" onclick="filterTable('HIGH', this)">High</button>
      <button class="tab" onclick="filterTable('MEDIUM', this)">Medium</button>
    </div>
  </div>

  <table id="threat-table">
    <thead>
      <tr>
        <th>Time</th>
        <th>Source IP</th>
        <th>Confidence</th>
        <th>Attack type</th>
        <th>MITRE ID</th>
        <th>Reasoning</th>
      </tr>
    </thead>
    <tbody>
      {% if threats %}
        {% for r in threats %}
        <tr data-conf="{{ r.confidence }}">
          <td><span class="ts">{{ r.timestamp[:19] }}</span></td>
          <td><span class="ip">{{ r.src_ip }}</span></td>
          <td><span class="badge {{ r.confidence }}">{{ r.confidence }}</span></td>
          <td><span class="attack-name">{{ r.attack_type }}</span></td>
          <td>
            {% if r.mitre_id != 'NONE' %}
            <span class="mitre-tag">{{ r.mitre_id }}</span>
            {% else %}
            <span style="color:var(--muted);font-size:12px">—</span>
            {% endif %}
          </td>
          <td><div class="reasoning">{{ r.reasoning[:160] }}{% if r.reasoning|length > 160 %}...{% endif %}</div></td>
        </tr>
        {% endfor %}
      {% else %}
        <tr><td colspan="6">
          <div class="empty">
            <div class="icon">◎</div>
            No threats detected yet — analysis is running
          </div>
        </td></tr>
      {% endif %}
    </tbody>
  </table>
</div>

<script>
function filterTable(conf, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#threat-table tbody tr').forEach(row => {
    if (conf === 'ALL' || row.dataset.conf === conf) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}
// Auto-refresh every 15 seconds
setTimeout(() => location.reload(), 15000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    cfg     = load_config()
    source  = cfg.get("log_source", "elasticsearch")

    if source == "file":
        results      = load_results()
        source_label = f"File mode · {cfg.get('file',{}).get('path','')}"
    else:
        results      = load_elk_results(cfg)
        source_label = f"ELK · {cfg.get('elasticsearch',{}).get('host','')}"

    threats = [r for r in results if r.get("verdict") == "YES"]
    total   = len(results)
    high    = sum(1 for r in threats if r.get("confidence") == "HIGH")
    medium  = sum(1 for r in threats if r.get("confidence") == "MEDIUM")
    clean   = total - len(threats)

    return render_template_string(
        HTML,
        threats      = sorted(threats, key=lambda x: x.get("timestamp",""), reverse=True),
        total        = total,
        high         = high,
        medium       = medium,
        clean        = clean,
        source_label = source_label,
    )


@app.route("/api/results")
def api_results():
    """JSON API endpoint for programmatic access."""
    cfg    = load_config()
    source = cfg.get("log_source", "elasticsearch")
    if source == "file":
        results = load_results()
    else:
        results = load_elk_results(cfg)
    threats = [r for r in results if r.get("verdict") == "YES"]
    return jsonify({
        "total"  : len(results),
        "threats": len(threats),
        "high"   : sum(1 for r in threats if r.get("confidence") == "HIGH"),
        "medium" : sum(1 for r in threats if r.get("confidence") == "MEDIUM"),
        "results": threats,
    })


if __name__ == "__main__":
    print("\n  RAG Threat Detector — Web UI")
    print("  Open: http://localhost:5000")
    print("  Ctrl+C to stop\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
