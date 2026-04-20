"""
baseline.py — Behavioral Baseline Normality Model
===================================================
Learns what "normal" looks like for each source IP
by computing statistics from a clean historical period in ELK.

Design principles:
  - Uses ES aggregations (not raw log loading) — scales to any log volume
  - Never makes the final detection decision — only adds context to LLM prompt
  - Every log still goes to the LLM — baseline never filters or skips anything
  - Recomputable on demand — call build_baseline() to refresh

Usage:
    from baseline import BaselineModel

    # Build baseline from clean period (before attacks start)
    baseline = BaselineModel(es)
    baseline.build(index="thesis-simulation-*", hours=1)

    # Get context string for a specific IP to inject into LLM prompt
    context = baseline.get_context("10.0.0.5")
    # Returns something like:
    # "Baseline for 10.0.0.5: normal_failures=0.2/hr, normal_success=2.1/hr,
    #  normal_sudo=0.5/hr — THIS SESSION: failures=47 (23x above baseline) ANOMALOUS"
"""

import json
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch


class BaselineModel:
    """
    Computes and stores per-IP behavioral baselines using
    Elasticsearch aggregations. Scales to any log volume.
    """

    def __init__(self, es: Elasticsearch):
        self.es       = es
        self.baseline = {}   # { src_ip: { metric: value } }
        self.built    = False
        self.built_at = None
        self.log_count = 0

    # ── Build baseline from a clean historical period ─────────────────────────
    def build(self, index: str, hours: int = 1, before_timestamp: str = None):
        """
        Computes per-IP statistics from ELK using ES aggregations.
        Does NOT load raw logs into memory — only aggregated numbers.

        Args:
            index: Elasticsearch index pattern
            hours: how many hours of history to use
            before_timestamp: use logs before this time (ISO format)
                              defaults to now
        """
        print(f"\nBuilding baseline from last {hours}h of logs...")

        if before_timestamp:
            end   = before_timestamp
            start = (
                datetime.fromisoformat(end.replace("Z", "+00:00"))
                - timedelta(hours=hours)
            ).isoformat()
        else:
            now   = datetime.now(timezone.utc)
            end   = now.isoformat()
            start = (now - timedelta(hours=hours)).isoformat()

        # ── ES aggregation query ───────────────────────────────────────────────
        # Computes per-IP: total events, failure count, success count,
        # sudo count, wget/curl count — all server-side
        # Works at any scale — ES returns just the numbers, not the raw docs
        body = {
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {"gte": start, "lte": end}
                }
            },
            "aggs": {
                "per_ip": {
                    "terms": {
                        "field": "src_ip.keyword",
                        "size": 1000
                    },
                    "aggs": {
                        "total_events": {
                            "value_count": {"field": "src_ip.keyword"}
                        },
                        "failed_events": {
                            "filter": {
                                "query_string": {
                                    "query": "message:(failed OR invalid OR denied OR refused OR error)",
                                    "default_field": "message"
                                }
                            }
                        },
                        "success_events": {
                            "filter": {
                                "query_string": {
                                    "query": "message:(accepted OR success OR opened)",
                                    "default_field": "message"
                                }
                            }
                        },
                        "sudo_events": {
                            "filter": {
                                "query_string": {
                                    "query": "message:sudo",
                                    "default_field": "message"
                                }
                            }
                        },
                        "download_events": {
                            "filter": {
                                "query_string": {
                                    "query": "message:(wget OR curl OR download)",
                                    "default_field": "message"
                                }
                            }
                        },
                    }
                }
            }
        }

        try:
            res    = self.es.search(index=index, body=body)
            hits   = res.get("hits", {}).get("total", {}).get("value", 0)
            buckets = res["aggregations"]["per_ip"]["buckets"]
        except Exception as e:
            print(f"  [!] Baseline build error: {e}")
            print(f"  [!] Baseline disabled — all logs will be analyzed without baseline context")
            self.built = False
            return

        self.baseline  = {}
        self.log_count = hits

        for bucket in buckets:
            ip     = bucket["key"]
            total  = bucket["total_events"]["value"]
            failed = bucket["failed_events"]["doc_count"]
            succ   = bucket["success_events"]["doc_count"]
            sudo   = bucket["sudo_events"]["doc_count"]
            dl     = bucket["download_events"]["doc_count"]

            # Normalize to per-hour rates
            # Avoids comparing absolute counts across different time windows
            self.baseline[ip] = {
                "total_per_hour"   : round(total  / max(hours, 1), 2),
                "failed_per_hour"  : round(failed / max(hours, 1), 2),
                "success_per_hour" : round(succ   / max(hours, 1), 2),
                "sudo_per_hour"    : round(sudo   / max(hours, 1), 2),
                "download_per_hour": round(dl     / max(hours, 1), 2),
                "raw_total"        : total,
            }

        self.built    = True
        self.built_at = datetime.now(timezone.utc).isoformat()

        print(f"  Baseline built from {hits} logs")
        print(f"  IPs profiled: {len(self.baseline)}")
        for ip, stats in self.baseline.items():
            print(f"  {ip}: {stats['failed_per_hour']} failures/hr, "
                  f"{stats['success_per_hour']} success/hr, "
                  f"{stats['sudo_per_hour']} sudo/hr")
        print()


    # ── Get baseline context string for a specific IP ─────────────────────────
    def get_context(self, src_ip: str, session_stats: dict) -> str:
        """
        Generates a context string comparing current session behavior
        against the learned baseline for this IP.

        Args:
            src_ip: the source IP being analyzed
            session_stats: dict with current session counts
                          (from get_session() in llm_watcher.py)

        Returns:
            A string to inject into the LLM prompt providing
            deviation context. Empty string if no baseline exists.
        """
        if not self.built:
            return ""

        # New IP — never seen before in baseline
        if src_ip not in self.baseline:
            return (
                f"Baseline context: IP {src_ip} has NO historical baseline "
                f"— this is a previously unseen source. Treat with elevated suspicion."
            )

        b = self.baseline[src_ip]

        # Current session rates (session_stats comes from get_session())
        cur_failed  = session_stats.get("failed",  0)
        cur_success = session_stats.get("success", 0)
        cur_sudo    = session_stats.get("sudo",    0)
        cur_dl      = session_stats.get("wget",    0)

        lines    = [f"Baseline context for {src_ip}:"]
        anomalies = []

        # Compare each metric — flag deviations > 3x baseline
        def check(metric_name, current, baseline_rate, label):
            # Convert baseline per-hour rate to per-session estimate
            # Session window is 10 minutes = 1/6 hour
            expected = baseline_rate * (10 / 60)
            if expected > 0 and current > 0:
                ratio = round(current / expected, 1)
                if ratio >= 3:
                    anomalies.append(
                        f"{label}: {current} events ({ratio}x above baseline of "
                        f"{baseline_rate}/hr) — ANOMALOUS"
                    )
                    return f"  {label}: current={current}, baseline={baseline_rate}/hr, ratio={ratio}x ⚠"
                else:
                    return f"  {label}: current={current}, baseline={baseline_rate}/hr, ratio={ratio}x (normal)"
            elif current > 0 and baseline_rate == 0:
                anomalies.append(
                    f"{label}: {current} events (baseline=0 — never seen before) — ANOMALOUS"
                )
                return f"  {label}: current={current}, baseline=0/hr — FIRST TIME SEEN ⚠"
            else:
                return f"  {label}: current={current}, baseline={baseline_rate}/hr (normal)"

        lines.append(check("failed",  cur_failed,  b["failed_per_hour"],   "Failed logins"))
        lines.append(check("success", cur_success, b["success_per_hour"],  "Successful logins"))
        lines.append(check("sudo",    cur_sudo,    b["sudo_per_hour"],     "Sudo events"))
        lines.append(check("dl",      cur_dl,      b["download_per_hour"], "Downloads"))

        if anomalies:
            lines.append(f"\nANOMALY SUMMARY — {len(anomalies)} deviation(s) detected:")
            for a in anomalies:
                lines.append(f"  ! {a}")
        else:
            lines.append("\nAll metrics within normal baseline range.")

        return "\n".join(lines)


    # ── Save / load baseline to disk ──────────────────────────────────────────
    def save(self, path: str = "./baseline.json"):
        """Save baseline to disk so it survives restarts."""
        with open(path, "w") as f:
            json.dump({
                "built_at" : self.built_at,
                "log_count": self.log_count,
                "baseline" : self.baseline,
            }, f, indent=2)
        print(f"Baseline saved to {path}")

    def load(self, path: str = "./baseline.json") -> bool:
        """Load baseline from disk. Returns True if successful."""
        try:
            with open(path) as f:
                data = json.load(f)
            self.baseline  = data["baseline"]
            self.built_at  = data["built_at"]
            self.log_count = data["log_count"]
            self.built     = True
            print(f"Baseline loaded from {path}")
            print(f"  Built at  : {self.built_at}")
            print(f"  IPs profiled: {len(self.baseline)}")
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"Baseline load error: {e}")
            return False


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    from elasticsearch import Elasticsearch

    es = Elasticsearch("http://localhost:9200")

    baseline = BaselineModel(es)

    # Build from the first 8 minutes of your dataset
    # (08:00:00 → 08:03:00 — all benign traffic before attack starts)
    baseline.build(
        index="thesis-simulation-*",
        hours=1,
        before_timestamp="2024-04-11T08:03:00Z"
    )

    baseline.save("./baseline.json")

    # Test context generation for attacker IP
    attacker_session = {
        "failed": 8, "success": 1, "sudo": 3, "wget": 2
    }
    print("\n--- Attacker IP context ---")
    print(baseline.get_context("10.0.0.5", attacker_session))

    # Test context generation for benign IP
    benign_session = {
        "failed": 0, "success": 1, "sudo": 1, "wget": 0
    }
    print("\n--- Benign IP context ---")
    print(baseline.get_context("192.168.1.10", benign_session))
