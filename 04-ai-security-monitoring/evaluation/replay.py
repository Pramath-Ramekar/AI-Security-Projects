"""
Attack replay system — Step 18.
Loads normal_traffic.json + attack_traffic.json, injects into collector,
runs detection, and writes results.json with detection metrics.

Usage: python evaluation/replay.py
"""
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from collector.collector import collect_batch, load_events, EVENTS_FILE
from detection.engine import run_detection

EVAL_DIR = Path(__file__).parent
RESULTS_FILE = EVAL_DIR / "results.json"


def load_json(path: Path) -> list[dict]:
    if not path.exists():
        print(f"[replay] Missing {path} — run generate_traffic.py first")
        return []
    return json.loads(path.read_text())


def compute_metrics(
    attack_events: list[dict],
    normal_events: list[dict],
    alerts: list[dict],
) -> dict:
    # Which attack events were actually flagged
    attack_event_ids = {e.get("event_id") for e in attack_events}
    normal_event_ids = {e.get("event_id") for e in normal_events}

    # Flatten all event_ids referenced in alerts
    alerted_event_ids = set()
    for a in alerts:
        alerted_event_ids.update(a.get("event_ids", []))
        # also check user-level — if attacker user appears in any alert
    alerted_users = {a.get("user_id") for a in alerts}
    attack_users = {e.get("user_id") for e in attack_events}

    # Attack detection: did any attack event's session get an alert?
    attack_session_ids = {e.get("session_id") for e in attack_events}
    alerted_session_ids = set()
    for a in alerts:
        for ev_id in a.get("event_ids", []):
            # We don't have direct session → alert mapping here, so use user proxy
            pass
    # Use user-level proxy: attack detected if attacker user appears in any alert
    detected_users = attack_users & alerted_users
    undetected_users = attack_users - alerted_users

    # Unique attack scenarios
    attack_scenarios = list({e.get("scenario", "?") for e in attack_events if e.get("label") == "attack"})
    detected_scenarios = []
    undetected_scenarios = []
    for scenario in attack_scenarios:
        scenario_events = [e for e in attack_events if e.get("scenario") == scenario]
        scenario_users = {e.get("user_id") for e in scenario_events}
        if scenario_users & alerted_users:
            detected_scenarios.append(scenario)
        else:
            undetected_scenarios.append(scenario)

    detection_rate = len(detected_scenarios) / len(attack_scenarios) if attack_scenarios else 0.0

    # False positives: normal events whose users got alerted
    normal_users = {e.get("user_id") for e in normal_events} - attack_users
    false_positive_users = normal_users & alerted_users
    fpr = len(false_positive_users) / len(normal_users) if normal_users else 0.0

    # Alert precision
    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    high_alerts = [a for a in alerts if severity_order.get(a.get("severity", "low"), 0) >= 2]

    return {
        "events_processed": len(attack_events) + len(normal_events),
        "normal_events": len(normal_events),
        "attack_events": len(attack_events),
        "attack_scenarios_total": len(attack_scenarios),
        "attack_scenarios_detected": len(detected_scenarios),
        "attack_scenarios_missed": len(undetected_scenarios),
        "detection_rate": round(detection_rate * 100, 1),
        "false_positive_rate": round(fpr * 100, 1),
        "false_positive_users": list(false_positive_users),
        "total_alerts": len(alerts),
        "high_critical_alerts": len(high_alerts),
        "detected_scenarios": detected_scenarios,
        "undetected_scenarios": undetected_scenarios,
    }


def main():
    print("=" * 55)
    print("  Aegis AI SOC — Attack Replay & Detection Evaluation")
    print("=" * 55)

    normal = load_json(EVAL_DIR / "normal_traffic.json")
    attacks = load_json(EVAL_DIR / "attack_traffic.json")

    if not normal and not attacks:
        print("No traffic data found. Run generate_traffic.py first.")
        sys.exit(1)

    # Clear previous log and reinject
    if EVENTS_FILE.exists():
        EVENTS_FILE.unlink()
        print(f"[replay] Cleared previous events log")

    all_events = sorted(normal + attacks, key=lambda e: e.get("timestamp", ""))
    n = collect_batch(all_events)
    print(f"[replay] Injected {n} events ({len(normal)} normal + {len(attacks)} attack)")

    # Run detection
    print("[replay] Running detection engine...")
    t0 = time.time()
    result = run_detection(verbose=True)
    elapsed = time.time() - t0
    print(f"[replay] Detection completed in {elapsed:.2f}s")

    # Compute metrics
    metrics = compute_metrics(attacks, normal, result.get("alerts", []))
    metrics["detection_time_seconds"] = round(elapsed, 3)
    metrics["run_timestamp"] = datetime.now(timezone.utc).isoformat()
    metrics["alert_summary"] = result.get("by_severity", {})

    # Write results
    RESULTS_FILE.write_text(json.dumps(metrics, indent=2))
    print(f"\n[replay] Results written to {RESULTS_FILE}")

    # Print table
    print("\n" + "=" * 55)
    print("  DETECTION RESULTS")
    print("=" * 55)
    print(f"  Events processed        : {metrics['events_processed']:>6}")
    print(f"  Attack scenarios        : {metrics['attack_scenarios_total']:>6}")
    print(f"  Scenarios detected      : {metrics['attack_scenarios_detected']:>6}")
    print(f"  Detection rate          : {metrics['detection_rate']:>5.1f}%")
    print(f"  False positive rate     : {metrics['false_positive_rate']:>5.1f}%")
    print(f"  Total alerts            : {metrics['total_alerts']:>6}")
    print(f"  HIGH/CRITICAL alerts    : {metrics['high_critical_alerts']:>6}")
    print(f"  Detection time          : {metrics['detection_time_seconds']:>5.3f}s")
    print("=" * 55)

    if metrics["undetected_scenarios"]:
        print(f"\n  Missed scenarios:")
        for s in metrics["undetected_scenarios"]:
            print(f"    - {s}")


if __name__ == "__main__":
    main()
