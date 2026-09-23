"""
Main detection engine — orchestrates rules, tool-chain, anomaly, correlation.
"""
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from detection.rules import evaluate_event
from detection.tool_chain import detect_chains
from detection.anomaly import detect_rate_anomalies, detect_new_user_behavior
from detection.correlation import correlate
from detection.risk_scoring import score_event, score_to_severity
from alerts.manager import process_incidents
from collector.collector import load_events


BASELINE_USERS = {"alice", "bob", "charlie", "admin"}


def run_detection(events: list[dict] = None, verbose: bool = False) -> dict:
    """
    Run the full detection pipeline over a list of events (or load from log).
    Returns detection summary.
    """
    if events is None:
        events = load_events()

    if not events:
        return {"error": "no events to process"}

    # Group by session
    sessions: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        sessions[e.get("session_id", "unknown")].append(e)

    all_findings = []

    # Per-event + session rules
    for sess_id, sess_events in sessions.items():
        for event in sess_events:
            findings = evaluate_event(event, events, sess_events)
            all_findings.extend(findings)

        # Tool chain detection per session
        chain_findings = detect_chains(sess_events)
        all_findings.extend(chain_findings)

    # Anomaly detection (across all events)
    anomalies = detect_rate_anomalies(events)
    all_findings.extend(anomalies)

    new_user_findings = detect_new_user_behavior(events, BASELINE_USERS)
    all_findings.extend(new_user_findings)

    if verbose:
        print(f"[Detection] {len(events)} events processed")
        print(f"[Detection] {len(all_findings)} raw findings")

    # Correlation
    incidents = correlate(events, all_findings)

    if verbose:
        print(f"[Detection] {len(incidents)} correlated incidents")

    # Alert generation (MEDIUM severity and above)
    alerts = process_incidents(incidents)

    if verbose:
        print(f"[Detection] {len(alerts)} alerts generated")

    # Summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sev = a.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "events_processed": len(events),
        "raw_findings": len(all_findings),
        "incidents": len(incidents),
        "alerts_generated": len(alerts),
        "by_severity": severity_counts,
        "alerts": [a.to_dict() for a in alerts],
    }


if __name__ == "__main__":
    result = run_detection(verbose=True)
    print(f"\nSummary:")
    print(f"  Events processed : {result['events_processed']}")
    print(f"  Raw findings     : {result['raw_findings']}")
    print(f"  Incidents        : {result['incidents']}")
    print(f"  Alerts generated : {result['alerts_generated']}")
    print(f"  By severity      : {result['by_severity']}")
