"""
Alert manager — Step 14.
Deduplicates, persists, and retrieves alerts.
"""
import json
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from alerts.schema import Alert, make_alert

ALERTS_FILE = Path(__file__).parent.parent / "logs" / "alerts.jsonl"


def _ensure_dir():
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)


def save_alert(alert: Alert) -> None:
    _ensure_dir()
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(alert.to_json() + "\n")


def load_alerts(
    severity: Optional[str] = None,
    user_id: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    if not ALERTS_FILE.exists():
        return []
    alerts = []
    with open(ALERTS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            if severity and a.get("severity") != severity:
                continue
            if user_id and a.get("user_id") != user_id:
                continue
            if status and a.get("status") != status:
                continue
            alerts.append(a)
    return alerts


def alert_count() -> dict:
    alerts = load_alerts()
    counts = {"total": len(alerts), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sev = a.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def process_incidents(incidents: list[dict], application: Optional[str] = None) -> list[Alert]:
    """Convert correlated incidents into Alert objects and persist them."""
    min_severity = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    alerts = []
    for incident in incidents:
        if min_severity.get(incident.get("severity", "low"), 0) >= 1:  # MEDIUM+
            alert = make_alert(incident, application)
            save_alert(alert)
            alerts.append(alert)
    return alerts
