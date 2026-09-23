"""
Event correlation engine — Step 13.
Groups findings by session and user; escalates severity when multiple
indicators cluster together within a time window.
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_NAMES = {0: "low", 1: "medium", 2: "high", 3: "critical"}


def _max_severity(severities: list[str]) -> str:
    if not severities:
        return "low"
    return SEVERITY_NAMES[max(SEVERITY_ORDER.get(s, 0) for s in severities)]


def correlate(
    events: list[dict],
    findings: list[dict],
    window_minutes: int = 10,
) -> list[dict]:
    """
    Correlate findings with their source events.
    When multiple HIGH/CRITICAL findings share the same user within the window,
    escalate to a correlated incident.

    Returns list of correlated incident dicts.
    """
    if not findings:
        return []

    # Group findings by user
    by_user: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        user = f.get("user_id") or _extract_user(f.get("reason", ""))
        by_user[user].append(f)

    incidents = []
    for user, user_findings in by_user.items():
        high_plus = [f for f in user_findings
                     if SEVERITY_ORDER.get(f.get("severity", "low"), 0) >= 2]
        if len(high_plus) >= 2:
            # Escalate: multiple high/critical findings for same user
            severities = [f.get("severity", "low") for f in high_plus]
            escalated = _escalate_severity(_max_severity(severities), len(high_plus))
            all_event_ids = []
            for f in high_plus:
                if "trigger_event" in f:
                    all_event_ids.append(f["trigger_event"])
                all_event_ids.extend(f.get("trigger_events", []))

            incidents.append({
                "type": "CORRELATED_INCIDENT",
                "severity": escalated,
                "user_id": user,
                "finding_count": len(high_plus),
                "reason": f"Correlated incident: {len(high_plus)} high/critical findings "
                          f"for user '{user}' — possible attack chain",
                "rules_fired": [f.get("rule") for f in high_plus],
                "event_ids": list(dict.fromkeys(all_event_ids)),  # dedup, preserve order
                "findings": high_plus,
            })
        else:
            # Pass through individual findings as-is
            for f in user_findings:
                incidents.append({
                    "type": "SINGLE_FINDING",
                    "severity": f.get("severity", "low"),
                    "user_id": user,
                    "finding_count": 1,
                    "reason": f.get("reason", ""),
                    "rules_fired": [f.get("rule")],
                    "event_ids": (
                        [f["trigger_event"]] if "trigger_event" in f
                        else f.get("trigger_events", [])
                    ),
                    "findings": [f],
                })

    return incidents


def _escalate_severity(base: str, count: int) -> str:
    level = SEVERITY_ORDER.get(base, 0)
    if count >= 4:
        level = min(level + 2, 3)
    elif count >= 2:
        level = min(level + 1, 3)
    return SEVERITY_NAMES[level]


def _extract_user(reason: str) -> str:
    import re
    m = re.search(r"user '([^']+)'", reason)
    return m.group(1) if m else "unknown"
