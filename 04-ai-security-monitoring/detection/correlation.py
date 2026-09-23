"""
Event correlation engine — Step 13.
Groups findings by session and user; escalates severity when multiple
indicators cluster together within a time window.
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter
from typing import Optional

from detection.risk_scoring import score_session


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_NAMES = {0: "low", 1: "medium", 2: "high", 3: "critical"}


def _max_severity(severities: list[str]) -> str:
    if not severities:
        return "low"
    return SEVERITY_NAMES[max(SEVERITY_ORDER.get(s, 0) for s in severities)]


def _finding_event_ids(finding: dict) -> list[str]:
    ids = []
    if finding.get("trigger_event"):
        ids.append(finding["trigger_event"])
    ids.extend(finding.get("trigger_events", []))
    return ids


def _dominant_application(findings: list[dict]) -> Optional[str]:
    """Most common non-null application across findings."""
    apps = [f.get("application") for f in findings if f.get("application")]
    if not apps:
        return None
    return Counter(apps).most_common(1)[0][0]


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

    # Index events by id so we can risk-score an incident's real events
    events_by_id = {e.get("event_id"): e for e in events if e.get("event_id")}

    # Group findings by user. Rules carry user_id explicitly; the reason-string
    # regex is only a fallback for any finding that predates that contract.
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
                all_event_ids.extend(_finding_event_ids(f))
            event_ids = list(dict.fromkeys(all_event_ids))

            # Risk score the incident from its underlying events
            incident_events = [events_by_id[i] for i in event_ids if i in events_by_id]
            risk_score, risk_severity = score_session(incident_events)

            # Escalation and risk score are independent signals; take the harsher.
            final_severity = _max_severity([escalated, risk_severity])

            rules = sorted(set(f.get("rule") for f in high_plus if f.get("rule")))

            incidents.append({
                "type": "CORRELATED_INCIDENT",
                "severity": final_severity,
                "user_id": user,
                "application": _dominant_application(high_plus),
                "finding_count": len(high_plus),
                "risk_score": risk_score,
                "reason": f"Correlated incident: {len(high_plus)} high/critical findings "
                          f"for user '{user}' (risk score {risk_score}) — possible attack chain",
                "rules_fired": rules,
                "event_ids": event_ids,
                "findings": high_plus,
            })
        else:
            # Pass through individual findings as-is
            for f in user_findings:
                event_ids = _finding_event_ids(f)
                incident_events = [events_by_id[i] for i in event_ids if i in events_by_id]
                risk_score, _ = score_session(incident_events)
                incidents.append({
                    "type": "SINGLE_FINDING",
                    "severity": f.get("severity", "low"),
                    "user_id": user,
                    "application": f.get("application"),
                    "finding_count": 1,
                    "risk_score": risk_score,
                    "reason": f.get("reason", ""),
                    "rules_fired": [f.get("rule")],
                    "event_ids": event_ids,
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
    """Fallback user extraction. Case-insensitive: rules write both
    "user 'x'" and "User 'x'"."""
    import re
    m = re.search(r"user '([^']+)'", reason, re.IGNORECASE)
    return m.group(1) if m else "unknown"
