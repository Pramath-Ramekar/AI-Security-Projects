"""
Rule-based detection engine — Steps 8, 9, 10.
Each rule returns a dict if it fires, else None.
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional


# ── Rule helpers ────────────────────────────────────────────────────────────

def _ts(event: dict) -> datetime:
    try:
        return datetime.fromisoformat(event["timestamp"])
    except Exception:
        return datetime.now(timezone.utc)


def _window(events: list[dict], minutes: int) -> list[dict]:
    """Return events within the last `minutes` minutes relative to the latest event."""
    if not events:
        return []
    latest = max(_ts(e) for e in events)
    cutoff = latest - timedelta(minutes=minutes)
    return [e for e in events if _ts(e) >= cutoff]


# ── Individual rules ─────────────────────────────────────────────────────────

def rule_prompt_injection(event: dict) -> Optional[dict]:
    """Rule 1: any prompt injection event → HIGH alert."""
    if event.get("event_type") == "prompt_injection":
        return {
            "rule": "RULE-001",
            "name": "Prompt Injection Detected",
            "severity": "high",
            "reason": f"Prompt injection event from user '{event.get('user_id')}' "
                      f"on {event.get('application')}",
            "trigger_event": event.get("event_id"),
        }
    return None


def rule_blocked_burst(session_events: list[dict], threshold: int = 5) -> Optional[dict]:
    """Rule 2: ≥threshold blocked requests in any 1-minute window → alert."""
    recent = _window(session_events, 1)
    blocked = [e for e in recent if e.get("decision") in ("blocked",)]
    if len(blocked) >= threshold:
        user = blocked[0].get("user_id", "?")
        return {
            "rule": "RULE-002",
            "name": "Blocked Request Burst",
            "severity": "high",
            "reason": f"{len(blocked)} blocked requests in 1 minute from user '{user}'",
            "trigger_events": [e.get("event_id") for e in blocked],
        }
    return None


def rule_sensitive_unauthorized(event: dict) -> Optional[dict]:
    """Rule 3: unauthorized retrieval of sensitive document → CRITICAL."""
    sensitive_paths = {"compensation", "secrets", "employees", "salary", "password"}
    if event.get("event_type") == "unauthorized_retrieval":
        doc = event.get("document", "")
        if any(s in (doc or "").lower() for s in sensitive_paths):
            return {
                "rule": "RULE-003",
                "name": "Sensitive Unauthorized Retrieval",
                "severity": "critical",
                "reason": f"User '{event.get('user_id')}' attempted unauthorized access "
                          f"to sensitive document '{doc}'",
                "trigger_event": event.get("event_id"),
            }
        return {
            "rule": "RULE-003b",
            "name": "Unauthorized Document Retrieval",
            "severity": "high",
            "reason": f"User '{event.get('user_id')}' unauthorized retrieval of '{doc}'",
            "trigger_event": event.get("event_id"),
        }
    return None


def rule_secret_access(event: dict) -> Optional[dict]:
    """Rule 4: any secret_access event → CRITICAL."""
    if event.get("event_type") == "secret_access":
        return {
            "rule": "RULE-004",
            "name": "Secret Access Attempt",
            "severity": "critical",
            "reason": f"User '{event.get('user_id')}' attempted to access secrets/credentials "
                      f"via {event.get('application')}",
            "trigger_event": event.get("event_id"),
        }
    return None


def rule_high_rate(
    all_events: list[dict],
    user_id: str,
    threshold: int = 30,
    window_minutes: int = 1,
) -> Optional[dict]:
    """Rule 5 (Step 9): sliding-window rate abuse detection."""
    user_events = [e for e in all_events if e.get("user_id") == user_id]
    recent = _window(user_events, window_minutes)
    if len(recent) >= threshold:
        return {
            "rule": "RULE-005",
            "name": "High Request Rate",
            "severity": "high",
            "reason": f"User '{user_id}' sent {len(recent)} requests in {window_minutes} minute(s) "
                      f"(threshold: {threshold})",
            "trigger_events": [e.get("event_id") for e in recent[:10]],
        }
    return None


def rule_repeated_violations(
    session_events: list[dict],
    threshold: int = 3,
    window_minutes: int = 5,
) -> Optional[dict]:
    """Rule 6 (Step 10): >threshold security violations in 5 min → suspicious session."""
    violation_types = {
        "prompt_injection", "unauthorized_retrieval", "secret_access",
        "policy_deny", "chain_blocked", "validation_fail",
    }
    recent = _window(session_events, window_minutes)
    violations = [e for e in recent if e.get("event_type") in violation_types]
    if len(violations) > threshold:
        user = violations[0].get("user_id", "?")
        sess = violations[0].get("session_id", "?")
        return {
            "rule": "RULE-006",
            "name": "Suspicious Session — Repeated Violations",
            "severity": "high",
            "reason": f"Session '{sess}' (user '{user}') had {len(violations)} security violations "
                      f"in {window_minutes} minutes",
            "trigger_events": [e.get("event_id") for e in violations],
        }
    return None


def rule_dangerous_tool(event: dict) -> Optional[dict]:
    """Rule 7: any request for execute_command → alert regardless of outcome."""
    if event.get("tool") == "execute_command":
        decision = event.get("decision", "allow")
        severity = "critical" if decision in ("allow", "executed") else "high"
        return {
            "rule": "RULE-007",
            "name": "Dangerous Tool Access",
            "severity": severity,
            "reason": f"User '{event.get('user_id')}' requested execute_command "
                      f"(decision: {decision})",
            "trigger_event": event.get("event_id"),
        }
    return None


def evaluate_event(event: dict, all_events: list[dict], session_events: list[dict]) -> list[dict]:
    """Run all per-event and session rules. Returns list of fired rule dicts."""
    findings = []
    for rule_fn in [rule_prompt_injection, rule_sensitive_unauthorized,
                    rule_secret_access, rule_dangerous_tool]:
        result = rule_fn(event)
        if result:
            findings.append(result)

    for session_rule in [rule_blocked_burst, rule_repeated_violations]:
        result = session_rule(session_events)
        if result:
            findings.append(result)

    rate_result = rule_high_rate(all_events, event.get("user_id", ""))
    if rate_result:
        findings.append(rate_result)

    return findings
