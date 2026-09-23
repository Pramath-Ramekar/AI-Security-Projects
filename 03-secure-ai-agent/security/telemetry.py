"""
Telemetry bridge — emits SecurityEvents to the Project 04 AI SOC collector.

Every audit event produced by the hardened agent is translated into the
common SecurityEvent schema and forwarded to the SOC. This is what turns
Project 04 from a synthetic-data exercise into monitoring of a real system.

Transport is file-based by default (append to the SOC's events.jsonl).
Set AEGIS_SOC_URL to POST over HTTP to a running collector instead.

Failure is always silent: telemetry must never break the agent.
"""

import json
import os
import uuid
import hashlib
from datetime import datetime, timezone

# Where the SOC collector keeps its event log.
_SOC_EVENTS = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "..",
        "04-ai-security-monitoring", "logs", "events.jsonl",
    )
)
_SOC_URL = os.environ.get("AEGIS_SOC_URL")  # e.g. http://localhost:8765/events

APPLICATION = "secure-agent"

# audit_logger event type -> (SOC event_type, default risk)
_EVENT_MAP = {
    "USER_REQUEST":       ("query",              "low"),
    "TOOL_REQUEST":       ("tool_request",       "low"),
    "POLICY_DENY":        ("policy_deny",        "high"),
    "POLICY_ALLOW":       ("tool_request",       "low"),
    "VALIDATION_FAIL":    ("validation_fail",    "high"),
    "VALIDATION_PASS":    ("tool_request",       "low"),
    "APPROVAL_REQUESTED": ("approval_requested", "medium"),
    "APPROVAL_GRANTED":   ("approval_granted",   "medium"),
    "APPROVAL_DENIED":    ("approval_denied",    "high"),
    "CHAIN_BLOCKED":      ("chain_blocked",      "critical"),
    "CHAIN_ALLOWED":      ("tool_request",       "low"),
    "TOOL_EXECUTED":      ("tool_executed",      "medium"),
    "TOOL_ERROR":         ("tool_request",       "medium"),
    "AGENT_RESPONSE":     ("agent_response",     "low"),
}

# Tool risk tiers mirror security/tool_registry.py
_TOOL_RISK = {
    "search_employee":  "low",
    "read_file":        "medium",
    "create_file":      "medium",
    "send_email":       "high",
    "execute_command":  "critical",
}

_DECISION_MAP = {
    "POLICY_DENY":     "blocked",
    "VALIDATION_FAIL": "blocked",
    "CHAIN_BLOCKED":   "blocked",
    "APPROVAL_DENIED": "blocked",
    "TOOL_EXECUTED":   "executed",
    "TOOL_ERROR":      "blocked",
    "APPROVAL_REQUESTED": "pending",
}

# Sensitive paths that should raise an event to secret_access / unauthorized
_SENSITIVE_MARKERS = ("employees.json", "secrets", "compensation", "salary", "password")


def _sensitive(arguments: dict) -> bool:
    blob = json.dumps(arguments or {}).lower()
    return any(m in blob for m in _SENSITIVE_MARKERS)


def _emit(event: dict) -> None:
    """Write the event to the SOC. Never raises."""
    try:
        if _SOC_URL:
            import urllib.request
            req = urllib.request.Request(
                _SOC_URL,
                data=json.dumps(event).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2).read()
        else:
            os.makedirs(os.path.dirname(_SOC_EVENTS), exist_ok=True)
            with open(_SOC_EVENTS, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
    except Exception:
        pass  # telemetry must never break the agent


def emit_audit_event(
    event_type: str,
    tool_name: str = None,
    arguments: dict = None,
    user: str = "unknown",
    session_id: str = "default",
    details: dict = None,
) -> None:
    """Translate an audit_logger event into a SecurityEvent and ship it."""
    mapped = _EVENT_MAP.get(event_type)
    if mapped is None:
        return  # unmapped audit event — nothing to report
    soc_type, base_risk = mapped

    # A tool's own risk tier outranks the event's default risk.
    risk = _TOOL_RISK.get(tool_name, base_risk)
    if event_type in ("POLICY_DENY", "VALIDATION_FAIL", "CHAIN_BLOCKED"):
        risk = _TOOL_RISK.get(tool_name, "high")

    # Reading a sensitive target is reported as secret_access, not a plain read.
    if soc_type in ("tool_request", "tool_executed") and _sensitive(arguments):
        soc_type = "secret_access"
        risk = "critical"

    args = arguments or {}
    document = args.get("filename") or args.get("path") or args.get("file")

    event = {
        "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "application": APPLICATION,
        "event_type": soc_type,
        "user_id": user,
        "session_id": session_id,
        "tool": tool_name,
        "document": document,
        "risk": risk,
        "decision": _DECISION_MAP.get(event_type, "allow"),
        "details": details or {},
        "source": "live",  # distinguishes real telemetry from replayed fixtures
    }
    if args:
        event["prompt_hash"] = hashlib.sha256(
            json.dumps(args, sort_keys=True).encode()
        ).hexdigest()[:16]

    _emit(event)
