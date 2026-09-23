"""
Audit Logger — Step 18.
Every tool request, decision, and outcome is written to a structured log.
"""

import json
import os
from datetime import datetime, timezone

try:
    from security.telemetry import emit_audit_event
    TELEMETRY_ENABLED = os.environ.get("AEGIS_TELEMETRY", "1") != "0"
except ImportError:
    TELEMETRY_ENABLED = False

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
LOG_FILE = os.path.join(LOG_DIR, "audit.jsonl")

EVENT_TYPES = {
    "USER_REQUEST",
    "TOOL_REQUEST",
    "POLICY_DENY",
    "POLICY_ALLOW",
    "VALIDATION_FAIL",
    "VALIDATION_PASS",
    "APPROVAL_REQUESTED",
    "APPROVAL_GRANTED",
    "APPROVAL_DENIED",
    "CHAIN_BLOCKED",
    "CHAIN_ALLOWED",
    "TOOL_EXECUTED",
    "TOOL_ERROR",
    "AGENT_RESPONSE",
}


def _write(event: dict):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def log(
    event_type: str,
    tool_name: str = None,
    arguments: dict = None,
    user: str = "unknown",
    session_id: str = "default",
    details: dict = None,
):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "session_id": session_id,
        "user": user,
        "tool": tool_name,
        "arguments": arguments,
        "details": details or {},
    }
    _write(entry)

    # Forward to the AI SOC (Project 04). Fails silently by design — the
    # agent's security pipeline must not depend on monitoring being up.
    if TELEMETRY_ENABLED:
        try:
            emit_audit_event(
                event_type=event_type,
                tool_name=tool_name,
                arguments=arguments,
                user=user,
                session_id=session_id,
                details=details,
            )
        except Exception:
            pass


def read_log(last_n: int = 20) -> list:
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        lines = f.readlines()
    entries = []
    for line in lines[-last_n:]:
        try:
            entries.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            pass
    return entries
