"""
Tool-chain detection — Step 11.
Detects dangerous tool sequences within a session.
"""
from typing import Optional


CHAIN_PATTERNS = [
    {
        "id": "CHAIN-READ-EXFIL",
        "name": "Read → External Exfiltration",
        "description": "File read followed by send_email (potential data exfiltration)",
        "severity": "critical",
        "sequence": [
            lambda e: e.get("tool") == "read_file",
            lambda e: e.get("tool") == "send_email",
        ],
        "window": 5,  # must complete within N events
    },
    {
        "id": "CHAIN-SEARCH-DUMP",
        "name": "Employee Search → Mass Email",
        "description": "Employee database search followed by send_email",
        "severity": "high",
        "sequence": [
            lambda e: e.get("tool") == "search_employee",
            lambda e: e.get("tool") == "send_email",
        ],
        "window": 5,
    },
    {
        "id": "CHAIN-READ-EXEC",
        "name": "Sensitive Read → Command Execution",
        "description": "File read followed by execute_command",
        "severity": "critical",
        "sequence": [
            lambda e: e.get("tool") == "read_file",
            lambda e: e.get("tool") == "execute_command",
        ],
        "window": 5,
    },
    {
        "id": "CHAIN-MULTI-READ-EXFIL",
        "name": "Bulk Read → Exfiltration",
        "description": "Multiple file reads followed by send_email (bulk exfiltration)",
        "severity": "critical",
        "sequence": [
            lambda e: e.get("tool") == "read_file",
            lambda e: e.get("tool") == "read_file",
            lambda e: e.get("tool") == "send_email",
        ],
        "window": 10,
    },
]


def _match_sequence(events: list[dict], pattern: list) -> bool:
    """Check if the pattern sequence appears in order within events."""
    pattern_idx = 0
    for event in events:
        if pattern[pattern_idx](event):
            pattern_idx += 1
            if pattern_idx == len(pattern):
                return True
    return False


def detect_chains(session_events: list[dict]) -> list[dict]:
    """
    Run all chain patterns against a session's tool events.
    Returns list of detected chain findings.
    """
    tool_events = [e for e in session_events if e.get("tool")]
    findings = []
    for pattern in CHAIN_PATTERNS:
        window_events = tool_events[-pattern["window"]:]
        if _match_sequence(window_events, pattern["sequence"]):
            user = session_events[0].get("user_id", "?") if session_events else "?"
            sess = session_events[0].get("session_id", "?") if session_events else "?"
            findings.append({
                "rule": pattern["id"],
                "name": pattern["name"],
                "severity": pattern["severity"],
                "user_id": user,
                "application": session_events[0].get("application") if session_events else None,
                "reason": f"Tool chain detected in session '{sess}' (user '{user}'): "
                          f"{pattern['description']}",
                "trigger_events": [e.get("event_id") for e in window_events],
            })
    return findings
