"""Risk scoring — Step 12."""

EVENT_SCORES = {
    "query":                  0,
    "agent_response":         0,
    "tool_executed":          1,
    "tool_request":           1,
    "approval_requested":     2,
    "approval_granted":       1,
    "approval_denied":        3,
    "rate_abuse":             4,
    "pii_request":            4,
    "validation_fail":        3,
    "policy_deny":            4,
    "tool_blocked":           4,
    "unauthorized_retrieval": 7,
    "prompt_injection":       5,
    "chain_blocked":          8,
    "suspicious_tool_chain":  8,
    "secret_access":          10,
}

RISK_MODIFIERS = {
    "critical": 3,
    "high":     2,
    "medium":   1,
    "low":      0,
}

DECISION_MODIFIERS = {
    "blocked":  1,
    "flagged":  1,
    "allow":    0,
    "executed": 0,
    "pending":  0,
}

THRESHOLDS = {
    "low":      (0, 4),
    "medium":   (5, 9),
    "high":     (10, 14),
    "critical": (15, float("inf")),
}


def score_event(event: dict) -> int:
    base = EVENT_SCORES.get(event.get("event_type", "query"), 0)
    risk_mod = RISK_MODIFIERS.get(event.get("risk", "low"), 0)
    decision_mod = DECISION_MODIFIERS.get(event.get("decision", "allow"), 0)
    return base + risk_mod + decision_mod


def score_to_severity(score: int) -> str:
    for level, (lo, hi) in THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "critical"


def score_session(events: list[dict]) -> tuple[int, str]:
    total = sum(score_event(e) for e in events)
    return total, score_to_severity(total)
