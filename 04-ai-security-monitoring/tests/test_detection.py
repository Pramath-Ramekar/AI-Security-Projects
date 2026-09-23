"""
Detection engine tests.
Run: python -m pytest tests/ -v    (or: python tests/test_detection.py)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from collector.schema import make_event, SecurityEvent
from detection.rules import (
    rule_prompt_injection, rule_secret_access, rule_dangerous_tool,
    rule_sensitive_unauthorized, rule_blocked_burst, rule_repeated_violations,
    rule_blocked_high_risk_tool,
)
from detection.tool_chain import detect_chains
from detection.correlation import correlate, _extract_user
from detection.risk_scoring import score_event, score_to_severity, score_session
from detection.anomaly import detect_rate_anomalies


def ev(event_type, user="attacker", app="secure-agent", **kw):
    """Build a plain event dict for testing."""
    base = {
        "event_id": kw.pop("event_id", f"EVT-{event_type[:4].upper()}"),
        "timestamp": kw.pop("timestamp", "2026-09-23T12:00:00+00:00"),
        "application": app,
        "event_type": event_type,
        "user_id": user,
        "session_id": kw.pop("session_id", "sess-test"),
        "risk": kw.pop("risk", "low"),
        "decision": kw.pop("decision", "allow"),
    }
    base.update(kw)
    return base


# ── Schema ───────────────────────────────────────────────────────────────────

def test_schema_rejects_unknown_application():
    try:
        SecurityEvent(application="not-a-real-app", event_type="query", user_id="alice")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown application")


def test_schema_accepts_valid_event():
    e = make_event("secure-agent", "tool_request", "alice", tool="read_file")
    d = e.to_dict()
    assert d["application"] == "secure-agent"
    assert d["tool"] == "read_file"
    assert d["event_id"].startswith("EVT-")


# ── Rules ────────────────────────────────────────────────────────────────────

def test_prompt_injection_fires_and_carries_user():
    f = rule_prompt_injection(ev("prompt_injection", user="attacker"))
    assert f is not None
    assert f["severity"] == "high"
    # Regression: findings must carry user_id explicitly, not rely on regex.
    assert f["user_id"] == "attacker"
    assert f["application"] == "secure-agent"


def test_prompt_injection_silent_on_normal_query():
    assert rule_prompt_injection(ev("query")) is None


def test_secret_access_is_critical():
    f = rule_secret_access(ev("secret_access", user="attacker"))
    assert f["severity"] == "critical"
    assert f["user_id"] == "attacker"


def test_dangerous_tool_carries_user():
    f = rule_dangerous_tool(ev("tool_request", user="alice", tool="execute_command",
                               decision="blocked"))
    assert f is not None
    assert f["user_id"] == "alice"
    # Blocked is less severe than actually executed.
    assert f["severity"] == "high"


def test_dangerous_tool_executed_is_critical():
    f = rule_dangerous_tool(ev("tool_executed", user="alice", tool="execute_command",
                               decision="executed"))
    assert f["severity"] == "critical"


def test_sensitive_unauthorized_escalates_on_sensitive_doc():
    f = rule_sensitive_unauthorized(
        ev("unauthorized_retrieval", document="finance/compensation"))
    assert f["rule"] == "RULE-003"
    assert f["severity"] == "critical"


def test_unauthorized_plain_doc_is_high_not_critical():
    f = rule_sensitive_unauthorized(
        ev("unauthorized_retrieval", document="engineering/readme"))
    assert f["rule"] == "RULE-003b"
    assert f["severity"] == "high"


def test_blocked_send_email_alone_raises_a_finding():
    """A lone blocked exfiltration attempt must not go unreported just
    because it is a single event."""
    f = rule_blocked_high_risk_tool(
        ev("tool_request", user="attacker", tool="send_email", decision="blocked"))
    assert f is not None
    assert f["rule"] == "RULE-008"
    assert f["severity"] == "high"
    assert f["user_id"] == "attacker"


def test_allowed_send_email_raises_nothing():
    assert rule_blocked_high_risk_tool(
        ev("tool_request", tool="send_email", decision="allow")) is None


def test_blocked_low_risk_tool_raises_nothing():
    assert rule_blocked_high_risk_tool(
        ev("tool_request", tool="search_employee", decision="blocked")) is None


def test_execute_command_deferred_to_rule_007():
    """RULE-007 owns execute_command; RULE-008 must not double-report it."""
    assert rule_blocked_high_risk_tool(
        ev("tool_request", tool="execute_command", decision="blocked")) is None


def test_blocked_burst_needs_threshold():
    few = [ev("policy_deny", decision="blocked", event_id=f"E{i}") for i in range(3)]
    assert rule_blocked_burst(few) is None
    many = [ev("policy_deny", decision="blocked", event_id=f"E{i}") for i in range(6)]
    f = rule_blocked_burst(many)
    assert f is not None and f["user_id"] == "attacker"


def test_repeated_violations_flags_session():
    events = [ev("prompt_injection", event_id=f"E{i}") for i in range(5)]
    f = rule_repeated_violations(events)
    assert f is not None
    assert f["user_id"] == "attacker"


# ── Tool chain ───────────────────────────────────────────────────────────────

def test_read_then_email_is_detected_as_exfiltration():
    session = [
        ev("tool_executed", tool="read_file", document="roadmap.txt"),
        ev("tool_request", tool="send_email"),
    ]
    chains = detect_chains(session)
    ids = {c["rule"] for c in chains}
    assert "CHAIN-READ-EXFIL" in ids
    assert all(c["user_id"] == "attacker" for c in chains)


def test_benign_tool_sequence_raises_no_chain():
    session = [
        ev("tool_executed", tool="search_employee"),
        ev("tool_executed", tool="read_file"),
    ]
    assert detect_chains(session) == []


# ── Risk scoring (regression: this module was dead code) ─────────────────────

def test_secret_access_outscores_normal_query():
    assert score_event(ev("secret_access", risk="critical", decision="blocked")) > \
           score_event(ev("query"))


def test_score_to_severity_bands():
    assert score_to_severity(0) == "low"
    assert score_to_severity(7) == "medium"
    assert score_to_severity(12) == "high"
    assert score_to_severity(99) == "critical"


def test_score_session_sums_events():
    total, sev = score_session([
        ev("secret_access", risk="critical", decision="blocked"),
        ev("prompt_injection", risk="high", decision="blocked"),
    ])
    assert total > 0
    assert sev in {"low", "medium", "high", "critical"}


# ── Correlation (regression: the user-attribution bug) ───────────────────────

def test_correlation_attributes_findings_to_real_user_not_unknown():
    """Regression test for the capital-U bug: findings whose reason said
    "User 'alice'" were bucketed as 'unknown' and merged across users."""
    events = [ev("tool_request", user="alice", tool="execute_command",
                 decision="blocked", event_id="E1")]
    findings = [
        rule_dangerous_tool(events[0]),
        {"rule": "RULE-X", "severity": "high", "user_id": "alice",
         "reason": "User 'alice' did something", "trigger_event": "E1"},
    ]
    incidents = correlate(events, findings)
    users = {i["user_id"] for i in incidents}
    assert "unknown" not in users, f"findings misattributed to 'unknown': {users}"
    assert users == {"alice"}


def test_extract_user_is_case_insensitive():
    assert _extract_user("User 'alice' requested execute_command") == "alice"
    assert _extract_user("... from user 'bob' on secure-rag") == "bob"
    assert _extract_user("no username here") == "unknown"


def test_correlation_does_not_merge_distinct_users():
    events = [ev("prompt_injection", user="alice", event_id="E1"),
              ev("prompt_injection", user="bob", event_id="E2")]
    findings = [
        {"rule": "R1", "severity": "high", "user_id": "alice",
         "reason": "x", "trigger_event": "E1"},
        {"rule": "R2", "severity": "critical", "user_id": "bob",
         "reason": "y", "trigger_event": "E2"},
    ]
    incidents = correlate(events, findings)
    assert {i["user_id"] for i in incidents} == {"alice", "bob"}


def test_correlation_dedupes_rules_fired():
    """Regression: rules_fired previously repeated the same rule ~50 times."""
    events = [ev("prompt_injection", user="attacker", event_id=f"E{i}")
              for i in range(10)]
    findings = [
        {"rule": "RULE-001", "severity": "high", "user_id": "attacker",
         "reason": "r", "trigger_event": f"E{i}"} for i in range(10)
    ]
    incidents = correlate(events, findings)
    corr = [i for i in incidents if i["type"] == "CORRELATED_INCIDENT"]
    assert corr, "expected a correlated incident"
    assert corr[0]["rules_fired"] == ["RULE-001"], "rules_fired should be deduped"


def test_correlation_propagates_application():
    """Regression: every alert previously had application=null."""
    events = [ev("prompt_injection", user="bob", app="secure-rag", event_id="E1"),
              ev("secret_access", user="bob", app="secure-rag", event_id="E2")]
    findings = [rule_prompt_injection(events[0]), rule_secret_access(events[1])]
    incidents = correlate(events, findings)
    assert incidents[0]["application"] == "secure-rag"


def test_correlation_escalates_multiple_findings():
    events = [ev("prompt_injection", user="attacker", event_id=f"E{i}")
              for i in range(4)]
    findings = [
        {"rule": f"R{i}", "severity": "high", "user_id": "attacker",
         "reason": "r", "trigger_event": f"E{i}"} for i in range(4)
    ]
    incidents = correlate(events, findings)
    assert incidents[0]["severity"] == "critical"  # high escalated by volume


# ── Anomaly ──────────────────────────────────────────────────────────────────

def test_rate_anomaly_needs_enough_samples():
    events = [ev("query", user="alice", timestamp=f"2026-09-23T{h:02d}:00:00+00:00")
              for h in range(2)]
    assert detect_rate_anomalies(events) == []


def test_rate_anomaly_flags_spike():
    events = []
    for h in range(6):                                   # quiet baseline hours
        events.append(ev("query", user="alice",
                         timestamp=f"2026-09-23T{h:02d}:00:00+00:00"))
    for i in range(300):                                 # one loud hour
        events.append(ev("query", user="alice",
                         timestamp="2026-09-23T09:00:00+00:00"))
    findings = detect_rate_anomalies(events)
    assert any(f["user_id"] == "alice" for f in findings)


# ── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed ({len(tests)} total)")
    sys.exit(1 if failed else 0)
