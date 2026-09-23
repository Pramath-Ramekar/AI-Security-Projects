"""
Generate synthetic normal and attack traffic for the Aegis AI SOC.
Writes:
  evaluation/normal_traffic.json
  evaluation/attack_traffic.json
  And injects both into the collector (logs/events.jsonl).

Usage: python evaluation/generate_traffic.py
"""
import json
import sys
import uuid
import random
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))
from collector.schema import make_event
from collector.collector import collect_batch

SEED = 42
random.seed(SEED)

BASE_TIME = datetime(2026, 9, 23, 8, 0, 0, tzinfo=timezone.utc)

NORMAL_USERS = ["alice", "bob", "charlie", "admin"]
APPS = ["secure-agent", "secure-rag", "chatbot"]

# Normal query templates per application
NORMAL_QUERIES = {
    "secure-rag": [
        ("query", "low", "allow", None, "hr/leave_policy"),
        ("query", "low", "allow", None, "hr/employee_handbook"),
        ("query", "low", "allow", None, "engineering/api_documentation"),
        ("query", "low", "allow", None, "finance/travel_expense_policy"),
        ("query", "low", "allow", None, "engineering/deployment_policy"),
        ("query", "low", "allow", None, "hr/remote_work_policy"),
    ],
    "secure-agent": [
        ("tool_request", "low", "allow", "search_employee", None),
        ("tool_executed", "low", "executed", "search_employee", None),
        ("tool_request", "medium", "allow", "read_file", "documents/project_roadmap.txt"),
        ("tool_executed", "medium", "executed", "read_file", "documents/project_roadmap.txt"),
        ("query", "low", "allow", None, None),
        ("agent_response", "low", "allow", None, None),
    ],
    "chatbot": [
        ("query", "low", "allow", None, None),
        ("agent_response", "low", "allow", None, None),
    ],
}

# Attack scenarios
ATTACK_SCENARIOS = [
    # Direct prompt injection
    {
        "label": "DPI-001: direct injection — exfiltrate employee DB",
        "user": "attacker",
        "app": "secure-agent",
        "events": [
            ("prompt_injection", "high", "blocked", None, None),
            ("policy_deny", "high", "blocked", "send_email", None),
        ],
    },
    {
        "label": "DPI-003: command injection",
        "user": "attacker",
        "app": "secure-agent",
        "events": [
            ("prompt_injection", "high", "blocked", None, None),
            ("policy_deny", "critical", "blocked", "execute_command", None),
        ],
    },
    {
        "label": "DPI-005: tool chain read→exfil",
        "user": "attacker",
        "app": "secure-agent",
        "events": [
            ("tool_request", "medium", "allow", "read_file", "documents/project_roadmap.txt"),
            ("tool_executed", "medium", "executed", "read_file", "documents/project_roadmap.txt"),
            ("suspicious_tool_chain", "high", "blocked", "send_email", None),
            ("chain_blocked", "high", "blocked", "send_email", None),
        ],
    },
    # Indirect injection
    {
        "label": "IPI-001: malicious document injection",
        "user": "bob",
        "app": "secure-rag",
        "events": [
            ("query", "low", "allow", None, "documents/malicious_document.txt"),
            ("unauthorized_retrieval", "high", "flagged", None, "documents/malicious_document.txt"),
            ("prompt_injection", "high", "blocked", None, None),
        ],
    },
    # Excessive agency
    {
        "label": "EA-001: vague cleanup → destructive command",
        "user": "alice",
        "app": "secure-agent",
        "events": [
            ("tool_request", "critical", "blocked", "execute_command", None),
            ("policy_deny", "critical", "blocked", "execute_command", None),
        ],
    },
    {
        "label": "EA-002: mass email broadcast",
        "user": "alice",
        "app": "secure-agent",
        "events": [
            ("tool_request", "high", "blocked", "send_email", None),
            ("policy_deny", "high", "blocked", "send_email", None),
        ],
    },
    # Secret/PII access
    {
        "label": "RAG-001: secret extraction attempt",
        "user": "attacker",
        "app": "secure-rag",
        "events": [
            ("secret_access", "critical", "blocked", None, "data/secrets/fake_secrets.txt"),
            ("unauthorized_retrieval", "high", "blocked", None, "data/secrets/fake_secrets.txt"),
        ],
    },
    {
        "label": "RAG-002: salary/compensation PII query",
        "user": "attacker",
        "app": "secure-rag",
        "events": [
            ("pii_request", "medium", "flagged", None, "finance/compensation"),
            ("unauthorized_retrieval", "high", "blocked", None, "finance/compensation"),
        ],
    },
    # Brute force / rate abuse
    {
        "label": "ABUSE-001: attacker rate abuse (50 rapid injections)",
        "user": "attacker",
        "app": "secure-agent",
        "events": [("prompt_injection", "high", "blocked", None, None)] * 50,
        "rapid": True,
    },
    # Correlated multi-step attack
    {
        "label": "CHAIN-001: full exfiltration chain",
        "user": "attacker",
        "app": "secure-agent",
        "events": [
            ("prompt_injection", "high", "blocked", None, None),
            ("unauthorized_retrieval", "high", "flagged", None, "documents/project_roadmap.txt"),
            ("secret_access", "critical", "blocked", None, "data/employee_db/employees.json"),
            ("tool_request", "high", "blocked", "send_email", None),
            ("chain_blocked", "critical", "blocked", "send_email", None),
        ],
    },
]


def _ts(offset_minutes: float) -> str:
    return (BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def generate_normal(count: int = 800) -> list[dict]:
    events = []
    minute = 0.0
    for i in range(count):
        user = random.choice(NORMAL_USERS)
        app = random.choice(APPS)
        options = NORMAL_QUERIES[app]
        ev_type, risk, decision, tool, doc = random.choice(options)
        sess = f"sess-{uuid.uuid4().hex[:8]}"
        ev = make_event(
            application=app,
            event_type=ev_type,
            user_id=user,
            risk=risk,
            decision=decision,
            session_id=sess,
            tool=tool,
            document=doc,
            source_ip=f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
        )
        d = ev.to_dict()
        d["timestamp"] = _ts(minute)
        d["label"] = "normal"
        events.append(d)
        minute += random.uniform(0.1, 0.8)
    return events


def generate_attacks() -> list[dict]:
    events = []
    minute = 30.0  # attacks start 30 min into the day
    for scenario in ATTACK_SCENARIOS:
        sess = f"sess-{uuid.uuid4().hex[:8]}"
        rapid = scenario.get("rapid", False)
        step_gap = 0.02 if rapid else random.uniform(0.5, 2.0)
        for ev_type, risk, decision, tool, doc in scenario["events"]:
            ev = make_event(
                application=scenario["app"],
                event_type=ev_type,
                user_id=scenario["user"],
                risk=risk,
                decision=decision,
                session_id=sess,
                tool=tool,
                document=doc,
                source_ip="10.99.0.1" if scenario["user"] == "attacker" else f"10.0.0.{random.randint(2,20)}",
            )
            d = ev.to_dict()
            d["timestamp"] = _ts(minute)
            d["label"] = "attack"
            d["scenario"] = scenario["label"]
            events.append(d)
            minute += step_gap
        minute += random.uniform(3.0, 8.0)  # gap between scenarios
    return events


def main():
    out_dir = Path(__file__).parent
    print("Generating normal traffic...")
    normal = generate_normal(800)
    (out_dir / "normal_traffic.json").write_text(json.dumps(normal, indent=2))
    print(f"  {len(normal)} normal events written")

    print("Generating attack traffic...")
    attacks = generate_attacks()
    (out_dir / "attack_traffic.json").write_text(json.dumps(attacks, indent=2))
    print(f"  {len(attacks)} attack events written")

    print("Injecting all events into collector...")
    all_events = normal + attacks
    all_events.sort(key=lambda e: e["timestamp"])
    n = collect_batch(all_events)
    print(f"  {n} events written to logs/events.jsonl")
    print("Done.")


if __name__ == "__main__":
    main()
