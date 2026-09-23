# AI Security Monitoring Lab

**Project 04 — AI Security Portfolio**

> Build an AI SOC that detects misuse, abuse, and suspicious activity across AI systems.

Covers **OWASP LLM01** (Prompt Injection), **LLM02** (Insecure Output Handling), **LLM06** (Excessive Agency).

---

## Results (real numbers — 2026-09-23)

| Metric | Result |
|---|---|
| Events processed | 874 |
| Attack scenarios | 10 |
| Detection rate | **80%** |
| False positive rate | **0%** |
| HIGH/CRITICAL alerts | 3 / 3 |
| Detection time | 0.204s |

See [`RESULTS.md`](RESULTS.md) for full breakdown and analysis.

---

## What this is

Project 04 is not a chatbot. It's an **AI Security Operations Center** — a detection pipeline that:

1. Collects events from AI applications (Secure Agent + Secure RAG from Projects 02/03)
2. Runs deterministic rule-based detection
3. Detects dangerous tool-chain patterns across a session
4. Detects behavioral anomalies (rate abuse, new users)
5. Correlates findings by user/session to escalate attack chains
6. Generates structured alerts with full event attribution
7. Visualises everything in a Streamlit dashboard

The key difference from the earlier projects:

> **Projects 02/03 stopped attacks. Project 04 detects attacks and suspicious behavior — including after they were blocked.**

---

## Architecture

```
AI SYSTEMS
    │
    ├── secure-agent    (Project 02)
    ├── secure-rag      (Project 03)
    └── chatbot

    │ telemetry (SecurityEvent JSONL)
    ▼

EVENT COLLECTOR  →  logs/events.jsonl

    │
    ▼

DETECTION ENGINE
    │
    ├── ① Rule-based       (7 rules — injection, secrets, rate, tool)
    ├── ② Tool-chain        (4 patterns — read→exfil, search→dump, etc.)
    ├── ③ Anomaly           (z-score on hourly request rates)
    └── ④ Correlation       (multi-finding → escalated incident)

    │
    ▼

ALERT ENGINE  →  logs/alerts.jsonl

    │
    ▼

STREAMLIT DASHBOARD
    ├── Overview (events/alerts timeline)
    ├── Alert list (filterable by severity)
    ├── Event log (filterable by user/type)
    └── Incident investigation (full attack chain view)
```

---

## Detection Rules

| Rule | Description | Severity |
|---|---|---|
| RULE-001 | Prompt injection detected | HIGH |
| RULE-002 | ≥5 blocked requests in 1 minute | HIGH |
| RULE-003 | Unauthorized access to sensitive document | CRITICAL |
| RULE-004 | Secret/credential access attempt | CRITICAL |
| RULE-005 | ≥30 requests in 1 minute (rate abuse) | HIGH |
| RULE-006 | >3 security violations in 5 minutes (suspicious session) | HIGH |
| RULE-007 | execute_command tool requested (any decision) | HIGH–CRITICAL |
| CHAIN-READ-EXFIL | read_file → send_email | CRITICAL |
| CHAIN-SEARCH-DUMP | search_employee → send_email | HIGH |
| CHAIN-READ-EXEC | read_file → execute_command | CRITICAL |
| ANOMALY-001 | Hourly request rate > 3σ above user mean | HIGH |
| ANOMALY-002 | Unknown user with no baseline | MEDIUM |

---

## Quick Start

```bash
pip install -r requirements.txt

# 1. Generate traffic (800 normal + 74 attack events)
python evaluation/generate_traffic.py

# 2. Run detection + get real metrics
python evaluation/replay.py

# 3. Launch dashboard
streamlit run dashboard/app.py

# 4. (Optional) run detection engine directly
python detection/engine.py
```

---

## Project Structure

```
04-ai-security-monitoring/
├── README.md
├── RESULTS.md
├── ARCHITECTURE.md
├── docs/
│   └── SCENARIO.md         Aegis AI SOC — users, apps, event types
├── collector/
│   ├── schema.py            SecurityEvent dataclass + validation
│   ├── collector.py         JSONL log writer/reader
│   └── api.py               Optional HTTP event receiver (port 8765)
├── detection/
│   ├── engine.py            Main pipeline orchestrator
│   ├── rules.py             7 deterministic rules
│   ├── tool_chain.py        4 dangerous tool-sequence patterns
│   ├── anomaly.py           z-score + new-user detection
│   ├── correlation.py       Multi-finding escalation engine
│   └── risk_scoring.py      Per-event scoring → LOW/MEDIUM/HIGH/CRITICAL
├── alerts/
│   ├── schema.py            Alert dataclass
│   └── manager.py           Persist + query alerts
├── dashboard/
│   └── app.py               Streamlit SOC dashboard
├── evaluation/
│   ├── generate_traffic.py  Synthetic normal + attack event generator
│   ├── replay.py            Full evaluation harness + metrics
│   ├── normal_traffic.json  800 normal events (generated)
│   └── attack_traffic.json  74 attack events across 10 scenarios
└── logs/
    ├── events.jsonl          (runtime — gitignored)
    └── alerts.jsonl          (runtime — gitignored)
```

---

## How Projects 02–04 connect

```
Project 02: Secure Agent
  └── security layer emits SecurityEvents
        │
        └──→ Project 04: SOC
               ├── detects blocked tool calls
               ├── correlates attack chains
               └── generates alerts

Project 03: Secure RAG
  └── security layer emits SecurityEvents
        │
        └──→ Project 04: SOC
               ├── detects unauthorized retrieval
               ├── detects secret access
               └── escalates multi-app chains
```

This is one security platform, not three independent repositories.
