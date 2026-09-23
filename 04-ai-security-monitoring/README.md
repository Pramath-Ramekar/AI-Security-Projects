# AI Security Monitoring Lab

**Project 04 — AI Security Portfolio**

> Build an AI SOC that detects misuse, abuse, and suspicious activity across AI systems.

Covers **OWASP LLM01** (Prompt Injection), **LLM02** (Insecure Output Handling), **LLM06** (Excessive Agency).

---

## Results (real numbers — 2026-09-23)

Two evaluations, because they answer different questions.

**Live** — the real hardened agent from Project 02, real attack prompts, real telemetry:

| Metric | Result |
|---|---|
| Attacks run against the real agent | 7 |
| Live telemetry events captured | 57 |
| Detection rate | **85.7%** (6/7) |
| Alerts | 3 (2 CRITICAL, 1 MEDIUM) |
| Detection time | 0.014s |

**Synthetic** — a seeded 874-event corpus for reproducible regression measurement:

| Metric | Result |
|---|---|
| Events processed | 874 (800 normal + 74 attack) |
| Detection rate | **100%** (10/10 scenarios) |
| False positive rate | **0%** |
| HIGH/CRITICAL alerts | 3 / 3 |
| Detection time | 0.234s |

Tests: **28 passed, 0 failed**.

Live figures vary between runs — the LLM is non-deterministic, and one attacker
alert fired on *unknown user* rather than an attack rule. Both caveats, and the
five bugs the evaluation surfaced, are documented in [`RESULTS.md`](RESULTS.md).

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
| RULE-008 | Blocked request for a side-effecting tool (send_email, create_file) | MEDIUM–HIGH |
| CHAIN-READ-EXFIL | read_file → send_email | CRITICAL |
| CHAIN-SEARCH-DUMP | search_employee → send_email | HIGH |
| CHAIN-READ-EXEC | read_file → execute_command | CRITICAL |
| ANOMALY-001 | Hourly request rate spike (median/MAD robust score) | HIGH–CRITICAL |
| ANOMALY-002 | Unknown user with no baseline | MEDIUM |

---

## Quick Start

```bash
pip install -r requirements.txt

# ── Live: monitor the REAL agent from Project 02 ──
# Requires ollama running with llama3.2.
# Runs real attacks through the hardened agent; its security pipeline
# emits live telemetry to the SOC, which then detects on it.
python evaluation/live_integration.py

# ── Synthetic: reproducible corpus ──
python evaluation/generate_traffic.py    # 800 normal + 74 attack events
python evaluation/replay.py              # detect + write metrics

# ── Dashboard ──
streamlit run dashboard/app.py

# ── Tests ──
python tests/test_detection.py
```

> **Warning:** `replay.py` and `live_integration.py` each **delete
> `logs/events.jsonl`** on start so their results are clean. Never run either
> during an investigation — see [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md).

---

## Project Structure

```
04-ai-security-monitoring/
├── README.md
├── RESULTS.md               Real numbers + the 5 bugs the evaluation found
├── ARCHITECTURE.md          Pipeline, telemetry bridge, design decisions
├── THREAT_MODEL.md          Threats against the SOC itself (7, honestly scored)
├── DETECTION_RULES.md       Rule catalogue + FP tuning + coverage gaps
├── INCIDENT_RESPONSE.md     validate → preserve → revoke → assess → communicate
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
│   ├── live_integration.py  Real agent + real attacks + live telemetry
│   ├── generate_traffic.py  Synthetic normal + attack event generator
│   ├── replay.py            Synthetic evaluation harness + metrics
│   ├── normal_traffic.json  800 normal events (generated)
│   └── attack_traffic.json  74 attack events across 10 scenarios
├── tests/
│   └── test_detection.py    28 tests, incl. regressions for every fixed bug
└── logs/
    ├── events.jsonl          (runtime — gitignored)
    └── alerts.jsonl          (runtime — gitignored)
```

The telemetry bridge lives in the monitored application, not here:
`03-secure-ai-agent/security/telemetry.py`

---

## How Projects 02–04 connect

```
Project 02: Secure Agent
  │
  │  audit_logger.log()  ← already fired on every policy decision
  │        │
  │        └── security/telemetry.py :: emit_audit_event()
  │                   translates audit record → SecurityEvent
  │
  └──────────────────────────→ Project 04: SOC
                                 ├── detects blocked tool calls
                                 ├── correlates attack chains
                                 └── generates alerts
```

The bridge hooks the agent's existing audit choke point, so no call site in
Project 02 changed. It fails silently by design — monitoring going down must
not become an agent outage — and honours `AEGIS_TELEMETRY=0` as a kill switch.

Live telemetry is tagged `"source": "live"` to distinguish it from replayed
synthetic fixtures sharing the same log.

**Status:** Project 02 is wired and verified end-to-end. Project 03 (Secure
RAG) emits the same schema and is covered by the rules, but its bridge is not
yet installed — its events in the corpus are synthetic.

This is one security platform, not three independent repositories.
