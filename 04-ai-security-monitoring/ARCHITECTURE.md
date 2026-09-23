# Architecture

## End-to-end flow

```
┌──────────────────────────────────────────────────────────────┐
│  MONITORED AI SYSTEMS                                        │
│                                                              │
│   secure-agent          secure-rag           chatbot         │
│   (Project 02)          (Project 03)                         │
│        │                     │                   │           │
│        │ audit_logger.log()  │                   │           │
│        ▼                     ▼                   ▼           │
│   telemetry.py  ──────────────────────────────────           │
│   emit_audit_event()                                         │
└────────────────────────┬─────────────────────────────────────┘
                         │  SecurityEvent (common schema)
                         ▼
              ┌─────────────────────┐
              │  EVENT COLLECTOR    │   file append (default)
              │  collector/         │   or POST /events (api.py)
              └──────────┬──────────┘
                         ▼
                  logs/events.jsonl
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  DETECTION ENGINE          detection/engine.py               │
│                                                              │
│   group events by session                                    │
│        │                                                     │
│        ├─► ① rules.py        7 deterministic rules           │
│        ├─► ② tool_chain.py   4 dangerous tool sequences      │
│        ├─► ③ anomaly.py      median/MAD rate outliers        │
│        │                                                     │
│        └─► findings[]  (each carries user_id + application)  │
│                    │                                         │
│                    ▼                                         │
│            ④ correlation.py                                  │
│               group by user → escalate on volume             │
│               risk_scoring.py scores the underlying events   │
│               final severity = max(escalation, risk band)    │
└────────────────────────┬─────────────────────────────────────┘
                         ▼  incidents[]
              ┌─────────────────────┐
              │  ALERT ENGINE       │   MEDIUM and above
              │  alerts/manager.py  │
              └──────────┬──────────┘
                         ▼
                  logs/alerts.jsonl
                         │
                         ▼
              ┌─────────────────────┐
              │  STREAMLIT DASHBOARD│
              │  dashboard/app.py   │
              │  · Overview         │
              │  · Alerts           │
              │  · Events           │
              │  · Incident Detail  │
              └─────────────────────┘
```

---

## Telemetry integration (Steps 4 & 5)

The bridge lives in the **monitored application**, not in the SOC:

`03-secure-ai-agent/security/telemetry.py`

`audit_logger.log()` already fired on every policy decision the hardened agent
made. The bridge hooks that single choke point and translates each audit
record into the SOC's `SecurityEvent` schema:

| Agent audit event | SOC event_type | Default risk |
|---|---|---|
| `USER_REQUEST` | `query` | low |
| `TOOL_REQUEST` | `tool_request` | tool's own tier |
| `POLICY_DENY` | `policy_deny` | tool's own tier |
| `VALIDATION_FAIL` | `validation_fail` | high |
| `CHAIN_BLOCKED` | `chain_blocked` | critical |
| `TOOL_EXECUTED` | `tool_executed` | tool's own tier |
| `APPROVAL_DENIED` | `approval_denied` | high |
| `AGENT_RESPONSE` | `agent_response` | low |

Two rules govern the translation:

1. **A tool's own risk tier outranks the event's default risk.** A
   `TOOL_REQUEST` is normally low-risk, but `execute_command` is CRITICAL
   regardless of which event carried it.
2. **Sensitive targets re-type the event.** A `read_file` whose arguments
   mention `employees.json`, `secrets`, `compensation`, `salary`, or
   `password` is emitted as `secret_access` at CRITICAL, not as a routine read.

### Design constraints

- **Telemetry never breaks the agent.** Every emit path is wrapped in a bare
  `except: pass`. The agent's security pipeline must not depend on the SOC
  being reachable — monitoring going down must not become an outage.
- **Transport is file-append by default.** Set `AEGIS_SOC_URL` to POST to a
  running collector instead. File-append needs no server for the demo.
- **Kill switch.** `AEGIS_TELEMETRY=0` disables emission entirely.
- **Live events are labelled.** Real telemetry carries `"source": "live"`,
  which distinguishes it from replayed synthetic fixtures in the same log.

---

## Why correlation groups by user, not by session

An early version derived the username by regex-matching the finding's prose
reason (`user '([^']+)'`). Rules wrote both `"user 'bob'"` and `"User 'alice'"`,
so the case-sensitive pattern silently failed on half of them and bucketed
those findings under `"unknown"` — merging unrelated users into one bogus
incident and suppressing real alerts.

Findings now carry `user_id` and `application` as structured fields. The regex
survives only as a fallback and is case-insensitive. `tests/test_detection.py`
pins this behaviour with three regression tests.

**Rule for this codebase: never parse identity back out of a display string.**

---

## Severity: two independent signals

An incident's final severity is the harsher of:

1. **Escalation by volume** — 2+ high/critical findings for one user bumps
   severity one band; 4+ bumps it two.
2. **Risk score band** — `risk_scoring.py` sums per-event scores across the
   incident's underlying events and maps the total to a band
   (0–4 LOW, 5–9 MEDIUM, 10–14 HIGH, 15+ CRITICAL).

Volume alone would miss a single catastrophic event. Score alone would miss a
slow campaign of individually-cheap actions. Taking the max catches both.

---

## Component reference

| Path | Responsibility |
|---|---|
| `collector/schema.py` | `SecurityEvent` dataclass, field validation, prompt hashing |
| `collector/collector.py` | JSONL append/read, filtering |
| `collector/api.py` | Optional HTTP receiver on port 8765 |
| `detection/rules.py` | 7 deterministic rules |
| `detection/tool_chain.py` | 4 dangerous tool-sequence patterns |
| `detection/anomaly.py` | Median/MAD rate outliers, unknown-user detection |
| `detection/correlation.py` | Group by user, escalate, dedupe, apply risk score |
| `detection/risk_scoring.py` | Per-event scores → severity bands |
| `detection/engine.py` | Pipeline orchestrator |
| `alerts/schema.py` | `Alert` dataclass |
| `alerts/manager.py` | Persist, filter, and count alerts |
| `dashboard/app.py` | Streamlit SOC UI (4 views) |
| `evaluation/generate_traffic.py` | Synthetic normal + attack fixtures |
| `evaluation/replay.py` | Synthetic replay + metrics |
| `evaluation/live_integration.py` | Real agent + real attacks + live telemetry |
| `tests/test_detection.py` | 24 tests incl. regressions for all fixed bugs |
