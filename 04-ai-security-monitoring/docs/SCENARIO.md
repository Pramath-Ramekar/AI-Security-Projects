# Aegis AI — Security Operations Center

**Project 04 — AI Security Monitoring & Detection Lab**

---

## The fictional company

**Aegis AI** is an enterprise software company that has deployed three AI systems for internal employee use. All three were built and hardened in earlier portfolio projects.

---

## Monitored applications

| Application | Project | Description |
|---|---|---|
| `secure-agent` | Project 02 | Tool-using autonomous agent — file access, email, shell commands |
| `secure-rag` | Project 03 | RAG chatbot over internal documents — HR, finance, engineering |
| `chatbot` | — | General-purpose internal helpdesk chatbot |

Each application emits structured events to the Aegis AI SOC. The SOC's job is to detect attacks and suspicious behavior that the per-application security controls may have blocked, flagged, or missed — and to correlate events across applications to surface attack chains invisible to any single system.

---

## Users

| User | Role | Expected behavior |
|---|---|---|
| `alice` | employee | Regular document queries, moderate volume |
| `bob` | employee | Engineering document access, tool use |
| `charlie` | manager | Finance and HR document access |
| `admin` | admin | Full tool access, system administration |
| `attacker` | (external / compromised) | Injection, enumeration, exfiltration attempts |

---

## Event types monitored

| Event type | Description | Default risk |
|---|---|---|
| `query` | Normal user query to any application | LOW |
| `tool_request` | Agent tool invocation proposed by LLM | LOW–HIGH |
| `tool_executed` | Tool ran successfully | varies |
| `tool_blocked` | Tool call denied by security layer | MEDIUM–HIGH |
| `prompt_injection` | Injection pattern detected in input | HIGH |
| `unauthorized_retrieval` | Document accessed outside user's clearance | HIGH |
| `pii_request` | Query targeting personal/sensitive data | MEDIUM |
| `secret_access` | Query or retrieval targeting credentials or secrets | CRITICAL |
| `suspicious_tool_chain` | Dangerous tool sequence detected | HIGH–CRITICAL |
| `rate_abuse` | Excessive request rate from a single user/session | MEDIUM |

---

## What the SOC does NOT do

- It does not replace per-application security controls — those remain the first line of defence.
- It does not block requests in real time (this lab is detection-first, not inline enforcement).
- It does not store raw prompts or PII — only hashes and metadata.

---

## Detection goals

1. **Detect attacks that were blocked** — confirm the block, escalate if repeated.
2. **Detect attack chains** — correlate events across tools and applications that individually look low-risk but together signal exfiltration or escalation.
3. **Detect behavioral anomalies** — usage patterns that deviate from established baselines for a user or session.
4. **Generate actionable alerts** — every alert explains the full event sequence that triggered it, not just a single event.
