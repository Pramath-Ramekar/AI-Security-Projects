# Threat Model — Aegis AI SOC

The system being threat-modelled here is **the monitoring pipeline itself**,
not the AI applications it watches. Those have their own threat models in
Projects 02 and 03.

A SOC is a security control, and security controls are targets.

---

## Assets

| Asset | Why an attacker wants it |
|---|---|
| `logs/events.jsonl` | The record of what they did. Deleting or corrupting it destroys attribution. |
| `logs/alerts.jsonl` | Evidence of detection. Suppressing it buys dwell time. |
| Detection rules and thresholds | Knowing the thresholds tells an attacker exactly how slow to go. |
| The dashboard | Shows which of their actions were seen. |
| Telemetry bridge config | `AEGIS_TELEMETRY=0` blinds the SOC to one application entirely. |

---

## Trust boundary

```
UNTRUSTED
─────────────────────────────────────────────
  Event contents — user_id, tool, document,
  details. All ultimately shaped by whoever
  is talking to the monitored application.

══════════ SOC TRUST BOUNDARY ══════════

TRUSTED
─────────────────────────────────────────────
  Detection rules, thresholds
  Correlation and scoring logic
  Alert store
```

**Events are untrusted input.** An attacker who controls a prompt partially
controls what appears in the telemetry derived from it. Detection logic must
never execute, interpolate, or trust event fields.

---

## Threats

### T1 — Telemetry suppression
**Attacker disables the bridge and operates unseen.**

`AEGIS_TELEMETRY=0` or an unwritable SOC log silences emission. The bridge
fails silently by design — that property protects the agent's availability but
means the SOC cannot distinguish "no attacks" from "no telemetry".

*Present state:* **Not mitigated.** There is no heartbeat, so a silent
application looks identical to a quiet one.
*Mitigation:* emit a periodic heartbeat per application; alert on its absence.

---

### T2 — Log tampering
**Attacker edits or truncates `events.jsonl` to erase their trail.**

The log is a plain appendable file with filesystem permissions only.

*Present state:* **Not mitigated.** Anyone who can run the agent can rewrite
the log.
*Mitigation:* append-only storage, off-host shipping, or hash-chained records.
`INCIDENT_RESPONSE.md` requires snapshotting logs before any remediation, which
reduces but does not remove the exposure.

---

### T3 — Threshold evasion (low and slow)
**Attacker paces below every threshold.**

Every rule has a published number: 5 blocked/min, 30 req/min, >3 violations/5min,
3.0 robust-σ. An attacker who reads `DETECTION_RULES.md` knows exactly how slow
to go.

*Present state:* **Partially mitigated.** Rate-based rules are evadable by
pacing. Content-based rules (RULE-001, -003, -004, -007, -008) are not — they
fire on a single event regardless of timing, and the tool-chain patterns match
on sequence rather than rate.
*Residual risk:* accepted. Publishing thresholds makes them tunable and
arguable; hiding them would be security through obscurity and would not stop a
patient attacker who can simply probe for the edges.

---

### T4 — Alert fatigue as a cover
**Attacker floods the SOC with noise, then acts inside it.**

*Present state:* **Partially mitigated.** Correlation collapses one user's
events into a single incident — the synthetic run folds 66 events into one
alert — so volume alone does not multiply alerts. The alert floor is MEDIUM.
*Residual risk:* a distributed flood across many user IDs would still produce
many incidents.

---

### T5 — Log injection via event content
**Attacker crafts a prompt so the derived event text forges a log line or
breaks the dashboard.**

*Present state:* **Mitigated.** Events are written with `json.dumps()`, which
escapes newlines and quotes, so a forged record cannot be injected. The
dashboard renders event fields through Streamlit's text APIs.
*Caveat:* the dashboard sets `unsafe_allow_html=True` for severity colouring.
That path renders only fixed CSS class names chosen from a lookup, never event
content — but it is the place a future edit could introduce XSS. Any change
there needs review.

---

### T6 — Identity spoofing in telemetry
**Attacker causes events to be attributed to another user.**

`user_id` comes from the agent's session, not from the prompt, so a user cannot
relabel themselves by asking. But the bridge trusts whatever the calling
application passes.

*Present state:* **Mitigated within the agent**, since the caller supplies the
authenticated user. **Not mitigated for the HTTP collector** — `api.py` accepts
any well-formed POST with no authentication, so anyone who can reach port 8765
can inject arbitrary events attributed to anyone.
*Mitigation:* the HTTP collector is a lab convenience. Do not expose it. Any
real deployment needs authentication and per-application credentials.

---

### T7 — Detection blind spots
**Attacks that produce no telemetry cannot be detected.**

If the model refuses a prompt without proposing a tool call, the agent emits a
`query` and an `agent_response` and nothing else. There is no attack-shaped
signal. Observed live as IPI-001 — see `RESULTS.md`.

*Present state:* **Not mitigated.** The SOC only sees what the application
reports, and the application reports decisions, not intent.
*Mitigation:* would require the monitored application to classify and emit
injection attempts even when it refuses them — a change in Projects 02/03, not
here.

---

## Summary

| ID | Threat | State |
|---|---|---|
| T1 | Telemetry suppression | Not mitigated — no heartbeat |
| T2 | Log tampering | Not mitigated — plain file |
| T3 | Threshold evasion | Partial — content rules hold, rate rules evadable |
| T4 | Alert fatigue | Partial — correlation caps per-user volume |
| T5 | Log injection | Mitigated — JSON encoding |
| T6 | Identity spoofing | Mitigated in-agent; **HTTP collector unauthenticated** |
| T7 | Blind spots | Not mitigated — needs upstream change |

**The honest summary:** this is a lab SOC. Its detection logic is sound and
tested, but its evidence store is a writable flat file and its HTTP ingest is
unauthenticated. It is built to demonstrate detection engineering, not to
withstand an attacker who already has host access. T1, T2 and T6 are the gaps
that would have to close first for any real deployment.
