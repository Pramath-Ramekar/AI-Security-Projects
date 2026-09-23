# Incident Response Playbook

Aegis AI SOC — response procedure for AI security alerts.

The workflow is: **validate → preserve evidence → revoke access → assess
exposure → communicate impact.**

---

## 0. Triage — is this worth working?

Open the alert in the dashboard (`Incident Detail` view). Every alert carries
the full event chain that produced it, not just the triggering event.

| Severity | Response time | Action |
|---|---|---|
| CRITICAL | Immediate | Page on-call. Assume compromise until disproven. |
| HIGH | Within 1 hour | Investigate before end of shift. |
| MEDIUM | Within 1 business day | Batch with other MEDIUMs. |
| LOW | Best effort | Review during weekly tuning. |

**Escalate to CRITICAL regardless of stated severity if any of:**
- `RULE-004` fired (secret access)
- Any `CHAIN-*` rule fired (tool chaining)
- `decision == "executed"` on a HIGH or CRITICAL tool
- The same user appears across multiple applications in one window

---

## 1. Validate the alert

Before acting, confirm the alert is real. The cost of revoking a legitimate
user's access is not zero.

```bash
# What exactly did this user do?
python -c "
from collector.collector import load_events
for e in load_events(user_id='USER'):
    print(e['timestamp'], e['event_type'], e.get('tool'), e['decision'])
"
```

Ask:
- **Was the action blocked?** A blocked attempt is an attacker signal but not
  a breach. Note the distinction in the ticket — it changes the response.
- **Is the source IP consistent with this user's history?**
- **Does the `session_id` contain other, benign activity?** A compromised
  session usually has legitimate traffic around the attack.
- **Is there a business explanation?** Check with the user's manager before
  revoking, for HIGH and below.

**If false positive:** record it in `DETECTION_RULES.md` under known FP
sources, tune the threshold, and add a regression test. Do not silently
suppress the rule.

---

## 2. Preserve evidence

**Do this before revoking anything.** Revocation can change agent behaviour and
truncate the log.

```bash
# Snapshot the raw logs. Use a fixed timestamp, not "now", for reproducibility.
mkdir -p incidents/INC-001
cp logs/events.jsonl        incidents/INC-001/events.jsonl
cp logs/alerts.jsonl        incidents/INC-001/alerts.jsonl
cp ../03-secure-ai-agent/logs/audit.jsonl incidents/INC-001/agent-audit.jsonl
```

Record in the ticket:
- Alert ID, `user_id`, `session_id`, `application`
- Full event chain with timestamps (copy from the Incident Detail view)
- Which rules fired and the incident's risk score
- Whether each action was `blocked` or `executed`

**Preserve, do not clean.** `evaluation/replay.py` and
`evaluation/live_integration.py` both **delete `logs/events.jsonl`** on start.
Never run either during an active investigation.

---

## 3. Revoke access

Match the revocation to what was actually reachable.

### Scope the blast radius first

| What the alert shows | Revoke |
|---|---|
| Blocked attempts only | Nothing yet — monitor, raise user's review flag |
| Tool executed at MEDIUM | That tool for that role |
| Tool executed at HIGH/CRITICAL | All agent access for the user |
| Secret access or chain executed | All agent access, org-wide kill switch |

### Emergency kill switch

Project 02 ships a global revocation that zeroes every tool for every user:

```python
# From 03-secure-ai-agent/
from security.tool_registry import revoke_all, restore_access
revoke_all()       # policy engine now denies before any other check
# ... investigate ...
restore_access()   # only after the incident is closed
```

`revoke_all()` is checked at **step 0** of the policy engine, before role
checks. It is the correct first action for a confirmed active compromise.

### Per-user revocation

Narrow the user's role in `security/tool_registry.py` (`allowed_roles`) and
restart the agent. Verify by re-running the triggering prompt and confirming a
`POLICY_DENY` in the audit log.

---

## 4. Assess exposure

The question is **what data actually left**, not what was attempted.

```bash
# Did anything execute, or was it all blocked?
python -c "
from collector.collector import load_events
ex = [e for e in load_events(user_id='USER') if e['decision'] == 'executed']
print(f'{len(ex)} executed actions')
for e in ex: print(' ', e['timestamp'], e['event_type'], e.get('tool'), e.get('document'))
"
```

| Finding | Exposure |
|---|---|
| All events `blocked` | **None.** Controls held. Attacker signal only. |
| `read_file` executed | Contents of that file reached the model context |
| `send_email` executed | **Data left the boundary.** Check `data/mailbox/sent/` for recipient and body. |
| `execute_command` executed | Assume host compromise. Escalate to infrastructure IR. |
| `secret_access` executed | **Rotate the credentials immediately.** Do not wait for the investigation to close. |

**A read that reached the model context is exposure even if nothing was sent.**
The content entered a system that may log, cache, or leak it through a later
response.

---

## 5. Communicate impact

Write for the audience, and lead with whether data left.

### Executive summary template

```
INCIDENT:   INC-001 — <one line, plain language>
DETECTED:   <timestamp> by <rule IDs>
SEVERITY:   <CRITICAL|HIGH|MEDIUM|LOW>
STATUS:     <contained | investigating | closed>

WHAT HAPPENED
<2–3 sentences. Name the capability abused, not the rule ID.>

DATA EXPOSURE
<"No data left the environment — all N attempts were blocked by policy."
 or "The following data was accessed: ...">

ACTIONS TAKEN
· <revocation, rotation, role change>

REMAINING RISK
<what is still open, and who owns it>
```

### Rules for the write-up

- **Lead with exposure.** "No data left the environment" is the first thing a
  reader needs. Do not bury it under the attack narrative.
- **Distinguish attempted from achieved.** "An employee's account attempted to
  email a confidential document externally; the policy engine blocked it" is a
  very different sentence from "...and the email was sent."
- **Name the control that worked.** Detection alone is not a good outcome; say
  which layer held.
- **Do not paste rule IDs at executives.** `RULE-004` means nothing outside
  this repo. "An attempt to read stored credentials" does.
- **If you do not know, say so.** An honest "we are still determining whether
  the file contents were transmitted" beats a confident wrong answer.

---

## Worked example — CHAIN-001

Drawn from the synthetic corpus (`evaluation/attack_traffic.json`).

**Alert:** CRITICAL, user `attacker`, application `secure-agent`, risk score 516
**Rules fired:** `RULE-001`, `RULE-004`, `RULE-006`, `RULE-007`,
`CHAIN-READ-EXFIL`, `CHAIN-MULTI-READ-EXFIL`, `RULE-002`, `RULE-003`, `RULE-003b`

**Event chain:**
```
prompt_injection        blocked
unauthorized_retrieval  flagged   documents/project_roadmap.txt
secret_access           blocked   data/employee_db/employees.json
tool_request            blocked   send_email
chain_blocked           blocked   send_email
```

**1. Validate** — Five escalating events in one session, from `10.99.0.1`,
which has no history for any legitimate user. Real.

**2. Preserve** — Snapshot both logs before touching anything.

**3. Revoke** — `secret_access` fired, so this qualifies for the kill switch:
`revoke_all()`, then narrow `attacker`'s role.

**4. Assess** — Every `decision` is `blocked` or `flagged`; none is `executed`.
**No data left the environment.** The roadmap retrieval was flagged, so treat
its contents as having reached the model context and note it.

**5. Communicate:**

> An external account attempted a five-step attack against the internal AI
> assistant: a prompt-injection attempt, followed by access attempts against
> the project roadmap and the employee database, followed by an attempt to
> email the results outside the company.
>
> **No data left the environment.** Every step was blocked by the agent's
> policy engine and tool-chain monitor. The SOC correlated all five events
> into a single critical incident within 0.2 seconds of the final action.
>
> Actions taken: agent access revoked org-wide pending review; source IP
> blocked; account disabled.
>
> Remaining risk: the roadmap document was reached for and its contents may
> have entered the model's working context before the send was blocked.
> Treat its contents as internally exposed, not externally disclosed.
