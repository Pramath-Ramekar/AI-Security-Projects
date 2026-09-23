# Detection Rules

Every rule below is implemented in `detection/` and covered by
`tests/test_detection.py`. Thresholds are **this lab's chosen policy**, not
industry standards — they are stated here so they can be argued with and tuned.

---

## Rule catalogue

### RULE-001 — Prompt Injection Detected
| | |
|---|---|
| **Fires when** | `event_type == "prompt_injection"` |
| **Severity** | HIGH |
| **Source** | `rules.py :: rule_prompt_injection` |
| **Rationale** | The monitored application already classified this input as an injection attempt. The SOC records it regardless of whether the app blocked it, because a blocked attempt is still an attacker signal. |

### RULE-002 — Blocked Request Burst
| | |
|---|---|
| **Fires when** | ≥ 5 events with `decision == "blocked"` in a 1-minute window, same session |
| **Severity** | HIGH |
| **Source** | `rules.py :: rule_blocked_burst` |
| **Rationale** | One block is a mistake or a policy edge. Five in a minute is someone probing for a gap. |
| **Tuning** | Lower to 3 for high-assurance environments; raise to 10 if a legitimate workflow trips policy repeatedly. |

### RULE-003 / RULE-003b — Unauthorized Retrieval
| | |
|---|---|
| **Fires when** | `event_type == "unauthorized_retrieval"` |
| **Severity** | CRITICAL if the document path matches a sensitive marker, otherwise HIGH |
| **Sensitive markers** | `compensation`, `secrets`, `employees`, `salary`, `password` |
| **Source** | `rules.py :: rule_sensitive_unauthorized` |
| **Rationale** | Access-control already denied the request. Severity is driven by what was reached for, not by whether it succeeded — intent matters for triage. |

### RULE-004 — Secret Access Attempt
| | |
|---|---|
| **Fires when** | `event_type == "secret_access"` |
| **Severity** | CRITICAL |
| **Source** | `rules.py :: rule_secret_access` |
| **Rationale** | No legitimate user workflow reads credential stores through an AI assistant. Zero tolerance; always page. |

### RULE-005 — High Request Rate
| | |
|---|---|
| **Fires when** | ≥ 30 events from one user in a 1-minute sliding window |
| **Severity** | HIGH |
| **Source** | `rules.py :: rule_high_rate` |
| **Rationale** | Human interaction with an AI assistant does not sustain 30 requests/minute. This is automation. |
| **Tuning** | Raise for service accounts and batch jobs — they should be allowlisted rather than have the global threshold relaxed. |

### RULE-006 — Suspicious Session (Repeated Violations)
| | |
|---|---|
| **Fires when** | > 3 security violations in one session within 5 minutes |
| **Counts as violation** | `prompt_injection`, `unauthorized_retrieval`, `secret_access`, `policy_deny`, `chain_blocked`, `validation_fail` |
| **Severity** | HIGH |
| **Source** | `rules.py :: rule_repeated_violations` |
| **Rationale** | Catches an attacker rephrasing. Individually the prompts look different; the pattern of *persisting after refusal* is the signal. |

### RULE-007 — Dangerous Tool Access
| | |
|---|---|
| **Fires when** | Any event whose `tool == "execute_command"` |
| **Severity** | CRITICAL if executed or allowed, HIGH if blocked |
| **Source** | `rules.py :: rule_dangerous_tool` |
| **Rationale** | Arbitrary command execution is the highest-blast-radius capability in the agent. Every request is worth a record, even a denied one. |

---

## Tool-chain patterns

Individually-permitted tools that are dangerous *in sequence*. All in
`detection/tool_chain.py`, matched within a sliding window of recent tool
events per session.

| ID | Sequence | Severity | Why |
|---|---|---|---|
| `CHAIN-READ-EXFIL` | `read_file` → `send_email` | CRITICAL | Read plus external send is an exfiltration pipeline |
| `CHAIN-MULTI-READ-EXFIL` | `read_file` → `read_file` → `send_email` | CRITICAL | Bulk collection before exfiltration |
| `CHAIN-SEARCH-DUMP` | `search_employee` → `send_email` | HIGH | Directory enumeration then mass send |
| `CHAIN-READ-EXEC` | `read_file` → `execute_command` | CRITICAL | Reconnaissance then execution |

Per-tool analysis cannot see these. `read_file` is MEDIUM and `send_email` is
HIGH, but neither alone justifies a CRITICAL alert — the *composition* does.

---

## Anomaly detection

### ANOMALY-001 — Anomalous Request Rate

Uses a **median/MAD robust score**, not a plain z-score.

A plain z-score is unusable for spike detection: a single large outlier
inflates the standard deviation it is being measured against, so the biggest
spikes hide themselves. With hourly rates `[1,1,1,1,1,1,300]` the spike scores
only **2.3σ** and never trips a 3σ threshold. Median and MAD are unaffected by
the outlier.

```
score = 0.6745 × (peak − median) / MAD      when MAD > 0
```

When MAD is 0 — more than half the hours are identical, common for low-volume
users — no dispersion estimate exists, so a ratio-vs-floor test is used
instead: fire when `peak ≥ max(median × 5, median + 20)`. The absolute floor
stops a quiet user going from 1 to 5 requests being reported as an anomaly.

**Severity:** HIGH below 5, CRITICAL at 5 and above.
**Minimum samples:** 3 hourly buckets. Below that, no baseline exists and the
rule stays silent.

### ANOMALY-002 — Unknown User Activity
Fires when a user with no established baseline appears. MEDIUM severity —
informational, since new employees are also new users.

---

## Risk scoring

`detection/risk_scoring.py`. Each event scores
`base(event_type) + risk_modifier + decision_modifier`.

| Event type | Base | | Risk | Mod | | Decision | Mod |
|---|---:|---|---|---:|---|---|---:|
| `query`, `agent_response` | 0 | | low | 0 | | allow | 0 |
| `tool_request`, `tool_executed` | 1 | | medium | 1 | | executed | 0 |
| `approval_requested` | 2 | | high | 2 | | pending | 0 |
| `validation_fail`, `approval_denied` | 3 | | critical | 3 | | blocked | 1 |
| `pii_request`, `policy_deny`, `tool_blocked`, `rate_abuse` | 4 | | | | | flagged | 1 |
| `prompt_injection` | 5 | | | | | | |
| `unauthorized_retrieval` | 7 | | | | | | |
| `chain_blocked`, `suspicious_tool_chain` | 8 | | | | | | |
| `secret_access` | 10 | | | | | | |

**Bands:** 0–4 LOW · 5–9 MEDIUM · 10–14 HIGH · 15+ CRITICAL

An incident's score is the sum across its underlying events. Final severity is
the harsher of the risk band and the volume-based escalation.

---

## False-positive tuning

Measured FPR on the synthetic corpus is **0.0%** against 800 normal events.
That number is only as good as the corpus, so the known pressure points:

| Tuning knob | Current | Raising it | Lowering it |
|---|---|---|---|
| RULE-002 blocked burst | 5 / min | Fewer alerts on users who legitimately hit policy limits | Catches slower probing; risks flagging confused users |
| RULE-005 rate threshold | 30 / min | Needed for service accounts and batch jobs | Catches slow automation; risks flagging power users |
| RULE-006 violation count | > 3 / 5 min | Quieter; risks missing patient attackers | Catches short bursts; noisier for users fighting an access-control edge |
| ANOMALY-001 threshold | 3.0 robust-σ | Fewer rate alerts | More sensitive to modest spikes |
| ANOMALY-001 `SPIKE_FLOOR` | 20 | Ignores small-absolute spikes | Flags low-volume users more readily |
| Alert floor | MEDIUM+ | Only serious incidents surface | LOW findings reach the dashboard as noise |

### Known false-positive sources

1. **Service accounts** trip RULE-005 by design. Allowlist them by `user_id`
   rather than relaxing the global threshold.
2. **New employees** trip ANOMALY-002 on their first day. It is MEDIUM and
   informational for exactly this reason.
3. **Legitimate policy friction** — a user who genuinely needs a tool their
   role lacks generates repeated `policy_deny` events and can reach RULE-002.
   The fix is a role review, not a detection change.

### Known coverage gaps

1. **Single-event low-severity attacks.** A one-shot injection that the model
   refuses on its own produces one HIGH finding, which does not clear the
   2-finding bar for correlated escalation. It is recorded but may not page.
   Observed live as `IPI-001` and `EA-005` — see `RESULTS.md`.
2. **Cross-application chains are not yet correlated by session.** Correlation
   groups by `user_id`, so a chain spanning `secure-agent` and `secure-rag` is
   caught only if the same `user_id` appears in both.
3. **Prompt content is never inspected.** Only hashes and metadata are stored,
   by design. Semantic detection would require retaining prompt text and is a
   deliberate privacy trade-off not taken here.
