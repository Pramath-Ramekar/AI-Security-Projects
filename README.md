# AI Security Projects

A hands-on portfolio of AI security labs built to demonstrate attack and defense techniques for real AI systems. Each project covers a specific threat surface, implements working exploits against vulnerable baselines, then hardens against them with measurable results.

---

## Projects

### 01 - AI Red Teaming Lab
Automated red-team pipeline for a live LLM application using PyRIT and Promptfoo.

- Attacks: jailbreaks, prompt injections, goal hijacking
- CI workflow runs attack matrix on every push
- Evidence collected automatically per run

### 02 - Secure RAG Application
Vulnerable-vs-secure comparison of an enterprise RAG system (fictional "Aegis Technologies").

- Attacks: context extraction, data exfiltration, direct and indirect injection, embedding weakness, unauthorized access
- Defense: 6-layer security stack (RBAC, input/output filtering, retrieval guardrails)
- Automated evaluation measures detection rate before and after hardening

### 03 - Secure AI Agent
Break-and-rebuild lab targeting a tool-using autonomous agent.

- Covers OWASP LLM01 (Prompt Injection), LLM06 (Excessive Agency), LLM07 (Insecure Output Handling)
- Vulnerable agent: 2 confirmed dangerous tool executions, unauthorized email sent
- Hardened agent: 0 dangerous executions, 100% pass rate across 13 attacks
- Security components: policy engine, action monitor, approval gate, audit logger, tool registry

### 04 - AI Security Monitoring
AI SOC pipeline that detects misuse and suspicious activity across AI systems in real time.

- Covers OWASP LLM01, LLM02, LLM06
- Live mode: 7 real attacks against the Project 03 hardened agent, 57 telemetry events captured
- Components: telemetry collector, detection rules engine, alert manager, dashboard

---

## Stack

Python, FastAPI, ChromaDB, PyRIT, Promptfoo, OpenTelemetry, GitHub Actions

---

## Author

Pramath Ramekar
