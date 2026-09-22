import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG_DIR = Path(__file__).parent.parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "security.jsonl"

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class SecurityLogger:
    def log(self, event: str, severity: str, user: str, action: str, details: Optional[Dict[str, Any]] = None):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "severity": severity,
            "user": user,
            "action": action,
            **(details or {}),
        }
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

        if SEVERITY_RANK.get(severity, 0) >= 3:
            print(f"  [SEC:{severity}] {event} | user={user} | {action}")

    def prompt_injection(self, user: str, query: str, action: str = "BLOCKED"):
        self.log("PROMPT_INJECTION", "HIGH", user, action, {"query_snippet": query[:120]})

    def indirect_injection(self, user: str, document: str, patterns: str, action: str = "BLOCKED"):
        self.log("INDIRECT_PROMPT_INJECTION", "HIGH", user, action, {"document": document, "patterns": patterns})

    def unauthorized_retrieval(self, user: str, role: str, requested_dept: str, action: str = "BLOCKED"):
        self.log("UNAUTHORIZED_RETRIEVAL", "HIGH", user, action, {"role": role, "requested_dept": requested_dept})

    def pii_detected(self, user: str, entity_types: List[str], action: str = "REDACTED"):
        self.log("PII_DETECTED", "MEDIUM", user, action, {"entity_types": entity_types})

    def secret_detected(self, user: str, secret_type: str, action: str = "BLOCKED"):
        self.log("SECRET_DETECTED", "CRITICAL", user, action, {"secret_type": secret_type})

    def malicious_document(self, user: str, document: str, risk_score: int, action: str = "QUARANTINED"):
        self.log("MALICIOUS_DOCUMENT", "HIGH", user, action, {"document": document, "risk_score": risk_score})

    def context_exfiltration(self, user: str, query: str, action: str = "BLOCKED"):
        self.log("CONTEXT_EXFILTRATION", "HIGH", user, action, {"query_snippet": query[:120]})

    def output_blocked(self, user: str, reason: str):
        self.log("OUTPUT_BLOCKED", "HIGH", user, "BLOCKED", {"reason": reason})

    def query_received(self, user: str, query: str, mode: str = "vulnerable"):
        self.log("QUERY_RECEIVED", "LOW", user, "ALLOWED", {"query_snippet": query[:120], "mode": mode})


_logger = SecurityLogger()


def get_logger() -> SecurityLogger:
    return _logger
