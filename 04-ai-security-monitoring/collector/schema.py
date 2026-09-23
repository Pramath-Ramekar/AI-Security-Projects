import uuid
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
import json

VALID_APPLICATIONS = {"secure-agent", "secure-rag", "chatbot"}

VALID_EVENT_TYPES = {
    "query",
    "tool_request",
    "tool_executed",
    "tool_blocked",
    "prompt_injection",
    "unauthorized_retrieval",
    "pii_request",
    "secret_access",
    "suspicious_tool_chain",
    "rate_abuse",
    "approval_requested",
    "approval_granted",
    "approval_denied",
    "policy_deny",
    "validation_fail",
    "chain_blocked",
    "agent_response",
}

VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}
VALID_DECISIONS = {"allow", "blocked", "flagged", "executed", "pending"}


@dataclass
class SecurityEvent:
    application: str
    event_type: str
    user_id: str

    # optional fields
    session_id: str = field(default_factory=lambda: f"sess-{uuid.uuid4().hex[:8]}")
    event_id: str = field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool: Optional[str] = None
    document: Optional[str] = None
    risk: str = "low"
    decision: str = "allow"
    prompt_hash: Optional[str] = None
    source_ip: Optional[str] = None
    details: Optional[dict] = None

    def __post_init__(self):
        if self.application not in VALID_APPLICATIONS:
            raise ValueError(f"Unknown application: {self.application}")
        if self.event_type not in VALID_EVENT_TYPES:
            raise ValueError(f"Unknown event_type: {self.event_type}")
        if self.risk not in VALID_RISK_LEVELS:
            raise ValueError(f"Unknown risk level: {self.risk}")
        if self.decision not in VALID_DECISIONS:
            raise ValueError(f"Unknown decision: {self.decision}")

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def hash_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


def make_event(
    application: str,
    event_type: str,
    user_id: str,
    risk: str = "low",
    decision: str = "allow",
    session_id: Optional[str] = None,
    tool: Optional[str] = None,
    document: Optional[str] = None,
    prompt: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[dict] = None,
) -> SecurityEvent:
    return SecurityEvent(
        application=application,
        event_type=event_type,
        user_id=user_id,
        risk=risk,
        decision=decision,
        session_id=session_id or f"sess-{uuid.uuid4().hex[:8]}",
        tool=tool,
        document=document,
        prompt_hash=hash_prompt(prompt) if prompt else None,
        source_ip=source_ip,
        details=details,
    )
