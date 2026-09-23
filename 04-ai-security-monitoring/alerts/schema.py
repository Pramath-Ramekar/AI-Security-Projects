import uuid
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Alert:
    severity: str
    user_id: str
    reason: str

    alert_id: str = field(default_factory=lambda: f"ALERT-{uuid.uuid4().hex[:6].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    application: Optional[str] = None
    risk_score: int = 0
    rules_fired: list = field(default_factory=list)
    event_ids: list = field(default_factory=list)
    status: str = "open"
    incident_type: str = "SINGLE_FINDING"

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def make_alert(incident: dict, application: Optional[str] = None) -> Alert:
    return Alert(
        severity=incident.get("severity", "low"),
        user_id=incident.get("user_id", "unknown"),
        reason=incident.get("reason", ""),
        # The incident knows which application it came from; the explicit
        # argument is only an override for single-app deployments.
        application=application or incident.get("application"),
        risk_score=incident.get("risk_score", 0),
        rules_fired=incident.get("rules_fired", []),
        event_ids=incident.get("event_ids", []),
        incident_type=incident.get("type", "SINGLE_FINDING"),
    )
