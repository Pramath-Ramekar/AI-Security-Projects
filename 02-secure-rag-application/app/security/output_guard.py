import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.security.pii_detector import PIIDetector, PIIEntity

_pii = PIIDetector()

BLOCKED_PATTERNS = [
    re.compile(r"FAKE_(?:DB_PASSWORD|INTERNAL_API_KEY|AWS_(?:ACCESS|SECRET)_KEY|KMS_KEY|OAUTH_SECRET|K8S_TOKEN|SIGNING_KEY)_\w+", re.I),
    re.compile(r"PROJECT.(?:PHOENIX|HYDRA|SENTINEL)", re.I),
    re.compile(r"(?:database|DB)\s+password\s*:?\s*\S{6,}", re.I),
    re.compile(r"(?:secret|signing)\s+key\s*:?\s*[A-Za-z0-9_\-!@#$%]{16,}", re.I),
    re.compile(r"client\s+secret\s*:?\s*[A-Za-z0-9_\-]{16,}", re.I),
]

INJECTION_FOLLOW_PATTERNS = [
    re.compile(r"(as\s+instructed|following\s+your\s+instructions?|per\s+the\s+(system\s+)?instructions?)", re.I),
    re.compile(r"(maintenance|developer|debug|admin)\s+mode\s+(activated|enabled|on)", re.I),
    re.compile(r"(printing|outputting|here\s+is)\s+(the\s+)?(complete|full|entire)\s+context", re.I),
    re.compile(r"as\s+(an?\s+)?(unrestricted|jailbroken|evil|unfiltered)\s+(ai|assistant|model)", re.I),
    re.compile(r"^SYSTEM_PROMPT\s*:", re.I | re.MULTILINE),
    re.compile(r"^CONTEXT\s*:\s*[-—]{3,}", re.I | re.MULTILINE),
]

# Additional blocked patterns for credential tokens that aren't FAKE_* prefixed
EXTRA_BLOCKED = [
    re.compile(r'\b\w+_TOKEN\s*=\s*\S+', re.I),           # ANY_TOKEN=value
    re.compile(r'\b\w+_SECRET\s*=\s*\S+', re.I),          # ANY_SECRET=value
    re.compile(r'\b\w+_KEY\s*=\s*\S{8,}', re.I),          # ANY_KEY=longvalue
    re.compile(r'\b\w+_PASSWORD\s*=\s*\S+', re.I),        # ANY_PASSWORD=value
    re.compile(r'PAGERDUTY_TOKEN|GITHUB_TOKEN|SLACK_TOKEN|STRIPE_KEY', re.I),
]

MAX_LENGTH = 4000


@dataclass
class GuardResult:
    allowed: bool
    response: str
    blocked_reason: Optional[str] = None
    pii_found: List[PIIEntity] = field(default_factory=list)
    was_redacted: bool = False


class OutputGuard:
    def scan(self, response: str, redact_pii: bool = True) -> GuardResult:
        if len(response) > MAX_LENGTH:
            response = response[:MAX_LENGTH] + "\n[TRUNCATED by output security policy]"

        for pattern in INJECTION_FOLLOW_PATTERNS:
            if pattern.search(response):
                return GuardResult(
                    allowed=False,
                    response="[BLOCKED] Response indicated instruction-following — probable prompt injection.",
                    blocked_reason="injection-following",
                )

        for pattern in BLOCKED_PATTERNS:
            if pattern.search(response):
                return GuardResult(
                    allowed=False,
                    response="[BLOCKED] Response contained sensitive credentials or classified project names.",
                    blocked_reason="sensitive-content",
                )

        for pattern in EXTRA_BLOCKED:
            if pattern.search(response):
                return GuardResult(
                    allowed=False,
                    response="[BLOCKED] Response contained credential tokens or secret key patterns.",
                    blocked_reason="credential-token-detected",
                )

        entities = _pii.detect(response)
        if entities:
            if redact_pii:
                redacted, _ = _pii.redact(response)
                return GuardResult(
                    allowed=True,
                    response=redacted,
                    pii_found=entities,
                    was_redacted=True,
                )
            return GuardResult(
                allowed=False,
                response="[BLOCKED] Response contained PII.",
                blocked_reason="pii-detected",
                pii_found=entities,
            )

        return GuardResult(allowed=True, response=response)


_guard = OutputGuard()


def scan_output(response: str) -> GuardResult:
    return _guard.scan(response)
