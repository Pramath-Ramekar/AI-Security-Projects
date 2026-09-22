import re
from dataclasses import dataclass
from typing import List, Tuple

PII_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("EMAIL",           re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ("PHONE",           re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')),
    ("SSN",             re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("CREDIT_CARD",     re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')),
    ("AWS_ACCESS_KEY",  re.compile(r'\b(?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b')),
    ("API_KEY",         re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.I)),
    ("PASSWORD_FIELD",  re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?', re.I)),
    ("SECRET_KEY",      re.compile(r'(?:secret[_-]?key|client.?secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', re.I)),
    ("BEARER_TOKEN",    re.compile(r'Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)')),
    # Aegis-specific fake secret patterns
    ("FAKE_DB_PASSWORD",  re.compile(r'FAKE_DB_PASSWORD_\w+', re.I)),
    ("FAKE_API_KEY",      re.compile(r'FAKE_INTERNAL_API_KEY_\w+', re.I)),
    ("FAKE_AWS_KEY",      re.compile(r'FAKE_AWS_(?:ACCESS|SECRET)_KEY_\w+', re.I)),
    ("FAKE_KMS_KEY",      re.compile(r'FAKE_KMS_KEY_\w+', re.I)),
    ("FAKE_OAUTH_SECRET", re.compile(r'FAKE_OAUTH_SECRET_\w+', re.I)),
    ("FAKE_K8S_TOKEN",    re.compile(r'FAKE_K8S_TOKEN_\w+', re.I)),
    ("FAKE_SIGNING_KEY",  re.compile(r'FAKE_SIGNING_KEY_\w+', re.I)),
]


@dataclass
class PIIEntity:
    entity_type: str
    value: str
    start: int
    end: int


class PIIDetector:
    def detect(self, text: str) -> List[PIIEntity]:
        entities = []
        seen_spans = set()
        for entity_type, pattern in PII_PATTERNS:
            for match in pattern.finditer(text):
                span = (match.start(), match.end())
                if span not in seen_spans:
                    seen_spans.add(span)
                    entities.append(PIIEntity(
                        entity_type=entity_type,
                        value=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    ))
        entities.sort(key=lambda e: e.start)
        return entities

    def redact(self, text: str) -> Tuple[str, List[PIIEntity]]:
        entities = self.detect(text)
        chars = list(text)
        for entity in reversed(entities):
            replacement = list(f"[{entity.entity_type}_REDACTED]")
            chars[entity.start:entity.end] = replacement
        return "".join(chars), entities

    def contains_sensitive(self, text: str) -> bool:
        return len(self.detect(text)) > 0


_detector = PIIDetector()


def detect_pii(text: str) -> List[PIIEntity]:
    return _detector.detect(text)


def redact_pii(text: str) -> Tuple[str, List[PIIEntity]]:
    return _detector.redact(text)
