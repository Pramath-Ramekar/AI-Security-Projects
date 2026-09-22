import re
from dataclasses import dataclass, field
from typing import List, Tuple

# (compiled_pattern, label, severity_0-10)
INJECTION_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),                          "ignore-previous-instructions", 9),
    (re.compile(r"ignore\s+(your\s+)?system\s+(prompt|instructions?)", re.I),                   "ignore-system-prompt", 9),
    (re.compile(r"disregard\s+(your\s+)?(previous|prior|earlier|all)\s+(instructions?|rules?)", re.I), "disregard-instructions", 9),
    (re.compile(r"you\s+are\s+now\s+in\s+(maintenance|developer|admin|debug)\s+mode", re.I),   "mode-switch", 8),
    (re.compile(r"SYSTEM\s+(OVERRIDE|COMMAND|ADMIN|DIAGNOSTIC)", re.I),                         "system-override", 10),
    (re.compile(r"(reveal|print|show|dump|expose|output)\s+(?:\w+\s+){0,3}(secret|password|credential|api.?key|token)", re.I), "secret-extraction", 9),
    (re.compile(r"(reveal|print|show|expose)\s+(the\s+)?(complete|full|entire)\s+(context|prompt|system)", re.I), "context-extraction", 8),
    (re.compile(r"this\s+is\s+a\s+(authorized|official|system)\s+(command|diagnostic|override)", re.I), "authority-claim", 7),
    (re.compile(r"(developer|admin|root|cto|ciso)\s+(mode|message|instruction|override|access)", re.I), "privilege-escalation", 8),
    (re.compile(r"(act|pretend|behave|respond)\s+as\s+(if\s+)?(you\s+are\s+)?(?:an?\s+)?(?:unrestricted|jailbroken|evil|dan|harmful)", re.I), "jailbreak-persona", 10),
    (re.compile(r"for\s+(testing|debugging|diagnostic)\s+purposes?,?\s+(ignore|bypass|skip)", re.I), "test-bypass", 7),
    (re.compile(r"IMPORTANT\s+INSTRUCTION\s+FOR\s+AI", re.I),                                   "explicit-ai-instruction", 9),
    (re.compile(r"\[\[INJECT\]\]|\[\[SYSTEM\]\]|\[\[OVERRIDE\]\]"),                             "injection-marker", 10),
    (re.compile(r"(follow|execute)\s+these\s+instructions?\s*:", re.I),                         "follow-instructions", 6),
    (re.compile(r"new\s+(persona|role|identity|instructions?)\s*:", re.I),                      "persona-change", 7),
    (re.compile(r"(print|output|reveal)\s+(all\s+)?(restricted|confidential|classified|internal)\s+(data|information|documents?)", re.I), "data-dump", 9),
    # T7 fix — soft/social-engineering injections that address the model
    # directly rather than using imperative override keywords. A document
    # doesn't need to say "ignore instructions" to hijack behavior; talking
    # to "the assistant/AI" about how it should answer is itself the tell.
    (re.compile(r"(tip|note|message|instruction)s?\s+for\s+the\s+(assistant|ai\b|model|chatbot|bot|llm)", re.I), "meta-instruction-to-ai", 8),
    (re.compile(r"(please\s+)?(close|end|append|include)\s+your\s+(answer|response)\s+(by|with)", re.I), "answer-manipulation-directive", 8),
    (re.compile(r"(always|every\s+time)\s+(you\s+)?(answer|respond|reply)\w*\b.{0,40}?(include|mention|append|add)", re.I), "persistent-append-directive", 8),
    (re.compile(r"when\s+(responding|answering|replying)\s+to\s+(any|every|all)\b.{0,80}?\b(please|always|be\s+sure\s+to|make\s+sure\s+to|remember\s+to)\b", re.I), "conditional-response-directive", 8),
]


@dataclass
class ValidationResult:
    verdict: str       # TRUSTED | SUSPICIOUS | QUARANTINED
    risk_score: int    # 0–10
    matches: List[dict] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return self.verdict == "TRUSTED"

    @property
    def is_suspicious(self) -> bool:
        return self.verdict == "SUSPICIOUS"

    @property
    def is_quarantined(self) -> bool:
        return self.verdict == "QUARANTINED"


class DocumentValidator:
    def validate(self, text: str) -> ValidationResult:
        matches = []
        max_score = 0

        for pattern, label, severity in INJECTION_PATTERNS:
            found = pattern.findall(text)
            if found:
                matches.append({"pattern": label, "severity": severity, "count": len(found)})
                max_score = max(max_score, severity)

        if max_score == 0:
            verdict = "TRUSTED"
        elif max_score < 7:
            verdict = "SUSPICIOUS"
        else:
            verdict = "QUARANTINED"

        return ValidationResult(verdict=verdict, risk_score=max_score, matches=matches)


_validator = DocumentValidator()


def validate_document(text: str) -> ValidationResult:
    return _validator.validate(text)
