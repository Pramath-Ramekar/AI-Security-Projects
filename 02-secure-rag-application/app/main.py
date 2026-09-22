"""
Step 8 — FastAPI Application

Endpoints:
  GET  /health          — health check
  GET  /users           — list known users + roles
  POST /chat            — VULNERABLE RAG (no security)
  POST /secure/chat     — SECURED RAG (RBAC + injection detection + output guard)
"""
import re
import time
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.rag.retriever import VulnerableRetriever, SecureRetriever
from app.rag.generator import VulnerableGenerator, SecureGenerator
from app.security.access_control import get_user_info, get_user_role, USERS
from app.security.context_sanitizer import ContextSanitizer
from app.security.output_guard import OutputGuard
from app.security.security_logger import get_logger

app = FastAPI(
    title="Aegis Technologies — RAG Security Lab",
    description=(
        "Vulnerable vs Secure RAG comparison. "
        "POST /chat = no security. POST /secure/chat = all defenses active."
    ),
    version="1.0.0",
)

# Singletons (lazy-init on first request)
_vuln_ret = VulnerableRetriever()
_sec_ret   = SecureRetriever()
_vuln_gen  = VulnerableGenerator()
_sec_gen   = SecureGenerator()
_sanitizer = ContextSanitizer()
_guard     = OutputGuard()
_logger    = get_logger()

# Direct-injection patterns checked on the raw query before retrieval
_INJECTION_RE = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
    re.compile(r"ignore\s+(your\s+)?system\s+(prompt|instructions?)", re.I),
    re.compile(r"(reveal|print|show|dump|expose)\s+(all\s+)?(secret|password|credential|api.?key|token)", re.I),
    re.compile(r"SYSTEM\s+(OVERRIDE|COMMAND|ADMIN|DIAGNOSTIC)", re.I),
    re.compile(r"(reveal|print|show|expose)\s+(the\s+)?(complete|full|entire)\s+(context|prompt|system)", re.I),
    re.compile(r"(act|pretend|behave|respond)\s+as\s+(if\s+)?(you\s+are\s+)?(?:an?\s+)?(?:unrestricted|jailbroken|evil|dan)", re.I),
    re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(?:an?\s+)?(?:unrestricted|jailbroken|evil|uncensored|unfiltered)", re.I),
    re.compile(r"(you\s+are|you're)\s+(?:now\s+)?(?:an?\s+)?(?:unrestricted|jailbroken|evil|uncensored)\s+ai", re.I),
    re.compile(r"disregard\s+(your\s+)?(previous|prior|all)\s+(instructions?|rules?)", re.I),
    re.compile(r"(output|repeat|print)\s+(your\s+)?(complete|full|entire)\s+(instructions?|system\s+(prompt|config))", re.I),
]

_EXFIL_RE = [
    re.compile(r"(show|print|output|dump)\s+(me\s+)?(your\s+)?(full\s+)?(context|prompt|retrieved\s+documents?)", re.I),
    re.compile(r"what\s+(documents?|text|content)\s+(did\s+you\s+retrieve|was\s+retrieved|are\s+in\s+(your\s+)?context)", re.I),
    re.compile(r"(return|give\s+me)\s+a\s+json\s+(object|dump|with)\s+(key|containing|with\s+key)", re.I),
]


class ChatRequest(BaseModel):
    user: str
    query: str
    n_results: int = 5


class SourceInfo(BaseModel):
    filename: str
    department: str
    classification: str
    score: float


class ChatResponse(BaseModel):
    answer: str
    sources: List[SourceInfo]
    user: str
    role: Optional[str]
    mode: str
    latency_ms: float
    security_events: List[str] = []


def _sources(chunks) -> List[SourceInfo]:
    return [
        SourceInfo(
            filename=c.metadata.get("filename", "?"),
            department=c.metadata.get("department", "?"),
            classification=c.metadata.get("classification", "?"),
            score=round(c.score, 4),
        )
        for c in chunks
    ]


_UI_PATH = Path(__file__).parent / "static" / "index.html"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def demo_ui():
    return HTMLResponse(_UI_PATH.read_text(encoding="utf-8"))


@app.get("/health")
def health():
    return {"status": "ok", "service": "Aegis RAG Security Lab"}


@app.get("/users")
def list_users():
    return {u: {"role": v["role"], "department": v["department"]} for u, v in USERS.items()}


@app.post("/chat", response_model=ChatResponse)
def vulnerable_chat(req: ChatRequest):
    """VULNERABLE RAG — no security controls. For demonstration of attacks."""
    t0 = time.time()
    _logger.query_received(req.user, req.query, mode="vulnerable")

    chunks = _vuln_ret.retrieve_for_user(req.query, req.user, n_results=req.n_results)
    answer = _vuln_gen.generate(req.query, chunks)
    role = get_user_role(req.user)

    return ChatResponse(
        answer=answer,
        sources=_sources(chunks),
        user=req.user,
        role=role,
        mode="vulnerable",
        latency_ms=round((time.time() - t0) * 1000, 1),
    )


@app.post("/secure/chat", response_model=ChatResponse)
def secure_chat(req: ChatRequest):
    """SECURED RAG — RBAC + input validation + context sanitization + output guard."""
    t0 = time.time()
    events: List[str] = []

    # 1. Authentication
    user_info = get_user_info(req.user)
    if user_info is None:
        raise HTTPException(status_code=401, detail=f"Unknown user: {req.user}")
    role = user_info["role"]

    _logger.query_received(req.user, req.query, mode="secure")

    # 2. Input — direct injection detection
    for pattern in _INJECTION_RE:
        if pattern.search(req.query):
            _logger.prompt_injection(req.user, req.query, "BLOCKED")
            events.append("PROMPT_INJECTION_BLOCKED")
            return ChatResponse(
                answer="[SECURITY] Query blocked: detected prompt injection attempt.",
                sources=[], user=req.user, role=role, mode="secure",
                latency_ms=round((time.time() - t0) * 1000, 1),
                security_events=events,
            )

    # 3. Input — context exfiltration detection
    for pattern in _EXFIL_RE:
        if pattern.search(req.query):
            _logger.context_exfiltration(req.user, req.query, "BLOCKED")
            events.append("CONTEXT_EXFILTRATION_BLOCKED")
            return ChatResponse(
                answer="[SECURITY] Query blocked: context exfiltration attempt detected.",
                sources=[], user=req.user, role=role, mode="secure",
                latency_ms=round((time.time() - t0) * 1000, 1),
                security_events=events,
            )

    # 4. RBAC retrieval (role-filtered)
    chunks = _sec_ret.retrieve_for_user(req.query, req.user, n_results=req.n_results, role=role)

    # 5. Context sanitization — indirect injection detection
    san = _sanitizer.sanitize(chunks)
    for flagged_chunk, result in san.flagged_chunks:
        dept = flagged_chunk.metadata.get("department", "?")
        fname = flagged_chunk.metadata.get("filename", "?")
        _logger.indirect_injection(
            req.user,
            f"{dept}/{fname}",
            str([m["pattern"] for m in result.matches]),
            "BLOCKED" if result.is_quarantined else "SANITIZED",
        )
        events.append(f"INDIRECT_INJECTION_{dept}/{fname}")

    # 6. Secure generation
    answer = _sec_gen.generate(req.query, san.safe_chunks)

    # 7. Output guard
    guard_result = _guard.scan(answer)
    if not guard_result.allowed:
        _logger.output_blocked(req.user, guard_result.blocked_reason or "unknown")
        events.append(f"OUTPUT_BLOCKED:{guard_result.blocked_reason}")
        answer = guard_result.response
    elif guard_result.was_redacted:
        types = [e.entity_type for e in guard_result.pii_found]
        _logger.pii_detected(req.user, types, "REDACTED")
        events.append(f"PII_REDACTED:{types}")
        answer = guard_result.response

    return ChatResponse(
        answer=answer,
        sources=_sources(san.safe_chunks),
        user=req.user,
        role=role,
        mode="secure",
        latency_ms=round((time.time() - t0) * 1000, 1),
        security_events=events,
    )
