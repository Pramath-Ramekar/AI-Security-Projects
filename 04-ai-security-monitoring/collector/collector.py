"""
Event collector — receives SecurityEvent dicts and appends them to logs/events.jsonl.
Can be used directly (in-process) or via the lightweight HTTP API (api.py).
"""
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

LOG_DIR = Path(__file__).parent.parent / "logs"
EVENTS_FILE = LOG_DIR / "events.jsonl"


def _ensure_log_dir():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def collect(event: dict) -> dict:
    """Append a single event dict to the JSONL log. Returns the event with server timestamp."""
    _ensure_log_dir()
    if "received_at" not in event:
        event["received_at"] = datetime.now(timezone.utc).isoformat()
    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    return event


def collect_batch(events: list[dict]) -> int:
    """Append a list of events. Returns count written."""
    _ensure_log_dir()
    ts = datetime.now(timezone.utc).isoformat()
    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        for ev in events:
            if "received_at" not in ev:
                ev["received_at"] = ts
            f.write(json.dumps(ev) + "\n")
    return len(events)


def load_events(
    since: Optional[str] = None,
    application: Optional[str] = None,
    user_id: Optional[str] = None,
    event_type: Optional[str] = None,
) -> list[dict]:
    """Load events from the JSONL log with optional filters."""
    if not EVENTS_FILE.exists():
        return []
    events = []
    with open(EVENTS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since and ev.get("timestamp", "") < since:
                continue
            if application and ev.get("application") != application:
                continue
            if user_id and ev.get("user_id") != user_id:
                continue
            if event_type and ev.get("event_type") != event_type:
                continue
            events.append(ev)
    return events


def event_count() -> int:
    if not EVENTS_FILE.exists():
        return 0
    with open(EVENTS_FILE, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())
