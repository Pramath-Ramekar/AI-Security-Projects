"""
Anomaly detection — Step 17.
Uses z-score and percentile thresholds on per-user request rates.
"""
import math
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional


def _ts(event: dict) -> datetime:
    try:
        return datetime.fromisoformat(event["timestamp"])
    except Exception:
        return datetime.now(timezone.utc)


def _compute_hourly_rates(events: list[dict]) -> dict[str, list[int]]:
    """Compute requests-per-hour buckets per user."""
    user_hours: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in events:
        t = _ts(e)
        bucket = t.strftime("%Y-%m-%dT%H")
        user_hours[e.get("user_id", "unknown")][bucket] += 1
    return {
        user: list(hours.values())
        for user, hours in user_hours.items()
    }


def _mean_std(values: list[int]) -> tuple[float, float]:
    if len(values) < 2:
        return float(values[0]) if values else 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, math.sqrt(variance)


def detect_rate_anomalies(
    all_events: list[dict],
    z_threshold: float = 3.0,
    min_samples: int = 3,
) -> list[dict]:
    """
    For each user, compute hourly request rates and flag any hour where
    the z-score exceeds z_threshold as anomalous.
    """
    hourly = _compute_hourly_rates(all_events)
    findings = []
    for user, rates in hourly.items():
        if len(rates) < min_samples:
            continue
        mean, std = _mean_std(rates)
        if std == 0:
            continue
        max_rate = max(rates)
        z = (max_rate - mean) / std
        if z >= z_threshold:
            findings.append({
                "rule": "ANOMALY-001",
                "name": "Anomalous Request Rate",
                "severity": "high" if z < 5 else "critical",
                "reason": f"User '{user}' peak hourly rate {max_rate} req/hr is "
                          f"{z:.1f}σ above their mean ({mean:.1f}±{std:.1f})",
                "user_id": user,
                "z_score": round(z, 2),
                "peak_rate": max_rate,
                "mean_rate": round(mean, 1),
            })
    return findings


def detect_new_user_behavior(
    recent_events: list[dict],
    baseline_users: set[str],
) -> list[dict]:
    """Flag users appearing in recent events who are not in the baseline."""
    findings = []
    seen = set()
    for e in recent_events:
        user = e.get("user_id", "")
        if user not in baseline_users and user not in seen:
            seen.add(user)
            findings.append({
                "rule": "ANOMALY-002",
                "name": "Unknown User Activity",
                "severity": "medium",
                "reason": f"User '{user}' has no established baseline — first seen in this window",
                "user_id": user,
                "trigger_event": e.get("event_id"),
            })
    return findings
