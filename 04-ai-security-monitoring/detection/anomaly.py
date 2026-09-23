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


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return float(s[mid]) if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _mad(values: list[float], med: float) -> float:
    """Median absolute deviation."""
    return _median([abs(x - med) for x in values])


# A spike must clear both a multiple of the baseline and an absolute floor,
# so a quiet user going from 1 to 5 requests is not reported as an anomaly.
SPIKE_RATIO = 5.0
SPIKE_FLOOR = 20


def detect_rate_anomalies(
    all_events: list[dict],
    z_threshold: float = 3.0,
    min_samples: int = 3,
) -> list[dict]:
    """
    For each user, compute hourly request rates and flag anomalous peaks.

    Uses a median/MAD-based robust score rather than a plain z-score. A plain
    z-score is not usable here: a single large spike inflates the standard
    deviation it is measured against, so the biggest outliers hide themselves.
    With rates [1,1,1,1,1,1,300] the spike scores only 2.3σ and never trips a
    3σ threshold. Median and MAD are unaffected by the outlier.

    When MAD is 0 (more than half the hours are identical, common for low-volume
    users) no dispersion estimate exists, so fall back to a ratio-vs-floor test.
    """
    hourly = _compute_hourly_rates(all_events)
    findings = []
    for user, rates in hourly.items():
        if len(rates) < min_samples:
            continue

        max_rate = max(rates)
        med = _median(rates)
        mad = _mad(rates, med)
        mean, std = _mean_std(rates)

        if mad > 0:
            # 0.6745 rescales MAD to be consistent with σ for normal data.
            score = 0.6745 * (max_rate - med) / mad
            triggered = score >= z_threshold
            basis = f"{score:.1f} robust-σ above median ({med:.1f}, MAD {mad:.1f})"
        else:
            triggered = max_rate >= max(med * SPIKE_RATIO, med + SPIKE_FLOOR)
            score = (max_rate / med) if med else float(max_rate)
            basis = f"{score:.1f}× the median hourly rate ({med:.1f})"

        if triggered:
            findings.append({
                "rule": "ANOMALY-001",
                "name": "Anomalous Request Rate",
                "severity": "high" if score < 5 else "critical",
                "reason": f"User '{user}' peak hourly rate {max_rate} req/hr is {basis}",
                "user_id": user,
                "score": round(score, 2),
                "peak_rate": max_rate,
                "median_rate": round(med, 1),
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
