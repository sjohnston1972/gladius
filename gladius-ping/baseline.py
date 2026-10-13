"""
baseline.py - Rolling baseline statistics and anomaly detection
"""
import math
import threading
import time
from storage import load_results

BASELINE_HOURS = 168  # 7 days
Z_THRESHOLD = 3.0     # anomaly if value > mean + Z * stddev
BASELINE_REFRESH_SEC = 600  # recompute each device's baseline at most every 10 min

_cache: dict[int, tuple[float, dict | None]] = {}  # device_id -> (computed_at, baseline)
_cache_lock = threading.Lock()


def _compute_baseline(device_id: int) -> dict | None:
    """Compute rolling mean and stddev from last 7 days of results."""
    rows = load_results(device_id, hours=BASELINE_HOURS)
    lats = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
    if len(lats) < 30:   # not enough data yet
        return None
    mean = sum(lats) / len(lats)
    variance = sum((x - mean) ** 2 for x in lats) / len(lats)
    stddev = math.sqrt(variance)
    return {"mean": round(mean, 2), "stddev": round(stddev, 2), "samples": len(lats)}


def get_baseline(device_id: int) -> dict | None:
    """Return the device's 7-day baseline, recomputed at most every BASELINE_REFRESH_SEC.

    A 7-day mean/stddev barely moves in a few minutes, so re-reading the
    results history on every sample is wasted work.
    """
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(device_id)
    if hit is not None and now - hit[0] < BASELINE_REFRESH_SEC:
        return hit[1]
    baseline = _compute_baseline(device_id)
    with _cache_lock:
        _cache[device_id] = (now, baseline)
    return baseline


def invalidate(device_id: int | None = None):
    """Drop cached baselines (all devices when device_id is None)."""
    with _cache_lock:
        if device_id is None:
            _cache.clear()
        else:
            _cache.pop(device_id, None)


def is_anomaly(device_id: int, latency: float) -> bool:
    """Return True if latency is statistically anomalous vs. 7-day baseline."""
    baseline = get_baseline(device_id)
    if baseline is None:
        return False
    threshold = baseline["mean"] + Z_THRESHOLD * baseline["stddev"]
    return latency > threshold and latency > baseline["mean"] * 1.5
