"""Baseline caching (#40) and the bisecting tail read used by load_results."""
import csv
import random
from datetime import datetime, timedelta

import baseline
import storage


def _write_results(device_id, start, count, step_sec, latency=lambda i: 10.0):
    path = storage.RESULTS_DIR / f"device_{device_id}.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "latency_ms", "success", "jitter_ms"])
        for i in range(count):
            ts = start + timedelta(seconds=i * step_sec)
            lat = latency(i)
            w.writerow([ts.isoformat(), "" if lat is None else round(lat, 3),
                        int(lat is not None), ""])
    return path


def _full_scan(path, hours):
    """Reference implementation: the original parse-everything load_results."""
    cutoff = storage.utcnow() - timedelta(hours=hours)
    out = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            ts = datetime.fromisoformat(row["timestamp"])
            if ts >= cutoff:
                out.append({
                    "timestamp": row["timestamp"],
                    "latency_ms": float(row["latency_ms"]) if row["latency_ms"] else None,
                    "success": bool(int(row["success"])),
                    "jitter_ms": float(row["jitter_ms"]) if row["jitter_ms"] else None,
                })
    return out


def test_tail_read_matches_full_scan(data_dir):
    rnd = random.Random(7)
    start = storage.utcnow() - timedelta(days=10)
    # one row per minute for 10 days (~14.4k rows, ~700 KB) so the bisection really runs
    path = _write_results(1, start, 14400, 60,
                          latency=lambda i: None if rnd.random() < 0.05 else rnd.uniform(1, 50))
    assert path.stat().st_size > 4 * storage._SEEK_MIN_SPAN
    for hours in (1, 5, 24, 168, 239, 300, 100000):
        assert storage.load_results(1, hours) == _full_scan(path, hours), hours


def test_tail_read_small_and_empty_files(data_dir):
    path = _write_results(2, storage.utcnow() - timedelta(minutes=30), 10, 60)
    assert storage.load_results(2, 1) == _full_scan(path, 1)
    _write_results(3, storage.utcnow(), 0, 60)
    assert storage.load_results(3, 1) == []
    assert storage.load_results(99, 1) == []


def test_sla_report_unchanged_by_tail_read(data_dir):
    _write_results(4, storage.utcnow() - timedelta(days=40), 40 * 24, 3600)
    report = storage.load_sla_report(4, days=30)
    assert len(report) == 30
    assert sum(d["total"] for d in report) in range(29 * 24, 30 * 24 + 1)


def test_baseline_is_cached_and_refreshed(data_dir, monkeypatch):
    baseline.invalidate()
    _write_results(5, storage.utcnow() - timedelta(hours=2), 100, 60, latency=lambda i: 10.0)
    calls = {"n": 0}
    real = baseline.load_results

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(baseline, "load_results", counting)
    clock = {"t": 1000.0}
    monkeypatch.setattr(baseline.time, "monotonic", lambda: clock["t"])

    b1 = baseline.get_baseline(5)
    assert b1["mean"] == 10.0 and b1["samples"] == 100
    for _ in range(50):
        baseline.is_anomaly(5, 12.0)
    assert calls["n"] == 1, "baseline re-read the history on every sample"

    # new data arrives; still served from cache until the refresh interval passes
    _write_results(5, storage.utcnow() - timedelta(hours=2), 100, 60, latency=lambda i: 20.0)
    assert baseline.get_baseline(5)["mean"] == 10.0
    clock["t"] += baseline.BASELINE_REFRESH_SEC + 1
    assert baseline.get_baseline(5)["mean"] == 20.0
    assert calls["n"] == 2

    baseline.invalidate(5)
    baseline.get_baseline(5)
    assert calls["n"] == 3


def test_baseline_needs_30_samples(data_dir):
    baseline.invalidate()
    _write_results(6, storage.utcnow() - timedelta(minutes=20), 20, 60)
    assert baseline.get_baseline(6) is None
    assert baseline.is_anomaly(6, 1000.0) is False
