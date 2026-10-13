"""Alert state machine: N failures -> down, recovery, cooldown setting, anomaly persistence (#108)."""
from datetime import datetime, timedelta

import pytest

import alerts
import storage

DEV = {"id": 1, "name": "edge", "host": "192.0.2.1",
       "thresholds": {"latency_ms": 100, "latency_ms_warn": 50}}
BASE = {"mean": 10.0, "stddev": 1.0, "samples": 1000}


class _Fired(list):
    """Alert types fired, plus the fake clock and a failure streak."""


@pytest.fixture
def fired(data_dir, monkeypatch):
    events = _Fired()
    monkeypatch.setattr(alerts, "_fire_alert",
                        lambda device, alert_type, msg, value=0, threshold=0: events.append(alert_type))
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(alerts.time, "time", lambda: clock["t"])
    alerts._last_alert.clear()
    alerts._fail_start.clear()
    alerts._down_alerted.clear()
    alerts._anomaly_hist.clear()
    events.clock = clock
    return events


def _probe(results, success, latency=10.0, jitter=None, device=DEV):
    """Feed one sample through check_and_alert with a consecutive-failure count."""
    results.streak = 0 if success else getattr(results, "streak", 0) + 1
    alerts.check_and_alert(device, latency if success else None, success, jitter,
                           failures=results.streak)


def test_down_after_n_consecutive_failures_then_recovery(fired):
    storage.save_settings({"down_after_failures": 3, "cooldown_sec": 0})
    _probe(fired, False)
    _probe(fired, False)
    assert fired == []                     # single/double loss is not an outage
    _probe(fired, False)
    assert fired == ["down"]
    for _ in range(10):                    # still down: no repeats, even with cooldown 0
        fired.clock["t"] += 60
        _probe(fired, False)
    assert fired == ["down"]
    _probe(fired, True)
    assert fired == ["down", "up"]
    _probe(fired, True)
    assert fired == ["down", "up"]


def test_blip_below_threshold_has_no_recovery_alert(fired):
    storage.save_settings({"down_after_failures": 3})
    _probe(fired, False)
    _probe(fired, True)
    assert fired == []


def test_cooldown_comes_from_settings(fired):
    storage.save_settings({"cooldown_sec": 1000})
    _probe(fired, True, latency=200)
    fired.clock["t"] += 500
    _probe(fired, True, latency=200)
    assert fired == ["high_latency"]
    fired.clock["t"] += 600
    _probe(fired, True, latency=200)
    assert fired == ["high_latency", "high_latency"]

    storage.save_settings({"cooldown_sec": 0})
    _probe(fired, True, latency=200)
    assert fired.count("high_latency") == 3


def test_maintenance_defers_down_and_swallows_recovery(fired):
    storage.save_settings({"down_after_failures": 2})
    now = datetime.utcnow()
    win = storage.add_maintenance({"label": "mw", "start": (now - timedelta(hours=1)).isoformat(),
                                   "end": (now + timedelta(hours=1)).isoformat(), "device_id": None})
    for _ in range(3):
        _probe(fired, False)
    assert fired == []
    storage.remove_maintenance(win["id"])
    _probe(fired, False)                    # still down after the window: alert now
    assert fired == ["down"]

    storage.add_maintenance({"label": "mw2", "start": (now - timedelta(hours=1)).isoformat(),
                             "end": (now + timedelta(hours=1)).isoformat(), "device_id": 1})
    _probe(fired, True)                     # recovers inside a window: silent
    assert fired == ["down"]


def test_anomaly_requires_persistence(fired):
    storage.save_settings({"anomaly_window_samples": 5, "anomaly_min_samples": 3, "cooldown_sec": 0})
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    alerts.check_anomaly(DEV, 10.0, False, BASE)
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    assert fired == []                      # 2 of 3: one-off spikes don't alert
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    assert fired == ["anomaly"]             # 3 of the last 5
    for _ in range(5):
        alerts.check_anomaly(DEV, 10.0, False, BASE)
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    assert fired == ["anomaly"]             # window flushed by normal samples


def test_anomaly_honours_cooldown(fired):
    storage.save_settings({"anomaly_window_samples": 1, "anomaly_min_samples": 1, "cooldown_sec": 300})
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    assert fired == ["anomaly"]
    fired.clock["t"] += 301
    alerts.check_anomaly(DEV, 50.0, True, BASE)
    assert fired == ["anomaly", "anomaly"]
