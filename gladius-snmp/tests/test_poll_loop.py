"""Concurrent poll cycles, loop supervision and /health liveness."""
import asyncio
import json
import time

import app


def test_poll_cycle_is_concurrent_and_isolates_failures(monkeypatch):
    monkeypatch.setattr(app, "_devices", {f"d{i}": {"id": f"d{i}"} for i in range(10)})
    monkeypatch.setattr(app, "POLL_CONCURRENCY", 10)
    done = []

    async def fake_poll_one(dev_id):
        await asyncio.sleep(0.2)
        if dev_id == "d3":
            raise RuntimeError("boom")
        done.append(dev_id)
    monkeypatch.setattr(app, "_poll_one", fake_poll_one)

    t0 = time.monotonic()
    asyncio.run(app._poll_cycle())
    assert time.monotonic() - t0 < 1.0          # 10 × 0.2s serially would be 2s
    assert sorted(done) == sorted(f"d{i}" for i in range(10) if i != 3)


def test_poll_cycle_respects_concurrency_limit(monkeypatch):
    monkeypatch.setattr(app, "_devices", {f"d{i}": {} for i in range(8)})
    monkeypatch.setattr(app, "POLL_CONCURRENCY", 3)
    active, peak = 0, 0

    async def fake_poll_one(dev_id):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
    monkeypatch.setattr(app, "_poll_one", fake_poll_one)
    asyncio.run(app._poll_cycle())
    assert peak == 3


def test_supervise_restarts_crashed_loop(monkeypatch):
    monkeypatch.setattr(app, "_RESTART_DELAY", 0)
    runs = []

    async def flaky():
        runs.append(1)
        if len(runs) < 3:
            raise RuntimeError("crash")
        await asyncio.sleep(3600)

    async def go():
        task = asyncio.create_task(app._supervise("test", flaky))
        for _ in range(50):
            await asyncio.sleep(0.01)
            if len(runs) >= 3:
                break
        task.cancel()
    asyncio.run(go())
    assert len(runs) == 3


def _health(monkeypatch, *, started_ago, cycle_ago, registry_error=None):
    now = time.monotonic()
    monkeypatch.setattr(app, "POLL_INTERVAL", 60)
    monkeypatch.setattr(app, "_started_at", now - started_ago)
    monkeypatch.setattr(app, "_last_cycle_completed", None if cycle_ago is None else now - cycle_ago)
    monkeypatch.setattr(app, "_registry_error", registry_error)
    r = app.health()
    return r.status_code, json.loads(r.body)


def test_health_ok_with_recent_cycle(monkeypatch):
    code, body = _health(monkeypatch, started_ago=1000, cycle_ago=30)
    assert code == 200 and body["status"] == "ok" and body["last_cycle_age_s"] == 30.0


def test_health_ok_during_startup_grace(monkeypatch):
    code, _ = _health(monkeypatch, started_ago=10, cycle_ago=None)
    assert code == 200


def test_health_503_when_poll_loop_stalls(monkeypatch):
    code, body = _health(monkeypatch, started_ago=1000, cycle_ago=181)
    assert code == 503 and body["status"] == "error"


def test_health_503_when_no_cycle_ever_completes(monkeypatch):
    code, _ = _health(monkeypatch, started_ago=181, cycle_ago=None)
    assert code == 503


def test_health_503_when_registry_unreadable(monkeypatch):
    code, body = _health(monkeypatch, started_ago=1000, cycle_ago=5, registry_error="bad")
    assert code == 503 and "registry" in body["detail"]
