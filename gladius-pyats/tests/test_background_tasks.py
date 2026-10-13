"""Background task tracking, schedule overlap guard and pyATS concurrency cap (#123)."""
import asyncio
import time


def test_overlapping_schedule_run_is_skipped(app, monkeypatch):
    release = None
    runs = []

    async def slow_execute(sched):
        runs.append(sched["id"])
        await release.wait()

    monkeypatch.setattr(app, "_execute_schedule", slow_execute)

    async def scenario():
        nonlocal release
        release = asyncio.Event()
        sched = {"id": "s1", "name": "nightly"}
        assert app._start_schedule(sched) is True
        await asyncio.sleep(0)
        assert app._start_schedule(sched) is False          # still running → skipped
        assert app._start_schedule({"id": "s2", "name": "other"}) is True
        assert len(app._background_tasks) == 2               # strong refs held
        release.set()
        await asyncio.gather(*list(app._background_tasks))
        await asyncio.sleep(0)
        assert app._background_tasks == set()
        assert app._running_schedules == set()
        assert app._start_schedule(sched) is True            # free to run again
        await asyncio.gather(*list(app._background_tasks))

    asyncio.run(scenario())
    assert runs == ["s1", "s2", "s1"]


def test_failed_background_task_is_released(app, monkeypatch):
    async def boom(sched):
        raise RuntimeError("schedule blew up")

    monkeypatch.setattr(app, "_execute_schedule", boom)

    async def scenario():
        app._start_schedule({"id": "s1", "name": "x"})
        await asyncio.gather(*list(app._background_tasks), return_exceptions=True)
        await asyncio.sleep(0)

    asyncio.run(scenario())
    assert app._running_schedules == set()
    assert app._background_tasks == set()


def test_pyats_subprocess_concurrency_is_capped(app, monkeypatch):
    active = 0
    peak = 0

    async def fake_slot(script, testbed, timeout, task_id):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.05)
        active -= 1
        return True, ""

    monkeypatch.setattr(app, "_run_script_in_slot", fake_slot)

    async def scenario():
        app._pyats_slots = asyncio.Semaphore(2)
        await asyncio.gather(*(app._run_script_once("x", "y") for _ in range(6)))

    asyncio.run(scenario())
    assert peak == 2


def test_lifespan_starts_and_cancels_background_loops(app):
    from fastapi.testclient import TestClient

    with TestClient(app.app) as client:
        names = {t.get_name() for t in app._background_tasks}
        assert {"scheduler", "ollama-monitor"} <= names
        start = time.monotonic()
        r = client.get("/health")
        assert r.status_code == 200
        assert time.monotonic() - start < 1.0
    assert app._background_tasks == set()
