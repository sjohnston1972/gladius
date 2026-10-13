"""Timeout / kill handling for pyATS script subprocesses (#47, #48, #120)."""
import asyncio
import os
import time

import pytest

# Stand-in for a hung pyATS run: starts a grandchild (like Unicon's helpers),
# records both pids, then sleeps far longer than any test timeout.
SLEEPER = """\
import os, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
with open({pidfile!r}, "w") as f:
    f.write(f"{{os.getpid()}} {{child.pid}}")
time.sleep(30)
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); treat it as dead.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def _wait_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _wait_for_pids(pidfile: str, timeout: float = 10.0) -> list[int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(pidfile):
            text = open(pidfile).read().split()
            if len(text) == 2:
                return [int(p) for p in text]
        time.sleep(0.05)
    raise AssertionError("sleeper never wrote its pids")


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="POSIX only")
def test_timeout_kills_subprocess_and_its_children(app, tmp_path):
    os.chmod(tmp_path, 0o777)
    pidfile = str(tmp_path / "pids")
    script = SLEEPER.format(pidfile=pidfile)

    start = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(app._run_script_once(script, "devices: {}\n", timeout=2))
    assert time.monotonic() - start < 15

    parent, grandchild = _wait_for_pids(pidfile)
    assert _wait_dead(parent), "timed-out pyATS process was left running"
    assert _wait_dead(grandchild), "helper process in the run's group was left running"


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="POSIX only")
def test_kill_stops_multi_device_learn(app, monkeypatch, tmp_path):
    """Kill during the first device/feature must stop the whole learn job."""
    os.chmod(tmp_path, 0o777)
    spawned = []
    real_spawn = app._spawn_pyats_subprocess

    async def counting_spawn(*a, **kw):
        proc = await real_spawn(*a, **kw)
        spawned.append(proc.pid)
        return proc

    async def fake_register(agent, description):
        return "task-under-test"

    # _complete_task stays real (its gladius-api call is refused locally), so
    # the test covers its interaction with the cancel flag.
    monkeypatch.setattr(app, "_spawn_pyats_subprocess", counting_spawn)
    monkeypatch.setattr(app, "_register_task", fake_register)
    monkeypatch.setattr(app, "_build_learn_script",
                        lambda feature: SLEEPER.format(pidfile=str(tmp_path / f"pids-{len(spawned)}")))

    with app.get_db() as conn:
        for i in range(2):
            conn.execute("INSERT INTO devices (id, hostname, ip) VALUES (?,?,?)",
                         (f"d{i}", f"R{i}", f"10.0.0.{i}"))

    async def scenario():
        body = app.LearnRequest(device_ids=["d0", "d1"], features=["bgp", "ospf"])
        job = asyncio.create_task(app.run_learn(body))
        for _ in range(200):
            if "task-under-test" in app._active_procs:
                break
            await asyncio.sleep(0.05)
        assert "task-under-test" in app._active_procs, "learn never started a subprocess"
        await app.kill_task("task-under-test")
        return await asyncio.wait_for(job, timeout=20)

    result = asyncio.run(scenario())
    assert result.get("killed") is True
    assert len(spawned) == 1, f"learn kept spawning after kill: {len(spawned)} subprocesses"
    assert "task-under-test" not in app._cancelled_tasks, "cancel flag leaked past the job"
    assert _wait_dead(spawned[0])


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="POSIX only")
def test_kill_stops_scheduled_learn(app, monkeypatch, tmp_path):
    """A Kill on the schedule's own task id must stop its subprocesses and skip
    the diff / notification / Jira steps."""
    os.chmod(tmp_path, 0o777)
    spawned = []
    real_spawn = app._spawn_pyats_subprocess

    async def counting_spawn(*a, **kw):
        proc = await real_spawn(*a, **kw)
        spawned.append(proc.pid)
        return proc

    async def fake_register(agent, description):
        return "sched-task"

    notified = []
    monkeypatch.setattr(app, "_spawn_pyats_subprocess", counting_spawn)
    monkeypatch.setattr(app, "_register_task", fake_register)
    monkeypatch.setattr(app, "_notify_schedule", lambda *a, **kw: notified.append(a))
    monkeypatch.setattr(app, "_build_learn_script",
                        lambda feature: SLEEPER.format(pidfile=str(tmp_path / f"pids-{len(spawned)}")))

    with app.get_db() as conn:
        conn.execute("INSERT INTO devices (id, hostname, ip) VALUES ('d0','R0','10.0.0.1')")
        conn.execute("INSERT INTO devices (id, hostname, ip) VALUES ('d1','R1','10.0.0.2')")
        conn.execute(
            "INSERT INTO schedules (id,name,type,device_ids,features,cron_expr,enabled,created_at) "
            "VALUES ('s1','nightly','learn_diff','[\"d0\",\"d1\"]','[\"bgp\"]','0 * * * *',1,'now')")
        sched = dict(conn.execute("SELECT * FROM schedules WHERE id='s1'").fetchone())

    async def scenario():
        job = asyncio.create_task(app._execute_schedule(sched))
        for _ in range(200):
            if "sched-task" in app._active_procs:
                break
            await asyncio.sleep(0.05)
        assert "sched-task" in app._active_procs, "scheduled learn never registered its subprocess"
        await app.kill_task("sched-task")
        await asyncio.wait_for(job, timeout=20)

    asyncio.run(scenario())
    assert len(spawned) == 1
    assert not notified
    with app.get_db() as conn:
        row = conn.execute("SELECT last_status FROM schedules WHERE id='s1'").fetchone()
    assert row["last_status"] == "killed"
    assert "sched-task" not in app._live_tasks and "sched-task" not in app._cancelled_tasks
