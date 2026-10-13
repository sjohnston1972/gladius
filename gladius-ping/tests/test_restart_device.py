"""restart_device must always leave exactly one live probe thread (#105)."""
import threading
import time

import collector
import storage


def _wait_for(cond, timeout=3.0):
    deadline = time.time() + timeout
    while not cond() and time.time() < deadline:
        time.sleep(0.01)
    return cond()


def _setup(monkeypatch):
    first_started = threading.Event()
    release_first = threading.Event()
    calls = []

    def fake_ping(host, packet_size=None, df_bit=False):
        calls.append(threading.current_thread().name)
        if len(calls) == 1:
            first_started.set()
            release_first.wait(5)   # old generation is stuck mid-probe
            return True, 111.0
        return True, 2.0

    monkeypatch.setattr(collector, "_ping_once", fake_ping)
    monkeypatch.setattr(collector, "check_and_alert", lambda *a, **k: None)
    return first_started, release_first, calls


def test_restart_while_probe_in_flight_starts_new_generation(data_dir, monkeypatch):
    first_started, release_first, calls = _setup(monkeypatch)
    dev = storage.add_device({"name": "r1", "host": "192.0.2.10", "interval_sec": 0.05, "enabled": True})
    collector.start_device(dev["id"])
    try:
        assert first_started.wait(3)
        old_thread = collector._threads[dev["id"]]

        collector.restart_device(dev["id"])
        new_thread = collector._threads[dev["id"]]
        assert new_thread is not old_thread and new_thread.is_alive()
        assert _wait_for(lambda: len(calls) >= 3), "new generation never probed"

        release_first.set()
        old_thread.join(timeout=3)
        assert not old_thread.is_alive()
        assert new_thread.is_alive()
        # the retired thread's in-flight result is discarded, not recorded
        lats = [r["latency_ms"] for r in storage.load_results(dev["id"], hours=1)]
        assert 111.0 not in lats and 2.0 in lats
    finally:
        release_first.set()
        collector.stop_device(dev["id"])
        collector._threads[dev["id"]].join(timeout=3)


def test_start_device_does_not_duplicate_running_thread(data_dir, monkeypatch):
    first_started, release_first, calls = _setup(monkeypatch)
    release_first.set()
    dev = storage.add_device({"name": "r2", "host": "192.0.2.11", "interval_sec": 0.05, "enabled": True})
    collector.start_device(dev["id"])
    try:
        t1 = collector._threads[dev["id"]]
        collector.start_device(dev["id"])
        assert collector._threads[dev["id"]] is t1
    finally:
        collector.stop_device(dev["id"])
        collector._threads[dev["id"]].join(timeout=3)


def test_restart_disabled_device_does_not_start_probing(data_dir, monkeypatch):
    _setup(monkeypatch)
    dev = storage.add_device({"name": "r3", "host": "192.0.2.12", "interval_sec": 0.05, "enabled": False})
    collector.restart_device(dev["id"])
    t = collector._threads.get(dev["id"])
    assert t is None or not t.is_alive()
