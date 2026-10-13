"""Probe-loop resilience (#41) and atomic JSON writes."""
import json
import threading
import time

import collector
import storage


def _add_device(**extra):
    return storage.add_device({"name": "lab", "host": "192.0.2.1", "probe_type": "icmp",
                               "interval_sec": 0.02, "enabled": True, **extra})


def _wait_for(cond, timeout=3.0):
    deadline = time.time() + timeout
    while not cond() and time.time() < deadline:
        time.sleep(0.01)
    return cond()


def test_loop_survives_iteration_exception(data_dir, monkeypatch):
    dev = _add_device()
    calls = {"n": 0}

    def flaky_iteration(device, last_latency, stop_event=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return 1.0

    monkeypatch.setattr(collector, "_probe_iteration", flaky_iteration)
    monkeypatch.setattr(collector, "_ERROR_BACKOFF_SEC", 0.01)
    stop = threading.Event()
    t = threading.Thread(target=collector._device_loop, args=(dev["id"], stop), daemon=True)
    t.start()
    ok = _wait_for(lambda: calls["n"] >= 3)
    stop.set()
    t.join(timeout=2)
    assert ok, "loop died after the first exception"
    assert not t.is_alive()


def test_loop_survives_corrupt_devices_file(data_dir, monkeypatch):
    dev = _add_device()
    good = storage.DEVICES_FILE.read_text()
    storage.DEVICES_FILE.write_text(good[: len(good) // 2])  # simulate a torn write
    seen = []
    monkeypatch.setattr(collector, "_probe_iteration", lambda d, last, ev=None: seen.append(d["id"]) or 1.0)
    monkeypatch.setattr(collector, "_ERROR_BACKOFF_SEC", 0.01)
    stop = threading.Event()
    t = threading.Thread(target=collector._device_loop, args=(dev["id"], stop), daemon=True)
    t.start()
    time.sleep(0.1)
    assert t.is_alive()
    storage.DEVICES_FILE.write_text(good)
    ok = _wait_for(lambda: bool(seen))
    stop.set()
    t.join(timeout=2)
    assert ok and set(seen) == {dev["id"]}


def test_loop_exits_when_device_removed(data_dir, monkeypatch):
    dev = _add_device()
    monkeypatch.setattr(collector, "_probe_iteration", lambda d, last, ev=None: 1.0)
    storage.remove_device(dev["id"])
    stop = threading.Event()
    t = threading.Thread(target=collector._device_loop, args=(dev["id"], stop), daemon=True)
    t.start()
    t.join(timeout=2)
    assert not t.is_alive()


def test_json_writes_are_atomic_and_leave_no_temp(data_dir):
    storage.save_devices([{"id": 1, "name": "a", "host": "h"}])
    assert json.loads(storage.DEVICES_FILE.read_text())[0]["name"] == "a"
    assert not list(data_dir.glob("*.tmp"))
