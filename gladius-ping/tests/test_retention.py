"""Retention purge covers every data file and holds the lock across read+rewrite (#42, #106)."""
import builtins
import csv
import threading
from datetime import timedelta

import storage


def _write(path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _count(path):
    with open(path, newline="") as f:
        return sum(1 for _ in csv.DictReader(f))


def _seed(now):
    old = (now - timedelta(days=40)).isoformat()
    new = (now - timedelta(days=1)).isoformat()
    _write(storage.RESULTS_DIR / "device_1.csv", ["timestamp", "latency_ms", "success", "jitter_ms"],
           [[old, 1.0, 1, ""]] * 5 + [[new, 2.0, 1, ""]] * 3)
    _write(storage.TRACES_DIR / "device_1.csv", ["timestamp", "hop", "ip", "lat1", "lat2", "lat3"],
           [[old, 1, "192.0.2.1", 1, 1, 1]] * 4 + [[new, 1, "192.0.2.1", 1, 1, 1]] * 2)
    _write(storage.ALERT_LOG, ["timestamp", "device_id", "device_name", "alert_type", "value", "threshold"],
           [[old, 1, "core, sw1", "down", 0, 0]] * 6 + [[new, 1, "core, sw1", "down", 0, 0]])
    _write(storage.SPEEDTEST_FILE, ["timestamp", "download_mbps", "upload_mbps", "ping_ms", "server", "isp"],
           [[old, 100, 10, 5, "s", "i"]] * 2 + [[new, 100, 10, 5, "s", "i"]] * 2)


def test_purge_covers_all_data_files(data_dir):
    _seed(storage.utcnow())
    purged = storage.purge_old_data(30)
    assert purged == 5 + 4 + 6 + 2
    assert _count(storage.RESULTS_DIR / "device_1.csv") == 3
    assert _count(storage.TRACES_DIR / "device_1.csv") == 2
    assert _count(storage.ALERT_LOG) == 1
    assert _count(storage.SPEEDTEST_FILE) == 2
    # quoted fields survive the rewrite
    assert storage.load_alerts()[0]["device_name"] == "core, sw1"
    assert not list(data_dir.rglob("*.tmp"))
    assert storage.purge_old_data(30) == 0


def test_purge_holds_lock_while_reading_and_writing(data_dir, monkeypatch):
    _seed(storage.utcnow())
    unlocked = []
    real_open = builtins.open

    def spy_open(file, *a, **k):
        if str(file).endswith((".csv", ".csv.tmp")) and not storage._lock._is_owned():
            unlocked.append(str(file))
        return real_open(file, *a, **k)

    monkeypatch.setattr(storage, "open", spy_open, raising=False)
    storage.purge_old_data(30)
    assert unlocked == []


def test_concurrent_appends_are_not_lost(data_dir):
    now = storage.utcnow()
    rows = [[(now - timedelta(days=40)).isoformat(), 1.0, 1, ""]] * 20000
    _write(storage.RESULTS_DIR / "device_7.csv", ["timestamp", "latency_ms", "success", "jitter_ms"], rows)
    stop = threading.Event()
    appended = {"n": 0}

    def writer():
        while not stop.is_set():
            storage.save_result(7, 3.0, True, None)
            appended["n"] += 1

    t = threading.Thread(target=writer)
    t.start()
    try:
        storage.purge_old_data(30)
    finally:
        stop.set()
        t.join()
    assert appended["n"] > 0
    assert len(storage.load_results(7, hours=1)) == appended["n"]


def test_run_retention_uses_setting_and_records_last_purge(data_dir):
    _seed(storage.utcnow())
    storage.save_settings({"retention_days": 60})
    assert storage.run_retention() == 0
    info = storage.last_purge_info()
    assert info["retention_days"] == 60 and info["at"] is not None
    storage.save_settings({"retention_days": 30})
    assert storage.run_retention() == 17


def test_run_retention_skips_invalid_days(data_dir):
    _seed(storage.utcnow())
    storage.save_settings({"retention_days": 0})
    assert storage.run_retention() == 0
    assert _count(storage.RESULTS_DIR / "device_1.csv") == 8
