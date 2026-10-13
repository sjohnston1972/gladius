"""Alert delivery runs on a worker thread, not the probe thread (#109)."""
import threading
import time

import alerts
import storage

DEV = {"id": 3, "name": "wan", "host": "192.0.2.3"}


def test_fire_alert_returns_before_slow_senders(data_dir, monkeypatch):
    delivered = []
    settings_seen = []
    release = threading.Event()

    def slow(name):
        def sender(*args):
            settings_seen.append(args[-1])
            release.wait(5)          # an unreachable notification target
            delivered.append(name)
        return sender

    for name in ("_send_slack", "_send_discord", "_send_teams", "_send_email", "_send_webhook"):
        monkeypatch.setattr(alerts, name, slow(name))
    loads = {"n": 0}
    real_load = alerts.load_settings

    def counting_load():
        loads["n"] += 1
        return real_load()

    monkeypatch.setattr(alerts, "load_settings", counting_load)

    t0 = time.monotonic()
    alerts._fire_alert(DEV, "down", ":red_circle: wan is DOWN", 3, 3)
    assert time.monotonic() - t0 < 0.5, "probe thread blocked on notification senders"
    # the alert log is written synchronously
    assert [a["alert_type"] for a in storage.load_alerts()] == ["down"]

    release.set()
    deadline = time.time() + 5
    while len(delivered) < 5 and time.time() < deadline:
        time.sleep(0.01)
    assert delivered == ["_send_slack", "_send_discord", "_send_teams", "_send_email", "_send_webhook"]
    assert loads["n"] == 1, "settings should be loaded once per alert"
    assert all(s is settings_seen[0] for s in settings_seen)


def test_sender_exception_does_not_kill_notifier(data_dir, monkeypatch):
    delivered = []

    def deliver(device, alert_type, *rest):
        if alert_type == "down":
            raise RuntimeError("smtp down")
        delivered.append(alert_type)

    monkeypatch.setattr(alerts, "_deliver", deliver)
    alerts._fire_alert(DEV, "down", "x")
    alerts._fire_alert(DEV, "up", "y")
    deadline = time.time() + 5
    while not delivered and time.time() < deadline:
        time.sleep(0.01)
    assert delivered == ["up"]
