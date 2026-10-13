"""Testbed export must not leak device / lab passwords (#118)."""
import asyncio

import yaml


def test_exported_testbed_is_redacted(app, monkeypatch):
    monkeypatch.setattr(app, "LAB_PASSWORD", "lab-secret-pw")
    monkeypatch.setattr(app, "LAB_USERNAME", "labuser")
    with app.get_db() as conn:
        conn.execute("INSERT INTO devices (id, hostname, ip, username, password) "
                     "VALUES ('d1','R1','10.0.0.1','admin','device-secret-pw')")
    result = asyncio.run(app.get_testbed())
    text = result["yaml"]
    assert "device-secret-pw" not in text and "lab-secret-pw" not in text
    tb = yaml.safe_load(text)
    for dev in tb["devices"].values():
        assert dev["credentials"]["default"]["password"] == app.TESTBED_PASSWORD_PLACEHOLDER
    assert tb["devices"]["R1"]["credentials"]["default"]["username"] == "admin"
    assert all("password" not in d for d in result["devices"])


def test_runner_testbed_keeps_real_credentials(app, monkeypatch):
    monkeypatch.setattr(app, "LAB_PASSWORD", "lab-secret-pw")
    tb = yaml.safe_load(app.build_testbed_yaml([
        {"hostname": "R1", "ip": "10.0.0.1", "password": "device-pw"},
        {"hostname": "R2", "ip": "10.0.0.2"},
    ]))
    assert tb["devices"]["R1"]["credentials"]["default"]["password"] == "device-pw"
    assert tb["devices"]["R2"]["credentials"]["default"]["password"] == "lab-secret-pw"
