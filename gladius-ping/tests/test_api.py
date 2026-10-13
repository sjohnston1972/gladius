"""API-level tests (need fastapi + httpx: run inside the gladius-ping image)."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

import api  # noqa: E402
import storage  # noqa: E402

SLACK = "https://hooks.slack.com/services/T000/B000/abcdefSECRET"


@pytest.fixture
def client(data_dir, monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    return TestClient(api.app)


def test_get_settings_is_redacted(client):
    storage.save_settings({"smtp_pass": "hunter2", "slack_webhook_url": SLACK})
    body = client.get("/api/settings").json()
    assert "hunter2" not in str(body) and "SECRET" not in str(body)
    assert body["smtp_pass"] == storage.SECRET_MASK


def test_env_slack_url_is_redacted(client, monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", SLACK)
    assert "SECRET" not in str(client.get("/api/settings").json())


def test_post_settings_validates_and_keeps_masked_secrets(client):
    storage.save_settings({"smtp_pass": "hunter2", "slack_webhook_url": SLACK})
    echoed = client.get("/api/settings").json()
    echoed.update({"retention_days": 14, "latency_threshold_ms": 120, "bogus_key": "x"})
    r = client.post("/api/settings", json=echoed)
    assert r.status_code == 200, r.text
    assert "SECRET" not in r.text and "hunter2" not in r.text
    s = storage.load_settings()
    assert s["smtp_pass"] == "hunter2" and s["slack_webhook_url"] == SLACK
    assert s["retention_days"] == 14 and s["latency_threshold_ms"] == 120
    assert "bogus_key" not in s


@pytest.mark.parametrize("payload", [
    {"slack_webhook_url": "https://example.com/hook"},
    {"webhook_url": "file:///etc/passwd"},
    {"retention_days": 0},
    {"cooldown_sec": "soon"},
    {"smtp_port": 70000},
    {"smtp_host": "mail.example.com\r\nX: y"},
])
def test_post_settings_rejects_invalid(client, payload):
    r = client.post("/api/settings", json=payload)
    assert r.status_code == 422
    assert not storage.SETTINGS_FILE.exists()  # nothing persisted
