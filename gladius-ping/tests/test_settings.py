"""Settings redaction and webhook URL validation helpers (#107)."""
import pytest

import storage

SLACK = "https://hooks.slack.com/services/T000/B000/abcdefSECRET"


def test_redact_masks_secrets_and_keeps_empty_values():
    s = {"smtp_pass": "hunter2", "slack_webhook_url": SLACK, "discord_webhook_url": "",
         "teams_webhook_url": "https://example.webhook.office.com/webhookb2/SECRET",
         "webhook_url": "http://user:pw@10.0.0.5:9000/hook?token=SECRET", "cooldown_sec": 300}
    r = storage.redact_settings(s)
    assert r["smtp_pass"] == storage.SECRET_MASK
    assert r["slack_webhook_url"] == f"https://hooks.slack.com/{storage.SECRET_MASK}"
    assert r["discord_webhook_url"] == ""
    assert r["webhook_url"] == f"http://10.0.0.5/{storage.SECRET_MASK}"
    assert "SECRET" not in repr(r) and "hunter2" not in repr(r) and "pw" not in r["webhook_url"]
    assert r["cooldown_sec"] == 300
    assert s["smtp_pass"] == "hunter2"          # input not mutated


def test_masked_values_round_trip_as_unchanged(data_dir):
    storage.save_settings({"smtp_pass": "hunter2", "slack_webhook_url": SLACK})
    echoed = storage.redact_settings(storage.load_settings())
    echoed["cooldown_sec"] = 60
    storage.save_settings(storage.drop_masked(echoed))
    s = storage.load_settings()
    assert s["smtp_pass"] == "hunter2" and s["slack_webhook_url"] == SLACK
    assert s["cooldown_sec"] == 60
    # an explicit empty string still clears a secret
    storage.save_settings(storage.drop_masked({"slack_webhook_url": ""}))
    assert storage.load_settings()["slack_webhook_url"] == ""


@pytest.mark.parametrize("key,url", [
    ("slack_webhook_url", SLACK),
    ("slack_webhook_url", ""),
    ("slack_webhook_url", f"https://hooks.slack.com/{storage.SECRET_MASK}"),
    ("discord_webhook_url", "https://discord.com/api/webhooks/1/abc"),
    ("teams_webhook_url", "https://contoso.webhook.office.com/webhookb2/x"),
    ("webhook_url", "http://10.0.0.5:9000/hook"),
])
def test_valid_webhook_urls(key, url):
    assert storage.validate_webhook_url(key, url) == url


@pytest.mark.parametrize("key,url", [
    ("slack_webhook_url", "http://hooks.slack.com/services/x"),   # not https
    ("slack_webhook_url", "https://example.com/services/x"),      # wrong vendor host
    ("discord_webhook_url", "https://evil.example/api/webhooks/1"),
    ("teams_webhook_url", "file:///etc/passwd"),
    ("webhook_url", "gopher://10.0.0.5/x"),
    ("webhook_url", "https:///nohost"),
    ("webhook_url", "http://10.0.0.5/a b"),
])
def test_invalid_webhook_urls(key, url):
    with pytest.raises(ValueError):
        storage.validate_webhook_url(key, url)
