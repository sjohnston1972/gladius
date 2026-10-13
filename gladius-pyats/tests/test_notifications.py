"""Schedule notifications: off the event loop, SMTP timeout, escaping, webhook allowlist (#49, #159)."""
import asyncio
import threading

import pydantic
import pytest


def test_email_html_escapes_untrusted_text(app):
    html = app._build_schedule_email_html(
        {"name": "<b>sched</b>"}, "partial", "summary <i>x</i>",
        "=== R1 / <bgp> ===\n+ desc: <img src=x>\n- desc: \"old\" & more\n  plain <tag>",
        "SEVERITY: HIGH\nSUMMARY: <u>sum</u>\nANALYSIS:\n1. item <a>\n- bullet <p>\nfree <q>",
    )
    for raw in ("<b>sched", "<i>x", "<img", "<bgp>", "<u>sum", "<a>", "<p>", "<q>", "<tag>"):
        assert raw not in html, raw
    for escaped in ("&lt;b&gt;sched", "&lt;img src=x&gt;", "&lt;u&gt;sum", "&quot;old&quot; &amp; more"):
        assert escaped in html, escaped
    assert "HIGH SEVERITY" in html          # our own markup survives


def test_slack_webhook_allowlist(app):
    assert app._validate_slack_webhook("") == ""
    assert app._validate_slack_webhook(None) is None
    assert app._validate_slack_webhook(" https://hooks.slack.com/services/T/B/x ") == \
        "https://hooks.slack.com/services/T/B/x"
    for bad in ("http://hooks.slack.com/x", "https://example.com/hook", "https://hooks.slack.com.evil/x"):
        with pytest.raises(ValueError):
            app._validate_slack_webhook(bad)
    with pytest.raises(pydantic.ValidationError):
        app.ScheduleCreate(name="x", device_ids=[], features=[], notify_slack="http://10.0.0.1/")
    with pytest.raises(pydantic.ValidationError):
        app.ScheduleUpdate(notify_slack="https://example.com/")


def test_send_slack_refuses_non_slack_url(app, monkeypatch):
    posts = []
    monkeypatch.setattr(app.httpx, "post", lambda *a, **kw: posts.append(a))
    app._send_slack("http://169.254.169.254/latest", "hi")
    assert posts == []


def test_smtp_has_timeout(app, monkeypatch):
    seen = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            seen["timeout"] = timeout
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): pass
        def login(self, *a): pass
        def send_message(self, msg): seen["sent"] = True

    monkeypatch.setattr(app, "SMTP_SERVER", "smtp.invalid")
    monkeypatch.setattr(app.smtplib, "SMTP", FakeSMTP)
    app._send_email_notification("ops@example.com", "subj", "<p>x</p>")
    assert seen == {"timeout": app.SMTP_TIMEOUT, "sent": True}


def test_schedule_notifications_run_off_the_event_loop(app, monkeypatch):
    threads = {}

    async def fake_learn(dev_rows, features, task_id):
        return {"results": [{"device": "R0", "feature": "bgp", "success": False, "error": "x"}]}

    async def fake_register(agent, description):
        return None

    monkeypatch.setattr(app, "_learn", fake_learn)
    monkeypatch.setattr(app, "_register_task", fake_register)
    monkeypatch.setattr(app, "_notify_schedule",
                        lambda *a: threads.setdefault("notify", threading.current_thread()))
    with app.get_db() as conn:
        conn.execute("INSERT INTO devices (id, hostname, ip) VALUES ('d0','R0','10.0.0.1')")
    sched = {"id": "s1", "name": "n", "type": "learn", "device_ids": '["d0"]', "features": '["bgp"]',
             "notify_slack": "", "notify_email": "ops@example.com", "jira_auto_ticket": ""}

    async def scenario():
        threads["loop"] = threading.current_thread()
        await app._execute_schedule(sched)

    asyncio.run(scenario())
    assert threads["notify"] is not threads["loop"]
