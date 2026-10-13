"""Event side effects (Jira / auto-tshoot) run off the event loop."""
import asyncio
import json
import time

import pytest

import app

DEV = {"id": "d1", "host": "10.0.0.1", "name": "R1"}


class FakeResponse:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self.ok = 200 <= status < 400
        self._body = body
        self.text = text if text is not None else json.dumps(body)
        self.headers = {"content-type": "application/json" if text is None else "text/html"}

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


@pytest.fixture
def calls(monkeypatch):
    """Record requests.post calls; responses come from calls.responses[url-suffix]."""
    class Calls(list):
        responses = {}
    rec = Calls()

    def fake_post(url, **kw):
        rec.append((url, kw.get("json")))
        for suffix, resp in rec.responses.items():
            if url.endswith(suffix):
                return resp
        raise AssertionError(f"unexpected POST {url}")

    monkeypatch.setattr(app.requests, "post", fake_post)
    monkeypatch.setattr(app, "_events", [])
    return rec


def test_add_event_never_does_http_on_the_caller(calls, monkeypatch):
    monkeypatch.setattr(app, "_side_effects", None)
    evt = app._add_event(DEV, "interface_down", "critical", "Gi0/0 went DOWN", {"interface": "Gi0/0"})
    assert evt["type"] == "interface_down" and calls == []
    assert app._events == [evt]


def test_add_event_queues_ticketable_events_only(calls, monkeypatch):
    async def go():
        q = asyncio.Queue()
        monkeypatch.setattr(app, "_side_effects", q)
        app._add_event(DEV, "interface_down", "critical", "Gi0/0 went DOWN", {"interface": "Gi0/0"})
        app._add_event(DEV, "interface_up", "info", "Gi0/0 came UP", {"interface": "Gi0/0"})
        app._add_event({**DEV, "muted": True}, "bgp_down", "critical", "x")
        return [q.get_nowait()["type"] for _ in range(q.qsize())]
    assert asyncio.run(go()) == ["interface_down"]
    assert calls == []


def test_side_effects_create_ticket_then_tshoot(calls):
    calls.responses = {
        "/api/automation/jira/create": FakeResponse(200, {"ok": True, "key": "GSR-1", "url": "https://jira/GSR-1"}),
        "/api/tshoot/auto": FakeResponse(200, {"ok": True, "task_id": "t1"}),
    }
    evt = {"device_id": "d1", "host": "10.0.0.1", "type": "interface_down", "detail": "Gi0/0 went DOWN",
           "interface": "Gi0/0"}
    app._process_event_side_effects(evt)
    assert evt["jira_key"] == "GSR-1" and evt["jira_url"] == "https://jira/GSR-1"
    assert [c[0].rsplit("/api/", 1)[1] for c in calls] == ["automation/jira/create", "tshoot/auto"]
    assert calls[1][1]["jira_key"] == "GSR-1"


@pytest.mark.parametrize("resp", [
    FakeResponse(502, None, text="<html>Bad Gateway</html>"),
    FakeResponse(200, None, text="<html>not json</html>"),
    FakeResponse(500, {"detail": "Jira not configured"}),
    FakeResponse(200, {"ok": False}),
])
def test_failed_jira_create_is_handled_and_skips_tshoot(calls, resp):
    calls.responses = {"/api/automation/jira/create": resp}
    evt = {"device_id": "d1", "host": "10.0.0.1", "type": "interface_down", "detail": "Gi0/0 went DOWN",
           "interface": "Gi0/0"}
    app._process_event_side_effects(evt)       # must not raise
    assert "jira_key" not in evt
    assert len(calls) == 1


def test_worker_keeps_event_loop_responsive(monkeypatch):
    """A slow Jira call (blocking 0.3s per event) must not stall the loop."""
    monkeypatch.setattr(app, "_process_event_side_effects", lambda evt: time.sleep(0.3))

    async def go():
        q = asyncio.Queue()
        monkeypatch.setattr(app, "_side_effects", q)
        worker = asyncio.create_task(app._side_effect_worker())
        for i in range(3):
            q.put_nowait({"type": "interface_down", "detail": str(i)})
        ticks, t0 = 0, time.monotonic()
        while time.monotonic() - t0 < 0.5:
            await asyncio.sleep(0.01)
            ticks += 1
        worker.cancel()
        return ticks
    assert asyncio.run(go()) > 20
