"""Persistent alert state: restart baseline, Jira ticket dedupe, auto-tshoot cooldown."""
import asyncio
import json
import time

import pytest

import app
from test_side_effects import FakeResponse

DEV = {"id": "d1", "host": "10.0.0.1", "name": "R1"}


@pytest.fixture
def alert_state():
    return app.ALERT_STATE_FILE   # per-test tmp path (conftest)


@pytest.mark.parametrize("prev, new, expected", [
    (None,    "ok",    "baseline"),
    (None,    "error", "baseline"),
    ("ok",    "error", "degraded"),
    ("ok",    "warn",  "degraded"),
    ("warn",  "error", "degraded"),
    ("error", "error", None),
    ("error", "warn",  None),
    ("error", "ok",    "recovered"),
    ("warn",  "ok",    "recovered"),
    ("ok",    "ok",    None),
])
def test_alert_transition(prev, new, expected):
    assert app._alert_transition(prev, new) == expected


def test_alert_state_roundtrip(alert_state):
    app._last_alerted.update({"d1": "error", "d2": "ok"})
    app._open_tickets["d1|device_down|"] = {"key": "GSR-7", "url": "u", "created": time.time()}
    app._tshoot_last["d1"] = 123.0
    app._save_alert_state()
    saved = json.loads(alert_state.read_text())
    app._last_alerted.clear(), app._open_tickets.clear(), app._tshoot_last.clear()
    app._load_alert_state()
    assert app._last_alerted == {"d1": "error", "d2": "ok"}
    assert app._open_tickets["d1|device_down|"]["key"] == "GSR-7"
    assert app._tshoot_last == {"d1": 123.0}
    assert saved["last_alerted"]["d1"] == "error"


def test_expired_tickets_are_pruned_on_save():
    app._open_tickets["old"] = {"key": "GSR-1", "created": time.time() - app.JIRA_DEDUPE_SECS - 10}
    app._open_tickets["new"] = {"key": "GSR-2", "created": time.time()}
    app._save_alert_state()
    assert list(app._open_tickets) == ["new"]


@pytest.mark.parametrize("content", ["{not json", "[]", ""])
def test_unreadable_alert_state_is_ignored(alert_state, content):
    alert_state.write_text(content)
    app._load_alert_state()          # must not raise
    assert app._last_alerted == {}


# ── Restart behaviour of _poll_one ────────────────────────────────────────────

def _run_poll(monkeypatch, status):
    """Run one _poll_one for DEV with the given poll status; return (events, alerts spawned)."""
    result = {"status": status, "last_poll": app.datetime.now(app.timezone.utc).isoformat(),
              "response_ms": 5, "error": None if status == "ok" else "timeout"}
    monkeypatch.setattr(app, "_devices", {"d1": dict(DEV)})
    monkeypatch.setattr(app, "_status", {})
    monkeypatch.setattr(app, "_proto_state", {})
    monkeypatch.setattr(app, "_poll_device_sync", lambda dev: dict(result))
    monkeypatch.setattr(app, "_poll_protocol_state_sync",
                        lambda dev: {"interfaces": None, "bgp": None, "ospf": None})
    events, spawned = [], []
    monkeypatch.setattr(app, "_add_event", lambda dev, *spec: events.append(spec[0]))

    def fake_spawn(coro):
        coro.close()
        spawned.append(True)
    monkeypatch.setattr(app, "_spawn", fake_spawn)
    asyncio.run(app._poll_one("d1"))
    return events, spawned


def test_restart_with_device_still_down_does_not_realert(monkeypatch, alert_state):
    alert_state.write_text(json.dumps({"last_alerted": {"d1": "error"}}))
    app._load_alert_state()
    assert _run_poll(monkeypatch, "error") == ([], [])


def test_first_poll_without_state_is_baseline(monkeypatch, alert_state):
    assert _run_poll(monkeypatch, "error") == ([], [])
    assert json.loads(alert_state.read_text())["last_alerted"] == {"d1": "error"}


def test_degradation_after_baseline_alerts(monkeypatch):
    app._last_alerted["d1"] = "ok"
    assert _run_poll(monkeypatch, "error") == (["device_down"], [True])
    assert app._last_alerted["d1"] == "error"


def test_recovery_across_restart_is_reported(monkeypatch, alert_state):
    alert_state.write_text(json.dumps({"last_alerted": {"d1": "error"}}))
    app._load_alert_state()
    assert _run_poll(monkeypatch, "ok") == (["device_up"], [])
    assert app._last_alerted["d1"] == "ok"


# ── Jira dedupe and auto-tshoot cooldown ──────────────────────────────────────

@pytest.fixture
def http(monkeypatch):
    class Http:
        posts, gets = [], []
        jira_status = "In Progress"
        next_key = 1

    def fake_post(url, **kw):
        Http.posts.append(url.rsplit("/api/", 1)[1])
        if url.endswith("/jira/create"):
            key = f"GSR-{Http.next_key}"
            Http.next_key += 1
            return FakeResponse(200, {"ok": True, "key": key, "url": f"https://jira/{key}"})
        return FakeResponse(200, {"ok": True})

    def fake_get(url, **kw):
        Http.gets.append(url.rsplit("/api/", 1)[1])
        return FakeResponse(200, {"key": url.rsplit("/", 1)[1], "status": Http.jira_status})

    Http.posts, Http.gets = [], []
    monkeypatch.setattr(app.requests, "post", fake_post)
    monkeypatch.setattr(app.requests, "get", fake_get)
    return Http


def iface_down(iface="Gi0/0", dev_id="d1"):
    return {"device_id": dev_id, "host": "10.0.0.1", "type": "interface_down", "severity": "critical",
            "detail": f"{iface} went DOWN", "interface": iface, "timestamp": "2026-10-13T00:00:00+00:00"}


def test_flapping_interface_reuses_open_ticket(http):
    first, second = iface_down(), iface_down()
    app._process_event_side_effects(first)
    app._process_event_side_effects(second)
    assert first["jira_key"] == second["jira_key"] == "GSR-1"
    assert second["jira_deduped"] is True
    assert http.posts == ["automation/jira/create", "tshoot/auto", "automation/jira/comment"]
    assert http.gets == ["automation/jira/issue/GSR-1"]


def test_closed_ticket_gets_a_new_one(http):
    app._process_event_side_effects(iface_down())
    http.jira_status = "Done"
    again = iface_down()
    app._tshoot_last.clear()
    app._process_event_side_effects(again)
    assert again["jira_key"] == "GSR-2" and "jira_deduped" not in again
    assert http.posts.count("automation/jira/create") == 2


def test_expired_ticket_gets_a_new_one_without_status_check(http):
    app._process_event_side_effects(iface_down())
    app._open_tickets["d1|interface_down|Gi0/0"]["created"] -= app.JIRA_DEDUPE_SECS + 1
    again = iface_down()
    app._process_event_side_effects(again)
    assert again["jira_key"] == "GSR-2"
    assert http.gets == []


def test_different_subjects_get_separate_tickets_but_one_tshoot_per_device(http):
    a, b = iface_down("Gi0/0"), iface_down("Gi0/1")
    app._process_event_side_effects(a)
    app._process_event_side_effects(b)
    assert (a["jira_key"], b["jira_key"]) == ("GSR-1", "GSR-2")
    assert http.posts.count("tshoot/auto") == 1      # cooldown per device


def test_open_tickets_survive_restart(http):
    app._process_event_side_effects(iface_down())
    app._open_tickets.clear()
    app._load_alert_state()
    again = iface_down()
    app._process_event_side_effects(again)
    assert again["jira_key"] == "GSR-1" and again["jira_deduped"]
