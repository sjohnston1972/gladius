"""Tests for the Slack Approve/Deny gate on write_file, docker_restart and git push."""
import threading
import time

import pytest


class FakeSlack:
    def __init__(self):
        self.posts = []
        self.updates = []

    def chat_postMessage(self, **kw):
        self.posts.append(kw)
        return {"ts": f"{len(self.posts)}.0"}

    def chat_update(self, **kw):
        self.updates.append(kw)
        return {"ok": True}


def _approval_id(post):
    actions = next(b for b in post["blocks"] if b["type"] == "actions")
    return actions["elements"][0]["value"]


def _click(app, slack, user, approved, team=None):
    """Wait for the approval prompt to appear, then click a button on it."""
    for _ in range(200):
        if slack.posts:
            break
        time.sleep(0.01)
    body = {"user": {"id": user}, "actions": [{"value": _approval_id(slack.posts[-1])}]}
    if team:
        body["team"] = {"id": team}
    return app.resolve_approval(body, approved)


@pytest.fixture
def allow_u1(app, monkeypatch):
    monkeypatch.setattr(app, "SLACK_ALLOWED_USERS", {"U1"})
    monkeypatch.setattr(app, "SLACK_ALLOWED_TEAM", "")


def _run_in_thread(fn, *args):
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("v", fn(*args)))
    t.start()
    return t, out


def test_no_slack_context_means_denied(app, root):
    target = root / "gladius-api" / "server.py"
    before = target.read_text()
    out = app.exec_tool("write_file", {"path": str(target), "content": "changed\n"})
    assert out.startswith("Denied")
    assert target.read_text() == before


def test_approved_write_is_applied(app, root, allow_u1):
    slack = FakeSlack()
    ctx = app.RunContext(slack, "C1", "111.0", "U1")
    target = root / "gladius-api" / "new_file.py"
    t, out = _run_in_thread(app.exec_tool, "write_file", {"path": str(target), "content": "x = 1\n"}, ctx)
    assert _click(app, slack, "U1", True) == "ok"
    t.join(5)
    assert out["v"].startswith("Written")
    assert target.read_text() == "x = 1\n"
    post = slack.posts[0]
    assert post["channel"] == "C1" and post["thread_ts"] == "111.0"
    assert "Approved by <@U1>" in str(slack.updates[-1]["blocks"])


def test_denied_restart_is_not_run(app, allow_u1, monkeypatch):
    calls = []
    monkeypatch.setattr(app, "_run_docker_restart", lambda c: calls.append(c))
    slack = FakeSlack()
    ctx = app.RunContext(slack, "C1", None, "U1")
    t, out = _run_in_thread(app.exec_tool, "docker_restart", {"container": "gladius-api"}, ctx)
    assert _click(app, slack, "U1", False) == "ok"
    t.join(5)
    assert out["v"].startswith("Denied") and calls == []


def test_click_from_unlisted_user_is_ignored_and_times_out(app, root, allow_u1, monkeypatch):
    monkeypatch.setattr(app, "APPROVAL_TIMEOUT", 0.3)
    slack = FakeSlack()
    ctx = app.RunContext(slack, "C1", None, "U1")
    target = root / "gladius-api" / "other.py"
    t, out = _run_in_thread(app.exec_tool, "write_file", {"path": str(target), "content": "y\n"}, ctx)
    assert _click(app, slack, "U999", True) == "unauthorized"
    t.join(5)
    assert out["v"].startswith("Denied") and not target.exists()
    assert "denied" in str(slack.updates[-1]["blocks"]).lower()


def test_click_from_wrong_team_is_ignored(app, allow_u1, monkeypatch):
    monkeypatch.setattr(app, "SLACK_ALLOWED_TEAM", "T1")
    monkeypatch.setattr(app, "APPROVAL_TIMEOUT", 0.3)
    slack = FakeSlack()
    ctx = app.RunContext(slack, "C1", None, "U1")
    t, out = _run_in_thread(app.request_approval, ctx, "x")
    assert _click(app, slack, "U1", True, team="T2") == "unauthorized"
    t.join(5)
    assert out["v"] == (False, None)


def test_git_push_needs_approval(app, monkeypatch):
    ran = []
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **kw: ran.append(a))
    out = app.exec_tool("bash", {"command": "git push origin main"})
    assert out.startswith("Denied") and ran == []


def test_unchanged_write_skips_approval(app, root):
    target = root / "gladius-api" / "server.py"
    out = app.exec_tool("write_file", {"path": str(target), "content": target.read_text()})
    assert out.startswith("Unchanged")


def test_self_modification_is_flagged(app, root):
    assert app._is_self_path(root / "gladius-overseer" / "app.py")
    assert app._is_self_path(root / "repo" / "gladius-overseer" / "app.py")
    assert not app._is_self_path(root / "gladius-api" / "server.py")


def test_stale_click_is_expired(app, allow_u1):
    body = {"user": {"id": "U1"}, "actions": [{"value": "no-such-id"}]}
    assert app.resolve_approval(body, True) == "expired"
