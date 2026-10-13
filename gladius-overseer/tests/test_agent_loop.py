"""Tests for run_agent limits/final text, error handling, threading and history trim."""
from types import SimpleNamespace as NS

import pytest


def _text(t):
    return NS(type="text", text=t)


def _tool(name="list_directory", inp=None, id_="t1"):
    return NS(type="tool_use", name=name, input=inp or {"path": "."}, id=id_)


def _resp(blocks, stop, in_tok=10, out_tok=5):
    return NS(content=blocks, stop_reason=stop, usage=NS(input_tokens=in_tok, output_tokens=out_tok))


class ScriptedModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


@pytest.fixture
def model(app, monkeypatch):
    def install(responses):
        m = ScriptedModel(responses)
        monkeypatch.setattr(app, "client_ai", m)
        return m
    return install


def test_final_text_excludes_narration(app, model):
    m = model([
        _resp([_text("Let me check."), _tool()], "tool_use"),
        _resp([_text("All good.")], "end_turn"),
    ])
    assert app.run_agent([{"role": "user", "content": "hi"}]) == "All good."
    assert m.calls[0]["model"] == app.OVERSEER_MODEL


def test_turn_limit_stops_loop(app, model, monkeypatch):
    monkeypatch.setattr(app, "MAX_TURNS", 3)
    m = model([_resp([_text("still going"), _tool()], "tool_use")])
    out = app.run_agent([{"role": "user", "content": "loop"}])
    assert len(m.calls) == 3
    assert "Stopped early" in out and "3-turn" in out and "ls →" in out


def test_token_limit_stops_loop(app, model, monkeypatch):
    monkeypatch.setattr(app, "MAX_RUN_TOKENS", 100)
    m = model([_resp([_tool()], "tool_use", in_tok=60, out_tok=0)])
    out = app.run_agent([{"role": "user", "content": "loop"}])
    assert len(m.calls) == 2 and "token" in out


def test_time_limit_excludes_approval_wait(app):
    assert app._run_limit_reason(1, 0, app.MAX_RUN_SECONDS + 1) is not None
    assert app._run_limit_reason(1, 0, 0) is None


def test_old_tool_results_are_elided(app):
    big = "x" * 10_000
    msgs = [{"role": "user", "content": "q"}]
    for i in range(5):
        msgs.append({"role": "assistant", "content": []})
        msgs.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": str(i), "content": big}]})
    app._elide_old_tool_results(msgs, keep_recent=3, max_chars=100)
    sizes = [len(m["content"][0]["content"]) for m in msgs if isinstance(m["content"], list) and m["content"]]
    assert sizes[-3:] == [10_000] * 3
    assert all(s < 300 for s in sizes[:2])
    assert msgs[0]["content"] == "q"


def test_trim_history_starts_on_user_turn(app):
    msgs = [{"role": r, "content": str(i)} for i, r in enumerate(["user", "assistant"] * 4)]
    trimmed = app._trim_history(msgs, 5)
    assert trimmed[0]["role"] == "user" and len(trimmed) == 4


@pytest.mark.parametrize("event,expected_key,expected_reply", [
    ({"channel_type": "im", "ts": "1.0"}, ("C", "dm"), None),
    ({"channel_type": "im", "ts": "2.0", "thread_ts": "1.0"}, ("C", "1.0"), "1.0"),
    ({"ts": "5.0"}, ("C", "5.0"), "5.0"),                        # top-level mention
    ({"ts": "6.0", "thread_ts": "5.0"}, ("C", "5.0"), "5.0"),    # follow-up in that thread
])
def test_thread_keys_match_reply_thread(app, event, expected_key, expected_reply):
    assert app._thread_key("C", event) == expected_key
    assert app._reply_thread_ts(event) == expected_reply


class FakeSlack:
    def __init__(self):
        self.posts, self.updates, self.deletes = [], [], []

    def chat_postMessage(self, **kw):
        self.posts.append(kw)
        return {"ts": f"9{len(self.posts)}.0"}

    def chat_update(self, **kw):
        self.updates.append(kw)

    def chat_delete(self, **kw):
        self.deletes.append(kw)


def test_agent_error_updates_placeholder_and_history(app, model, monkeypatch):
    monkeypatch.setattr(app, "_save_history", lambda *a, **kw: None)
    model([RuntimeError("overloaded")])
    slack = FakeSlack()
    key = ("C", "err-thread")
    app._process_request(slack, "C", "err-thread", key, "U1", "do it")
    assert slack.posts[0]["text"].startswith("⚙️") and slack.posts[0]["thread_ts"] == "err-thread"
    assert "overloaded" in slack.updates[-1]["text"]
    roles = [m["role"] for m in app._history[key]]
    assert roles == ["user", "assistant"]


def test_reply_posted_in_thread(app, model, monkeypatch):
    monkeypatch.setattr(app, "_save_history", lambda *a, **kw: None)
    model([_resp([_text("done")], "end_turn")])
    slack = FakeSlack()
    app._process_request(slack, "C", "7.0", ("C", "7.0"), "U1", "hi")
    assert slack.deletes and slack.posts[-1]["thread_ts"] == "7.0" and slack.posts[-1]["text"] == "done"
