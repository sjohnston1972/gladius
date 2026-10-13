"""Focused unit tests for pure helpers in gladius-api/server.py.

These cover the history-bounding elision and the OAuth token-TTL derivation.
They import the server module (which pulls in fastapi/anthropic/etc.) but make
no network calls, so run them inside the gladius-api image with --network none.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
server = importlib.import_module("server")


def _tool_result_msg(text: str, tool_use_id: str = "t1") -> dict:
    return {
        "role": "user",
        "content": [{
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": [{"type": "text", "text": text}],
            "is_error": False,
        }],
    }


def _assistant_tool_use(tool_use_id: str = "t1") -> dict:
    return {
        "role": "assistant",
        "content": [{"type": "tool_use", "id": tool_use_id, "name": "run_show_command", "input": {}}],
    }


def test_elide_leaves_short_history_untouched():
    msgs = [{"role": "user", "content": "hi"}]
    assert server._elide_old_tool_results(msgs) == 0
    assert msgs == [{"role": "user", "content": "hi"}]


def test_elide_shrinks_old_bulky_tool_results():
    big = "X" * 5000
    # Many turns so the bulky result is well outside the keep-recent window.
    msgs = []
    for i in range(12):
        msgs.append(_assistant_tool_use(f"t{i}"))
        msgs.append(_tool_result_msg(big, f"t{i}"))
    n = server._elide_old_tool_results(msgs, keep_recent=4, elide_over=600)
    assert n >= 1
    # The oldest tool_result text must have been elided and shortened.
    first_text = msgs[1]["content"][0]["content"][0]["text"]
    assert server._HISTORY_ELIDE_MARKER in first_text
    assert len(first_text) < len(big)


def test_elide_preserves_tool_use_ids_and_recent_tail():
    big = "Y" * 5000
    msgs = []
    for i in range(12):
        msgs.append(_assistant_tool_use(f"id{i}"))
        msgs.append(_tool_result_msg(big, f"id{i}"))
    before_ids = [b["tool_use_id"]
                  for m in msgs if m["role"] == "user"
                  for b in m["content"] if b["type"] == "tool_result"]
    server._elide_old_tool_results(msgs, keep_recent=4, elide_over=600)
    after_ids = [b["tool_use_id"]
                 for m in msgs if m["role"] == "user"
                 for b in m["content"] if b["type"] == "tool_result"]
    assert before_ids == after_ids  # pairing preserved
    # The last user tool_result (within keep_recent) is untouched.
    assert msgs[-1]["content"][0]["content"][0]["text"] == big


def test_elide_is_idempotent():
    big = "Z" * 5000
    msgs = []
    for i in range(12):
        msgs.append(_assistant_tool_use(f"k{i}"))
        msgs.append(_tool_result_msg(big, f"k{i}"))
    first = server._elide_old_tool_results(msgs, keep_recent=4, elide_over=600)
    second = server._elide_old_tool_results(msgs, keep_recent=4, elide_over=600)
    assert first >= 1
    assert second == 0  # already-elided blocks are not re-elided


def test_oauth_token_ttl_from_expires_in():
    # expires_in minus the 60s safety margin.
    assert server._oauth_token_ttl({"expires_in": 3600}) == 3540
    assert server._oauth_token_ttl({"expires_in": "3600"}) == 3540


def test_oauth_token_ttl_floor_and_fallback():
    # Very short expiry floors at 60s.
    assert server._oauth_token_ttl({"expires_in": 10}) == 60
    # Missing/invalid expires_in falls back to the default cache TTL.
    assert server._oauth_token_ttl({}) == server.CACHE_TTL
    assert server._oauth_token_ttl({"expires_in": "nope"}) == server.CACHE_TTL
