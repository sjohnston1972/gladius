"""Claude / Ollama routing for every Factory LLM endpoint (#50, #116, #158)."""
import asyncio
import json
import time

import httpx
import pytest

CLAUDE_SSE_OK = (
    'event: message_start\ndata: {"type":"message_start","message":{}}\n\n'
    'event: ping\ndata: {"type":"ping"}\n\n'
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
    '"delta":{"type":"text_delta","text":"Hello "}}\n\n'
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
    '"delta":{"type":"text_delta","text":"world"}}\n\n'
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)
CLAUDE_SSE_ERROR = (
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
    '"delta":{"type":"text_delta","text":"partial"}}\n\n'
    'event: error\ndata: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}\n\n'
)


@pytest.fixture
def mock_http(app, monkeypatch):
    """Route every httpx.AsyncClient the app creates through a handler; records requests."""
    calls = []
    state = {"handler": None}
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(_dispatch), **kwargs)

    def _dispatch(request: httpx.Request):
        calls.append(request)
        return state["handler"](request)

    monkeypatch.setattr(app.httpx, "AsyncClient", factory)
    return calls, state


def _events(gen) -> list[dict]:
    async def collect():
        return [json.loads(chunk[len("data: "):]) async for chunk in gen]
    return asyncio.run(collect())


def _set_ollama(app, ok: bool):
    app._ollama_status.update(ok=ok, checked_at=time.monotonic(), models=["qwen2.5-coder:7b"] if ok else [])


def test_anthropic_payload_conversion(app):
    p = app._anthropic_payload("claude-x", "SYS", [
        {"role": "assistant", "content": "leading assistant turn is dropped"},
        {"role": "system", "content": "extra system"},
        {"role": "user", "content": "a"},
        {"role": "user", "content": "b"},
        {"role": "assistant", "content": ""},
        {"role": "assistant", "content": "c"},
    ], max_tokens=100, stream=True)
    assert p["system"] == "SYS\n\nextra system"
    assert p["messages"] == [{"role": "user", "content": "a\n\nb"}, {"role": "assistant", "content": "c"}]
    assert p["stream"] is True and p["max_tokens"] == 100 and p["model"] == "claude-x"
    with pytest.raises(app.LLMError):
        app._anthropic_payload("claude-x", "", [{"role": "assistant", "content": "x"}], 10, False)


def test_anthropic_sse_event_parsing(app):
    assert app._anthropic_sse_event('data: {"type":"ping"}') is None
    assert app._anthropic_sse_event("event: content_block_delta") is None
    assert app._anthropic_sse_event(
        'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"x"}}') == ("text", "x")
    kind, msg = app._anthropic_sse_event('data: {"type":"error","error":{"type":"overloaded_error","message":"busy"}}')
    assert kind == "error" and "overloaded_error" in msg and "busy" in msg
    assert app._anthropic_sse_event('data: {"type":"message_stop"}') == ("stop", "")


def test_ollama_stream_event_parsing(app):
    assert app._ollama_stream_event('{"message":{"content":"hi"},"done":false}') == ("text", "hi")
    assert app._ollama_stream_event('{"message":{"content":""},"done":true}') == ("stop", "")
    assert app._ollama_stream_event('{"error":"model not found"}')[0] == "error"
    assert app._ollama_stream_event("") is None


def test_claude_model_streams_from_anthropic(app, mock_http, monkeypatch):
    calls, state = mock_http
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "test-key")
    state["handler"] = lambda req: httpx.Response(200, text=CLAUDE_SSE_OK,
                                                  headers={"content-type": "text/event-stream"})
    events = _events(app._llm_sse("claude-haiku-5-5", "SYSTEM", [{"role": "user", "content": "hi"}]))
    assert events == [{"type": "text", "content": "Hello "}, {"type": "text", "content": "world"}, {"type": "done"}]
    assert len(calls) == 1 and calls[0].url.host == "api.anthropic.com"
    body = json.loads(calls[0].content)
    assert body["system"] == "SYSTEM" and body["model"] == "claude-haiku-5-5" and body["stream"] is True
    assert calls[0].headers["x-api-key"] == "test-key"


def test_claude_stream_error_event_is_surfaced(app, mock_http, monkeypatch):
    _, state = mock_http
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "test-key")
    state["handler"] = lambda req: httpx.Response(200, text=CLAUDE_SSE_ERROR)
    events = _events(app._llm_sse("claude-haiku-5-5", "", [{"role": "user", "content": "hi"}]))
    assert events[0] == {"type": "text", "content": "partial"}
    assert events[-1]["type"] == "error" and "Overloaded" in events[-1]["content"]
    assert {"type": "done"} not in events


def test_claude_http_error_is_surfaced(app, mock_http, monkeypatch):
    _, state = mock_http
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "test-key")
    state["handler"] = lambda req: httpx.Response(401, text='{"error":"bad key"}')
    events = _events(app._llm_sse("claude-haiku-5-5", "", [{"role": "user", "content": "hi"}]))
    assert events == [{"type": "error", "content": 'Claude API 401: {"error":"bad key"}'}]


def test_ollama_model_streams_from_ollama(app, mock_http):
    calls, state = mock_http
    body = '{"message":{"content":"a"},"done":false}\n{"message":{"content":"b"},"done":false}\n{"done":true}\n'
    state["handler"] = lambda req: httpx.Response(200, text=body)
    events = _events(app._llm_sse("qwen2.5-coder:7b", "SYS", [{"role": "user", "content": "hi"}]))
    assert events == [{"type": "text", "content": "a"}, {"type": "text", "content": "b"}, {"type": "done"}]
    sent = json.loads(calls[0].content)
    assert sent["messages"][0] == {"role": "system", "content": "SYS"}
    assert calls[0].url.path == "/api/chat"


def test_unreachable_ollama_falls_back_to_claude(app, mock_http, monkeypatch):
    calls, state = mock_http
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "test-key")

    def handler(req):
        if req.url.host == "api.anthropic.com":
            return httpx.Response(200, text=CLAUDE_SSE_OK)
        raise httpx.ConnectError("connection refused", request=req)

    state["handler"] = handler
    _set_ollama(app, True)
    events = _events(app._llm_sse("qwen2.5:7b", "SYS", [{"role": "user", "content": "hi"}]))
    assert [e["type"] for e in events] == ["text", "text", "done"]
    assert json.loads(calls[-1].content)["model"] == app.CLAUDE_MODEL
    assert app._ollama_status["ok"] is False


def test_unreachable_ollama_without_key_errors_fast(app, mock_http):
    _, state = mock_http

    def handler(req):
        raise httpx.ConnectError("connection refused", request=req)

    state["handler"] = handler
    events = _events(app._llm_sse("qwen2.5:7b", "", [{"role": "user", "content": "hi"}]))
    assert events == [{"type": "error", "content": f"Ollama is unreachable at {app.OLLAMA_URL} (ConnectError)"}]


def test_pick_model(app, monkeypatch):
    _set_ollama(app, False)
    assert asyncio.run(app._pick_model("qwen2.5:7b", "x")) == "qwen2.5:7b"     # no key → no fallback
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "k")
    assert asyncio.run(app._pick_model("qwen2.5:7b", "x")) == app.CLAUDE_MODEL
    assert asyncio.run(app._pick_model(None, "qwen2.5:7b")) == app.CLAUDE_MODEL
    assert asyncio.run(app._pick_model("claude-sonnet-4-6", "x")) == "claude-sonnet-4-6"
    _set_ollama(app, True)
    assert asyncio.run(app._pick_model(None, "qwen2.5:7b")) == "qwen2.5:7b"


def test_models_endpoint_defaults_to_claude_when_ollama_down(app, monkeypatch):
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "k")
    _set_ollama(app, False)
    r = asyncio.run(app.list_models())
    assert r["ollama_available"] is False
    assert r["default"] == app.CLAUDE_MODEL
    assert app.OLLAMA_MODEL not in r["models"] and app.CLAUDE_MODEL in r["models"]
    _set_ollama(app, True)
    r = asyncio.run(app.list_models())
    assert r["ollama_available"] is True and r["default"] == app.OLLAMA_MODEL
    assert "qwen2.5-coder:7b" in r["models"]


def test_llm_complete_claude_and_analyze_route(app, mock_http, monkeypatch):
    calls, state = mock_http
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "k")
    state["handler"] = lambda req: httpx.Response(200, json={
        "content": [{"type": "text", "text": "SEVERITY: LOW\nSUMMARY: nothing"}]})
    body = app.AnalyzeRequest(diff_text="- a\n+ b", feature="bgp", device="R1", model="claude-sonnet-4-6")
    result = asyncio.run(app.analyze_diff(body))
    assert result == {"analysis": "SEVERITY: LOW\nSUMMARY: nothing", "model": "claude-sonnet-4-6"}
    assert calls[0].url.host == "api.anthropic.com" and "stream" not in json.loads(calls[0].content)


def test_autofix_uses_callers_claude_model(app, mock_http, monkeypatch):
    calls, state = mock_http
    monkeypatch.setattr(app, "ANTHROPIC_API_KEY", "k")
    state["handler"] = lambda req: httpx.Response(200, json={
        "content": [{"type": "text", "text": "```python\nprint('fixed')\n```"}]})
    fixed = asyncio.run(app._autofix_script("print(", "SyntaxError", model="claude-sonnet-4-6"))
    assert fixed == "print('fixed')"
    assert json.loads(calls[0].content)["model"] == "claude-sonnet-4-6"
