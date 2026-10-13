"""Jira query/key validation and error surfacing (#122, #125, #158)."""
import asyncio

import httpx
import pytest
from fastapi import HTTPException


@pytest.fixture
def jira(app, monkeypatch):
    monkeypatch.setattr(app, "JIRA_CONFIGURED", True)
    monkeypatch.setattr(app, "JIRA_URL", "https://jira.invalid")
    monkeypatch.setattr(app, "JIRA_PROJECT", "GSR")
    calls = []
    state = {"handler": lambda req: httpx.Response(200, json={"issues": []})}
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        def dispatch(req):
            calls.append(req)
            return state["handler"](req)
        return real_client(*args, transport=httpx.MockTransport(dispatch), **kwargs)

    monkeypatch.setattr(app.httpx, "AsyncClient", factory)
    return app, calls, state


def test_jql_values_are_escaped(jira):
    app, calls, _ = jira
    status = 'Done" OR project = OTHER OR status = "x'
    result = asyncio.run(app.jira_issues(status=status, q='back\\slash "quote"'))
    jql = result["jql"]
    assert jql.startswith("project = GSR AND status = ")
    assert 'status = "Done\\" OR project = OTHER OR status = \\"x"' in jql
    assert 'text ~ "back\\\\slash \\"quote\\""' in jql
    assert calls[0].url.params["jql"] == jql


def test_jql_str(app):
    assert app._jql_str('a"b') == '"a\\"b"'
    assert app._jql_str("a\\") == '"a\\\\"'
    assert app._jql_str("line1\nline2") == '"line1 line2"'


@pytest.mark.parametrize("key,ok", [
    ("GSR-12", "GSR-12"), (" gsr-5 ", "GSR-5"), ("AB_1-9", "AB_1-9"),
    ("GSR-12/transitions", None), ("../myself", None), ("GSR", None), ("1GS-2", None), ("", None), (None, None),
])
def test_issue_key_validation(app, key, ok):
    if ok:
        assert app._check_issue_key(key) == ok
    else:
        with pytest.raises(HTTPException) as exc:
            app._check_issue_key(key)
        assert exc.value.status_code == 400


def test_bad_issue_key_never_reaches_jira(jira):
    app, calls, _ = jira
    for coro in (
        app.jira_issue_detail("GSR-1/../../myself"),
        app.jira_add_comment(app.JiraCommentRequest(issue_key="x/y", comment="hi")),
        app.jira_close_ticket(app.JiraCloseRequest(issue_key="GSR-1?expand=x")),
    ):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(coro)
        assert exc.value.status_code == 400
    assert calls == []


def test_jira_errors_are_surfaced_not_empty(jira):
    app, _, state = jira
    state["handler"] = lambda req: httpx.Response(401, text="unauthorized")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(app.jira_issues(status="Done"))
    assert exc.value.status_code == 502
    with pytest.raises(HTTPException) as exc:
        asyncio.run(app.jira_open_tickets())
    assert exc.value.status_code == 502

    def unreachable(req):
        raise httpx.ConnectError("refused", request=req)

    state["handler"] = unreachable
    with pytest.raises(HTTPException) as exc:
        asyncio.run(app.jira_issues())
    assert exc.value.status_code == 502


def test_open_tickets_query_uses_status_category(jira):
    app, calls, _ = jira
    asyncio.run(app.jira_open_tickets())
    assert "statusCategory != Done" in calls[0].url.params["jql"]


def test_comment_and_parse_models(jira):
    app, calls, state = jira
    state["handler"] = lambda req: httpx.Response(201, json={})
    r = asyncio.run(app.jira_add_comment(app.JiraCommentRequest(issue_key="gsr-3", comment="a\nb")))
    assert r == {"ok": True, "issue_key": "GSR-3"}
    assert calls[0].url.path == "/rest/api/3/issue/GSR-3/comment"
    parsed = asyncio.run(app.jira_parse_ticket(app.ParseTicketRequest(text="Incident Title: Core down\nPriority: P1")))
    assert parsed["summary"] == "Core down" and parsed["priority"] == "P1"
