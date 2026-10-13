"""Load gladius-slack/app.py for unit tests without Slack.

The real slack_bolt App verifies its token over the network at construction,
so it is replaced with an inert stub before import. httpx is used for real
when installed (it is in the service image); otherwise a minimal stand-in
lets the pure helpers be tested.
"""
import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="slack-tests-"))
os.environ["HISTORY_FILE"] = str(_TMP / "data" / "history.json")


class _StubApp:
    def __init__(self, *a, **kw):
        pass

    def event(self, *a, **kw):
        return lambda fn: fn


def _install_stubs():
    slack_bolt = types.ModuleType("slack_bolt")
    slack_bolt.App = _StubApp
    adapter = types.ModuleType("slack_bolt.adapter")
    socket_mode = types.ModuleType("slack_bolt.adapter.socket_mode")
    socket_mode.SocketModeHandler = object
    sys.modules.update({
        "slack_bolt": slack_bolt,
        "slack_bolt.adapter": adapter,
        "slack_bolt.adapter.socket_mode": socket_mode,
    })
    try:
        import httpx  # noqa: F401
    except ImportError:
        httpx = types.ModuleType("httpx")
        httpx.STUB = True

        class HTTPError(Exception):
            pass

        class RequestError(HTTPError):
            pass

        class HTTPStatusError(HTTPError):
            pass

        httpx.HTTPError, httpx.RequestError, httpx.HTTPStatusError = HTTPError, RequestError, HTTPStatusError
        httpx.Client = None
        sys.modules["httpx"] = httpx


def _load_app():
    _install_stubs()
    path = Path(__file__).resolve().parent.parent / "app.py"
    spec = importlib.util.spec_from_file_location("slack_app", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_APP = _load_app()


@pytest.fixture
def app():
    return _APP
