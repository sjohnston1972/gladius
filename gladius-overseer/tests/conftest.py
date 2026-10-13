"""Load gladius-overseer/app.py for unit tests without Slack/Anthropic.

The real slack_bolt App verifies its token over the network at construction
and the Anthropic client needs a key, so both are replaced with inert stubs
before the module is imported. OVERSEER_ROOT and HISTORY_FILE point at a
temporary directory.
"""
import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="overseer-tests-"))
ROOT = (_TMP / "projects").resolve()
REPO = ROOT / "repo"
REPO.mkdir(parents=True)
(REPO / ".git").mkdir()
(ROOT / "gladius-api").mkdir()
(ROOT / "gladius-api" / "server.py").write_text("print('hi')\n")
(ROOT / "gladius-api" / ".env").write_text("X=1\n")

os.environ["OVERSEER_ROOT"] = str(ROOT)
os.environ["OVERSEER_GIT_DIR"] = str(REPO)
os.environ["HISTORY_FILE"] = str(_TMP / "data" / "history.json")


class _StubApp:
    def __init__(self, *a, **kw):
        pass

    def event(self, *a, **kw):
        return lambda fn: fn

    def action(self, *a, **kw):
        return lambda fn: fn


class _StubWebClient:
    def __init__(self, *a, **kw):
        pass


def _install_stubs():
    anthropic = types.ModuleType("anthropic")
    anthropic.Anthropic = lambda *a, **kw: types.SimpleNamespace(messages=None)
    slack_bolt = types.ModuleType("slack_bolt")
    slack_bolt.App = _StubApp
    adapter = types.ModuleType("slack_bolt.adapter")
    socket_mode = types.ModuleType("slack_bolt.adapter.socket_mode")
    socket_mode.SocketModeHandler = object
    slack_sdk = types.ModuleType("slack_sdk")
    slack_sdk.WebClient = _StubWebClient
    sys.modules.update({
        "anthropic": anthropic,
        "slack_bolt": slack_bolt,
        "slack_bolt.adapter": adapter,
        "slack_bolt.adapter.socket_mode": socket_mode,
        "slack_sdk": slack_sdk,
    })


def _load_app():
    _install_stubs()
    path = Path(__file__).resolve().parent.parent / "app.py"
    spec = importlib.util.spec_from_file_location("overseer_app", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_APP = _load_app()


@pytest.fixture
def app():
    return _APP


@pytest.fixture
def root():
    return ROOT


@pytest.fixture
def repo():
    return REPO
