"""Shared fixtures for gladius-pyats tests.

The tests import app.py directly, so they need the service's dependencies
(fastapi, httpx, pyyaml, ...). Run them inside the gladius-pyats image with
no network, e.g.:

    docker run --rm --network none -v <repo>/gladius-pyats:/src -w /src \
        --entrypoint python gladius-pyats-gladius-pyats:latest -m pytest tests -q
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Point the service at a throwaway DB *before* app.py is imported, and keep it
# away from any real Slack / Jira / Anthropic / Ollama configuration.
_TMP = tempfile.mkdtemp(prefix="gladius-pyats-tests-")
os.environ["DB_PATH"] = os.path.join(_TMP, "scripts.db")
for _var in ("JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT",
             "ANTHROPIC_API_KEY", "SMTP_SERVER", "GLADIUS_API_TOKEN"):
    os.environ[_var] = ""
os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"        # discard port — refused
os.environ["GLADIUS_API_URL"] = "http://127.0.0.1:9"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402


@pytest.fixture
def app():
    """The app module with a fresh DB and side-effect-free task hooks."""
    if os.path.exists(app_module.DB_PATH):
        os.remove(app_module.DB_PATH)
    app_module.init_db()
    app_module._active_procs.clear()
    app_module._cancelled_tasks.clear()
    app_module._live_tasks.clear()
    app_module._running_schedules.clear()
    # asyncio primitives bind to the first loop that waits on them; each test
    # runs its own loop, so give each one a fresh semaphore.
    app_module._pyats_slots = asyncio.Semaphore(app_module.PYATS_MAX_CONCURRENT)
    return app_module


@pytest.fixture(autouse=True)
def _no_fs_hardening(monkeypatch):
    # _harden_fs_permissions chmods the app/data dirs; never do that to the
    # bind-mounted source tree under test.
    monkeypatch.setattr(app_module, "_harden_fs_permissions", lambda: None)
