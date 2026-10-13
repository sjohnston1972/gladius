"""Make gladius-snmp/app.py importable from the tests directory and isolate its state."""
import os
import sys
import tempfile

import pytest

# app.py derives its data paths from DEVICES_FILE at import time; point them at
# a throwaway directory so importing the module never touches /data.
os.environ.setdefault("DEVICES_FILE", os.path.join(tempfile.mkdtemp(prefix="snmp-test-"), "devices.json"))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_app_state(tmp_path, monkeypatch):
    """Fresh module state per test, data files under tmp_path, and no real HTTP."""
    monkeypatch.setattr(app, "DEVICES_FILE", tmp_path / "devices.json")
    monkeypatch.setattr(app, "ALERT_STATE_FILE", tmp_path / "alert_state.json")
    for name in ("_devices", "_status", "_last_alerted", "_open_tickets", "_tshoot_last",
                 "_proto_state", "_hold_counts"):
        monkeypatch.setattr(app, name, {})
    monkeypatch.setattr(app, "_events", [])
    monkeypatch.setattr(app, "_registry_error", None)

    def no_http(url, *a, **kw):
        raise AssertionError(f"unexpected HTTP call to {url}")
    monkeypatch.setattr(app.requests, "get", no_http)
    monkeypatch.setattr(app.requests, "post", no_http)
