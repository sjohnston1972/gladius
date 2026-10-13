"""History persistence: atomic save, corrupt-file quarantine, idle expiry."""
import json
import time
from collections import defaultdict

import pytest


@pytest.fixture
def hist(app, monkeypatch, tmp_path):
    path = tmp_path / "history.json"
    monkeypatch.setattr(app, "HISTORY_FILE", path)
    monkeypatch.setattr(app, "_history", defaultdict(list))
    monkeypatch.setattr(app, "_history_last_active", {})
    return path


def test_round_trip(app, hist):
    app._append_history(("C", "1.0"), "user", "hi")
    app._append_history(("C", "1.0"), "assistant", "hello")
    history, last_active = app._load_history()
    assert [m["content"] for m in history[("C", "1.0")]] == ["hi", "hello"]
    assert ("C", "1.0") in last_active
    assert not list(hist.parent.glob("*.tmp"))


def test_legacy_file_without_metadata_loads(app, hist):
    hist.write_text(json.dumps({"C|main": [{"role": "user", "content": "x"}]}))
    history, _ = app._load_history()
    assert history[("C", "main")][0]["content"] == "x"


@pytest.mark.parametrize("bad", ["{not json", "[1, 2, 3]"])
def test_corrupt_file_is_quarantined_not_overwritten(app, hist, bad):
    hist.write_text(bad)
    history, _ = app._load_history()
    assert len(history) == 0
    quarantined = list(hist.parent.glob("history.json.corrupt-*"))
    assert len(quarantined) == 1 and quarantined[0].read_text() == bad


def test_idle_conversations_expire(app, hist, monkeypatch):
    monkeypatch.setattr(app, "HISTORY_TTL_DAYS", 30)
    hist.write_text(json.dumps({
        "C|old": [{"role": "user", "content": "a"}],
        "C|new": [{"role": "user", "content": "b"}],
        app.HISTORY_META_KEY: {"C|old": time.time() - 31 * 86400, "C|new": time.time()},
    }))
    history, _ = app._load_history()
    assert set(history) == {("C", "new")}


def test_failed_save_keeps_previous_file(app, hist, monkeypatch):
    app._append_history(("C", "1.0"), "user", "first")
    before = hist.read_text()

    def boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(app.json, "dump", boom)
    app._append_history(("C", "1.0"), "assistant", "second")
    assert hist.read_text() == before
    assert not list(hist.parent.glob("*.tmp"))
