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
    assert history[("C", "1.0")] == [{"role": "user", "content": "hi"},
                                     {"role": "assistant", "content": "hello"}]
    assert ("C", "1.0") in last_active
    assert not list(hist.parent.glob("*.tmp"))


def test_legacy_file_without_metadata_loads(app, hist):
    hist.write_text(json.dumps({"C|dm": [{"role": "user", "content": "x"}]}))
    history, last_active = app._load_history()
    assert history[("C", "dm")][0]["content"] == "x"
    assert last_active[("C", "dm")] == pytest.approx(time.time(), abs=60)


@pytest.mark.parametrize("bad", ["{not json", "[1, 2, 3]"])
def test_corrupt_file_is_quarantined_not_overwritten(app, hist, bad):
    hist.write_text(bad)
    history, _ = app._load_history()
    assert len(history) == 0
    assert not hist.exists()
    quarantined = list(hist.parent.glob("history.json.corrupt-*"))
    assert len(quarantined) == 1 and quarantined[0].read_text() == bad


def test_idle_conversations_expire(app, hist, monkeypatch):
    monkeypatch.setattr(app, "HISTORY_TTL_DAYS", 30)
    old = time.time() - 31 * 86400
    hist.write_text(json.dumps({
        "C|old": [{"role": "user", "content": "a"}],
        "C|new": [{"role": "user", "content": "b"}],
        app.HISTORY_META_KEY: {"C|old": old, "C|new": time.time()},
    }))
    history, last_active = app._load_history()
    assert set(history) == {("C", "new")} and set(last_active) == {("C", "new")}


def test_failed_save_keeps_previous_file(app, hist, monkeypatch):
    app._append_history(("C", "1.0"), "user", "first")
    before = hist.read_text()

    def boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(app.json, "dump", boom)
    app._append_history(("C", "1.0"), "assistant", "second")
    assert hist.read_text() == before
    assert not list(hist.parent.glob("*.tmp"))
