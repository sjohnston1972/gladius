"""Atomic devices.json load/save, including the corrupt-file paths."""
import json

import pytest
from fastapi import HTTPException

import app

DEV_A = {"a": {"id": "a", "host": "10.0.0.1", "community": "s3cret"}}
DEV_B = {"b": {"id": "b", "host": "10.0.0.2", "community": "s3cret"}}


@pytest.fixture
def registry(tmp_path, monkeypatch):
    path = tmp_path / "devices.json"
    monkeypatch.setattr(app, "DEVICES_FILE", path)
    monkeypatch.setattr(app, "_devices", {})
    monkeypatch.setattr(app, "_registry_error", None)
    return path


def _bak(path):
    return path.with_name(path.name + ".bak")


def _leftovers(path):
    return [p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")]


def test_missing_file_loads_empty_and_is_writable(registry):
    app._load_devices()
    assert app._devices == {}
    assert app._registry_error is None


def test_save_load_roundtrip(registry):
    app._devices = dict(DEV_A)
    app._save_devices()
    assert json.loads(registry.read_text()) == DEV_A
    assert _leftovers(registry) == []
    app._devices = {}
    app._load_devices()
    assert app._devices == DEV_A


def test_save_keeps_previous_good_version_as_bak(registry):
    app._devices = dict(DEV_A)
    app._save_devices()
    app._devices = {**DEV_A, **DEV_B}
    app._save_devices()
    assert json.loads(_bak(registry).read_text()) == DEV_A
    assert json.loads(registry.read_text()) == {**DEV_A, **DEV_B}


def test_failed_write_leaves_original_intact(registry):
    app._devices = dict(DEV_A)
    app._save_devices()
    app._devices = {"x": {"bad": object()}}   # not JSON-serialisable
    app._save_devices()                        # logs, does not raise
    assert json.loads(registry.read_text()) == DEV_A
    assert _leftovers(registry) == []


@pytest.mark.parametrize("bad_content", ["{not json", "", "[1, 2, 3]"])
def test_corrupt_file_restores_from_bak(registry, bad_content):
    _bak(registry).write_text(json.dumps(DEV_A))
    registry.write_text(bad_content)
    app._load_devices()
    assert app._devices == DEV_A
    assert app._registry_error is None
    corrupt = list(registry.parent.glob("devices.json.corrupt-*"))
    assert len(corrupt) == 1 and corrupt[0].read_text() == bad_content
    # A save now replaces the corrupt file but must not clobber the good .bak
    app._devices = {**DEV_A, **DEV_B}
    app._save_devices()
    assert json.loads(registry.read_text()) == {**DEV_A, **DEV_B}
    assert json.loads(_bak(registry).read_text()) == DEV_A


def test_corrupt_file_without_bak_makes_registry_read_only(registry):
    registry.write_text("{truncated")
    app._load_devices()
    assert app._devices == {}
    assert app._registry_error
    assert list(registry.parent.glob("devices.json.corrupt-*"))
    # Saving is refused: the unreadable file is left exactly as it was
    app._devices = dict(DEV_B)
    app._save_devices()
    assert registry.read_text() == "{truncated"
    with pytest.raises(HTTPException) as exc:
        app._require_writable_registry()
    assert exc.value.status_code == 503


def test_corrupt_file_and_corrupt_bak_is_read_only(registry):
    registry.write_text("{")
    _bak(registry).write_text("{")
    app._load_devices()
    assert app._devices == {}
    assert app._registry_error
