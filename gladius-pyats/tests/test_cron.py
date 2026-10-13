"""Cron parsing, validation and scheduler isolation (#126, #51)."""
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pydantic
import pytest

UTC = timezone.utc


def at(y, mo, d, h=0, mi=0, tz=UTC):
    return datetime(y, mo, d, h, mi, tzinfo=tz)


def test_step_on_day_of_month_counts_from_one(app):
    spec = app._parse_cron("0 0 */10 * *")
    assert spec.days == frozenset({1, 11, 21, 31})
    assert app._cron_matches("0 0 */10 * *", at(2026, 10, 1))
    assert not app._cron_matches("0 0 */10 * *", at(2026, 10, 10))
    assert app._parse_cron("0 0 1 */5 *").months == frozenset({1, 6, 11})


def test_basic_fields(app):
    assert app._cron_matches("*/15 * * * *", at(2026, 10, 13, 9, 45))
    assert not app._cron_matches("*/15 * * * *", at(2026, 10, 13, 9, 46))
    assert app._cron_matches("5-10/5 8-17 * * *", at(2026, 10, 13, 12, 10))
    assert app._cron_matches("30 2,14 * * *", at(2026, 10, 13, 14, 30))
    assert app._parse_cron("10/20 * * * *").minutes == frozenset({10, 30, 50})


def test_day_of_month_or_day_of_week(app):
    # 2026-10-13 is a Tuesday; 2026-10-12 a Monday; 2026-10-01 a Thursday.
    expr = "0 9 1 * 1"          # both restricted → the 1st OR any Monday
    assert app._cron_matches(expr, at(2026, 10, 1, 9))
    assert app._cron_matches(expr, at(2026, 10, 12, 9))
    assert not app._cron_matches(expr, at(2026, 10, 13, 9))
    # one side '*' → only the other side matters
    assert app._cron_matches("0 9 * * 1", at(2026, 10, 12, 9))
    assert not app._cron_matches("0 9 * * 1", at(2026, 10, 13, 9))
    assert not app._cron_matches("0 9 1 * *", at(2026, 10, 12, 9))


def test_sunday_alias_and_names(app):
    sunday = at(2026, 10, 11, 6)
    assert app._cron_matches("0 6 * * 7", sunday)
    assert app._cron_matches("0 6 * * 0", sunday)
    assert app._cron_matches("0 6 * oct sun", sunday)
    assert app._cron_matches("0 6 * * mon-fri", at(2026, 10, 13, 6))
    assert not app._cron_matches("0 6 * * mon-fri", sunday)


@pytest.mark.parametrize("expr", [
    "", "* * * *", "* * * * * *", "61 * * * *", "* 24 * * *", "* * 0 * *",
    "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "1,,2 * * * *",
    "a b c d e", "-1 * * * *", "*/x * * * *", "1-2-3 * * * *",
])
def test_invalid_expressions_raise(app, expr):
    with pytest.raises(ValueError):
        app._parse_cron(expr)


def test_next_run(app):
    assert app._cron_next_run("0 * * * *", at(2026, 10, 13, 9, 15)) == "2026-10-13T10:00:00+00:00"
    assert app._cron_next_run("0 0 29 2 *", at(2026, 10, 13)) == "2028-02-29T00:00:00+00:00"
    assert app._cron_next_run("0 0 31 2 *", at(2026, 10, 13)) is None
    assert app._cron_next_run("bogus", at(2026, 10, 13)) is None
    london = ZoneInfo("Europe/London")
    assert app._cron_next_run("30 8 * * *", at(2026, 10, 13, 9, 0, london)) == "2026-10-14T08:30:00+01:00"


def test_next_run_is_cheap(app):
    start = time.monotonic()
    for _ in range(50):
        app._cron_next_run("0 0 31 2 *", at(2026, 10, 13))   # worst case: never fires
    assert time.monotonic() - start < 2.0


def test_schedule_models_validate_cron(app):
    with pytest.raises(pydantic.ValidationError):
        app.ScheduleCreate(name="x", device_ids=[], features=[], cron_expr="99 * * * *")
    with pytest.raises(pydantic.ValidationError):
        app.ScheduleUpdate(cron_expr="0 0 31 2 *")
    ok = app.ScheduleCreate(name="x", device_ids=[], features=[], cron_expr="  0   3 * * 1 ")
    assert ok.cron_expr == "0 3 * * 1"
    assert app.ScheduleUpdate().cron_expr is None


def test_one_bad_schedule_does_not_block_others(app, monkeypatch):
    started = []
    monkeypatch.setattr(app, "_start_schedule", lambda s: started.append(s["id"]))
    schedules = [
        {"id": "bad", "name": "bad", "cron_expr": "*/x * * * *"},
        {"id": "good", "name": "good", "cron_expr": "* * * * *"},
    ]
    app._dispatch_due_schedules(schedules, at(2026, 10, 13, 9, 0))
    assert started == ["good"]


def test_health_does_not_probe_ollama(app, monkeypatch):
    import asyncio

    async def must_not_probe():
        raise AssertionError("/health must not probe Ollama inline")

    monkeypatch.setattr(app, "_probe_ollama", must_not_probe)
    result = asyncio.run(app.health())
    assert result["ollama"] is False and result["status"] == "degraded"
