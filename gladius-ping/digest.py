"""
digest.py - Generate periodic summary digests and send via email/webhook
"""
import threading
import time
import storage


def build_digest(hours: int = 24) -> dict:
    """Build a digest summary for all devices over the last N hours."""
    devices = storage.load_devices()
    rows = []
    for d in devices:
        summary = storage.load_results_summary(d["id"], hours)
        uptime = storage.load_uptime_stats(d["id"], hours)
        incidents = storage.load_incidents(d["id"], hours)
        rows.append({
            "id": d["id"],
            "name": d["name"],
            "host": d["host"],
            "probe_type": d.get("probe_type", "icmp"),
            "avg_latency": summary.get("avg_latency"),
            "p95": summary.get("p95"),
            "loss_pct": summary.get("loss_pct"),
            "uptime_pct": uptime.get("uptime_pct"),
            "incidents": len(incidents),
        })
    alerts = storage.load_alerts(50)
    return {
        "generated_at": storage.utcnow().isoformat(),
        "period_hours": hours,
        "devices": rows,
        "recent_alerts": alerts[:10],
    }


def format_digest_text(digest: dict) -> str:
    """Format digest as plain text for email."""
    lines = [
        f"PingPlotter Digest — {digest['period_hours']}h summary",
        f"Generated: {digest['generated_at'][:19].replace('T', ' ')} UTC",
        "=" * 60,
    ]
    for d in digest["devices"]:
        uptime = f"{d['uptime_pct']:.1f}%" if d["uptime_pct"] is not None else "—"
        lat = f"{d['avg_latency']:.1f}ms" if d["avg_latency"] else "—"
        p95 = f"{d['p95']:.1f}ms" if d["p95"] else "—"
        loss = f"{d['loss_pct']:.1f}%" if d["loss_pct"] is not None else "—"
        lines.append(f"\n{d['name']} ({d['host']})")
        lines.append(f"  Uptime: {uptime}  Avg: {lat}  P95: {p95}  Loss: {loss}  Incidents: {d['incidents']}")
    if digest["recent_alerts"]:
        lines.append("\n" + "=" * 60)
        lines.append("Recent Alerts:")
        for a in digest["recent_alerts"]:
            lines.append(f"  [{a['timestamp'][:19]}] {a['device_name']} — {a['alert_type']}")
    return "\n".join(lines)


_digest_thread = None
_digest_stop = threading.Event()


_TICK_SEC = 60  # how often the scheduler re-reads digest_interval_hours


def _interval_hours() -> int:
    try:
        return max(0, int(storage.load_settings().get("digest_interval_hours", 0) or 0))
    except (TypeError, ValueError, OSError):
        return 0


def send_digest(interval_hours: int):
    from alerts import _send_email, _send_slack
    digest = build_digest(interval_hours)
    text = format_digest_text(digest)
    subject = f"PingPlotter {interval_hours}h Digest — {storage.utcnow().strftime('%Y-%m-%d')}"
    _send_email(subject, text)
    _send_slack(f"```{text[:2900]}```")  # Slack 3k char limit


def _digest_loop(stop: threading.Event):
    """Send a digest every digest_interval_hours, re-reading the setting each
    tick so changes apply without a restart (0 disables)."""
    from speedtest_runner import is_due
    last_run = None
    while not stop.is_set():
        hours = _interval_hours()
        if is_due(hours * 3600, last_run, time.monotonic()):
            last_run = time.monotonic()
            try:
                send_digest(hours)
            except Exception as e:
                print(f"[Digest] Failed: {e}")
        stop.wait(_TICK_SEC)


def start():
    global _digest_thread, _digest_stop
    _digest_stop = threading.Event()
    _digest_thread = threading.Thread(target=_digest_loop, args=(_digest_stop,), daemon=True, name="digest")
    _digest_thread.start()
