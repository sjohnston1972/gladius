"""
alerts.py - Threshold monitoring and Slack/webhook notifications
"""
import os
import queue
import time
import threading
from collections import deque
from storage import log_alert, load_settings

# Cooldown tracker: don't spam alerts. Store last alert time per (device_id, alert_type)
_last_alert: dict[tuple, float] = {}
_alert_lock = threading.Lock()
COOLDOWN_SEC = 300  # default gap between repeat alerts; overridden by the cooldown_sec setting

# Up/down state machine: a device is declared DOWN after N consecutive failed
# probes (down_after_failures setting) and alerts once per transition, with a
# recovery alert when it answers again.
DOWN_AFTER_FAILURES = 3
_fail_start: dict[int, float] = {}   # device_id -> time of first failure in the current streak
_down_alerted: set[int] = set()      # devices whose DOWN alert has fired and not yet recovered
# Anomaly persistence: alert only if k of the last m successful samples are anomalous.
ANOMALY_WINDOW = 5
ANOMALY_MIN = 3
_anomaly_hist: dict[int, deque] = {}
_state_lock = threading.Lock()


def _setting_int(s: dict, key: str, default: int, minimum: int = 0) -> int:
    try:
        value = int(s.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, value)

_recent_alerts: dict[str, list[tuple[float, int, str]]] = {}  # type -> [(time, device_id, name)]
_CORRELATION_WINDOW = 60  # seconds
_CORRELATION_MIN = 2      # minimum devices for a network event
_correlation_lock = threading.Lock()

def _check_correlation(device_id: int, device_name: str, alert_type: str):
    """Track recent alerts; if N devices fire same type within window, log a network event."""
    import storage as st
    now = time.time()
    with _correlation_lock:
        bucket = _recent_alerts.setdefault(alert_type, [])
        bucket.append((now, device_id, device_name))
        bucket[:] = [(t, did, dn) for t, did, dn in bucket if now - t <= _CORRELATION_WINDOW]
        if len(bucket) >= _CORRELATION_MIN:
            ids = [did for _, did, _ in bucket]
            names = [dn for _, _, dn in bucket]
            st.log_network_event(alert_type, ids, names)
            bucket.clear()


def _can_alert(device_id: int, alert_type: str, cooldown: float | None = None) -> bool:
    key = (device_id, alert_type)
    now = time.time()
    if cooldown is None:
        cooldown = COOLDOWN_SEC
    with _alert_lock:
        last = _last_alert.get(key)
        if last is None or now - last >= cooldown:
            _last_alert[key] = now
            return True
    return False


def _send_slack(message: str, s: dict | None = None):
    """Send a message to Slack. Requires SLACK_WEBHOOK_URL env var or settings."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        s = s if s is not None else load_settings()
        webhook_url = s.get("slack_webhook_url", "")
    if not webhook_url:
        print(f"[ALERT] Slack not configured. Message: {message}")
        return
    try:
        import urllib.request
        import json
        payload = json.dumps({"text": message}).encode()
        req = urllib.request.Request(webhook_url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[ALERT] Slack send failed: {e}")


def _send_discord(message: str, s: dict | None = None):
    """Send alert to Discord via incoming webhook."""
    s = s if s is not None else load_settings()
    url = s.get("discord_webhook_url", "").strip()
    if not url:
        return
    try:
        import urllib.request, json
        clean = message.replace(":red_circle:", "🔴").replace(":large_yellow_circle:", "🟡").replace(":chart_with_upwards_trend:", "📈").replace(":arrows_counterclockwise:", "🔄").replace(":large_green_circle:", "🟢")
        payload = json.dumps({"content": clean}).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[ALERT] Discord send failed: {e}")


def _send_teams(message: str, s: dict | None = None):
    """Send alert to Microsoft Teams via incoming webhook."""
    s = s if s is not None else load_settings()
    url = s.get("teams_webhook_url", "").strip()
    if not url:
        return
    try:
        import urllib.request, json
        clean = message.replace(":red_circle:", "🔴").replace(":large_yellow_circle:", "🟡").replace(":chart_with_upwards_trend:", "📈").replace(":arrows_counterclockwise:", "🔄").replace(":large_green_circle:", "🟢")
        payload = json.dumps({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "text": clean
        }).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[ALERT] Teams send failed: {e}")


def _send_email(subject: str, body: str, s: dict | None = None):
    """Send alert email via SMTP."""
    s = s if s is not None else load_settings()
    if not s.get("email_alerts_enabled"):
        return
    host = s.get("smtp_host", "").strip()
    to_addr = s.get("smtp_to", "").strip()
    if not host or not to_addr:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = s.get("smtp_from") or s.get("smtp_user", "pingplotter@localhost")
        msg["To"] = to_addr
        port = int(s.get("smtp_port", 587))
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            if port == 587:
                smtp.starttls()
            user = s.get("smtp_user", "").strip()
            passwd = s.get("smtp_pass", "").strip()
            if user and passwd:
                smtp.login(user, passwd)
            smtp.sendmail(msg["From"], [to_addr], msg.as_string())
    except Exception as e:
        print(f"[ALERT] Email send failed: {e}")


def _send_webhook(device: dict, alert_type: str, value: float, threshold: float,
                  s: dict | None = None):
    """POST JSON to a custom webhook URL from settings, if configured."""
    try:
        s = s if s is not None else load_settings()
        url = s.get("webhook_url", "").strip()
        if not url:
            return
        import json, urllib.request
        payload = json.dumps({
            "device_id":   device["id"],
            "device_name": device["name"],
            "host":        device["host"],
            "alert_type":  alert_type,
            "value":       value,
            "threshold":   threshold,
        }).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[ALERT] Custom webhook send failed: {e}")


def _deliver(device: dict, alert_type: str, slack_msg: str, value: float, threshold: float):
    """Send one alert to every configured channel (runs on the notifier thread)."""
    s = load_settings()   # once per alert, shared by all senders
    _send_slack(slack_msg, s)
    _send_discord(slack_msg, s)
    _send_teams(slack_msg, s)
    import re
    clean = re.sub(r':[a-z_]+:', '', slack_msg).strip()
    _send_email(f"PingPlotter: {alert_type} — {device['name']}", clean, s)
    _send_webhook(device, alert_type, value, threshold, s)


# Notifications go through a queue drained by one worker thread, so a slow or
# unreachable Slack/Discord/Teams/SMTP/webhook target never stalls probing.
_NOTIFY_QUEUE_MAX = 500
_notify_queue: queue.Queue = queue.Queue(maxsize=_NOTIFY_QUEUE_MAX)
_notifier: threading.Thread | None = None
_notifier_lock = threading.Lock()


def _notifier_loop():
    while True:
        item = _notify_queue.get()
        try:
            _deliver(*item)
        except Exception as e:
            print(f"[ALERT] Notification delivery failed: {e!r}")
        finally:
            _notify_queue.task_done()


def _ensure_notifier():
    global _notifier
    with _notifier_lock:
        if _notifier is None or not _notifier.is_alive():
            _notifier = threading.Thread(target=_notifier_loop, daemon=True, name="alert-notifier")
            _notifier.start()


def _fire_alert(device: dict, alert_type: str, slack_msg: str, value: float = 0, threshold: float = 0):
    """Log the alert and queue it for delivery to Slack/Discord/Teams/email/webhook."""
    log_alert(device["id"], device["name"], alert_type, value, threshold)
    _check_correlation(device["id"], device["name"], alert_type)
    _ensure_notifier()
    try:
        _notify_queue.put_nowait((dict(device), alert_type, slack_msg, value, threshold))
    except queue.Full:
        print(f"[ALERT] Notification queue full; dropped {alert_type} for {device['name']}")


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s" if h else f"{m}m {s}s"


def _update_down_state(device: dict, success: bool, failures: int, down_after: int,
                       in_maintenance: bool):
    """Advance the up/down state machine. Returns ("down"|"up", seconds) or None.

    During maintenance nothing fires: a DOWN that is still down when the
    window ends fires then; a recovery inside the window clears silently.
    """
    device_id = device["id"]
    now = time.time()
    with _state_lock:
        if not success:
            _fail_start.setdefault(device_id, now)
            if failures >= down_after and device_id not in _down_alerted and not in_maintenance:
                _down_alerted.add(device_id)
                return "down", now - _fail_start[device_id]
            return None
        started = _fail_start.pop(device_id, None)
        if device_id in _down_alerted:
            _down_alerted.discard(device_id)
            if not in_maintenance:
                return "up", now - (started or now)
        return None


def check_and_alert(
    device: dict,
    latency: float | None,
    success: bool,
    jitter: float | None,
    route_changed: bool = False,
    failures: int | None = None,
):
    """Evaluate thresholds for a device and fire alerts if needed.

    `failures` is the current count of consecutive failed probes; DOWN fires
    once when it reaches the down_after_failures setting, and a recovery alert
    fires on the first success after that.
    """
    from storage import is_in_maintenance
    device_id = device["id"]
    name = device["name"]
    thresholds = device.get("thresholds", {})
    s = load_settings()
    cooldown = _setting_int(s, "cooldown_sec", COOLDOWN_SEC)
    down_after = _setting_int(s, "down_after_failures", DOWN_AFTER_FAILURES, minimum=1)
    if failures is None:
        failures = 0 if success else 1
    in_maintenance = is_in_maintenance(device_id)

    # ── Host down / recovered (state transitions, no repeats) ─────────────────
    transition = _update_down_state(device, success, failures, down_after, in_maintenance)
    if transition and transition[0] == "down":
        _fire_alert(device, "down",
            f":red_circle: *PingPlotter Alert* — `{name}` ({device['host']}) is *DOWN* "
            f"(no response to {failures} consecutive probes)",
            failures, down_after)
    elif transition and transition[0] == "up":
        _fire_alert(device, "up",
            f":large_green_circle: *PingPlotter Recovery* — `{name}` ({device['host']}) is back *UP* "
            f"(down for {_fmt_duration(transition[1])})",
            round(transition[1], 1), 0)

    if in_maintenance:
        return   # silenced during maintenance

    # ── High latency (critical) ────────────────────────────────────────────────
    latency_crit = thresholds.get("latency_ms")
    if latency is not None and latency_crit and latency > latency_crit:
        if _can_alert(device_id, "high_latency", cooldown):
            _fire_alert(device, "high_latency",
                f":red_circle: *PingPlotter CRITICAL* — `{name}` high latency: *{latency:.1f}ms* (critical: {latency_crit}ms)",
                latency, latency_crit)

    # ── High latency (warning) ─────────────────────────────────────────────────
    latency_warn = thresholds.get("latency_ms_warn")
    if latency is not None and latency_warn and latency > latency_warn:
        if latency_crit is None or latency <= latency_crit:
            if _can_alert(device_id, "high_latency_warn", cooldown):
                _fire_alert(device, "high_latency_warn",
                    f":large_yellow_circle: *PingPlotter Warning* — `{name}` elevated latency: *{latency:.1f}ms* (warning: {latency_warn}ms)",
                    latency, latency_warn)

    # ── High jitter (critical) ─────────────────────────────────────────────────
    jitter_crit = thresholds.get("jitter_ms")
    if jitter is not None and jitter_crit and jitter > jitter_crit:
        if _can_alert(device_id, "high_jitter", cooldown):
            _fire_alert(device, "high_jitter",
                f":red_circle: *PingPlotter CRITICAL* — `{name}` high jitter: *{jitter:.1f}ms* (critical: {jitter_crit}ms)",
                jitter, jitter_crit)

    # ── High jitter (warning) ──────────────────────────────────────────────────
    jitter_warn = thresholds.get("jitter_ms_warn")
    if jitter is not None and jitter_warn and jitter > jitter_warn:
        if jitter_crit is None or jitter <= jitter_crit:
            if _can_alert(device_id, "high_jitter_warn", cooldown):
                _fire_alert(device, "high_jitter_warn",
                    f":large_yellow_circle: *PingPlotter Warning* — `{name}` elevated jitter: *{jitter:.1f}ms* (warning: {jitter_warn}ms)",
                    jitter, jitter_warn)

    # ── Route change ───────────────────────────────────────────────────────────
    if route_changed:
        if _can_alert(device_id, "route_changed", cooldown):
            _fire_alert(device, "route_changed",
                f":arrows_counterclockwise: *PingPlotter* — `{name}` ({device['host']}) route has *changed* (new hop IPs detected)")


def check_anomaly(device: dict, latency: float, anomalous: bool, baseline: dict | None):
    """Record one successful sample's anomaly verdict and alert only when the
    anomaly persists: at least anomaly_min_samples of the last
    anomaly_window_samples samples must be anomalous."""
    s = load_settings()
    window = _setting_int(s, "anomaly_window_samples", ANOMALY_WINDOW, minimum=1)
    need = min(window, _setting_int(s, "anomaly_min_samples", ANOMALY_MIN, minimum=1))
    with _state_lock:
        hist = _anomaly_hist.get(device["id"])
        if hist is None or hist.maxlen != window:
            hist = deque(hist or (), maxlen=window)
            _anomaly_hist[device["id"]] = hist
        hist.append(bool(anomalous))
        persistent = sum(hist) >= need
    if anomalous and persistent and baseline is not None:
        fire_anomaly_alert(device, latency, baseline,
                           cooldown=_setting_int(s, "cooldown_sec", COOLDOWN_SEC))


def fire_anomaly_alert(device: dict, latency: float, baseline: dict, cooldown: float | None = None):
    """Fire anomaly alert (statistically unusual latency vs. 7-day baseline)."""
    from storage import is_in_maintenance
    if is_in_maintenance(device["id"]):
        return
    if not _can_alert(device["id"], "anomaly", cooldown):
        return
    mean = baseline["mean"]
    _fire_alert(device, "anomaly",
        f":chart_with_upwards_trend: *PingPlotter Anomaly* — `{device['name']}` latency *{latency:.1f}ms* is anomalous (baseline: {mean:.1f}ms ± {baseline['stddev']:.1f}ms)",
        latency, mean)


