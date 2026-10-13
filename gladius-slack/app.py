import os
import json
import time
import logging
import tempfile
import threading
import httpx
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from collections import defaultdict
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gladius-slack")

GLADIUS_API       = os.getenv("GLADIUS_API_URL", "http://gladius-api:8080")
GLADIUS_API_TOKEN = os.getenv("GLADIUS_API_TOKEN")
BOT_TOKEN         = os.getenv("SLACK_BOT_TOKEN")
APP_TOKEN         = os.getenv("SLACK_APP_TOKEN")

# ── Slack user-ID authorization allowlist ──────────────────────────────────────
SLACK_ALLOWED_USERS = {
    u.strip() for u in os.getenv("SLACK_ALLOWED_USERS", "").split(",") if u.strip()
}
SLACK_ALLOWED_TEAM = os.getenv("SLACK_ALLOWED_TEAM", "").strip()

app = App(token=BOT_TOKEN)


def _is_authorized(body: dict, event: dict) -> bool:
    """Only allow messages from an explicit Slack user/team allowlist read from env."""
    user_id = event.get("user")
    team_id = body.get("team_id") or event.get("team")
    if SLACK_ALLOWED_TEAM and team_id != SLACK_ALLOWED_TEAM:
        return False
    return bool(user_id) and user_id in SLACK_ALLOWED_USERS

# ── Persistent conversation history ───────────────────────────────────────────
MAX_HISTORY   = 60
HISTORY_FILE  = Path(os.getenv("HISTORY_FILE", "/data/history.json"))
# Conversations idle for longer than this are dropped (0 = keep forever).
try:
    HISTORY_TTL_DAYS = int(os.getenv("HISTORY_TTL_DAYS", "30"))
except ValueError:
    HISTORY_TTL_DAYS = 30
# Reserved top-level key holding per-conversation last-activity timestamps.
# It has no "|" so older versions of the loader simply skip it.
HISTORY_META_KEY = "__last_active__"
_history_lock = threading.Lock()

# Slack hard limit for block text fields is 3001 chars; stay comfortably under
SLACK_BLOCK_LIMIT = 2900

# Tool name → emoji mapping for progress updates (network-audit-mcp tool names)
TOOL_EMOJI = {
    "connect_to_device":    "🔌",
    "run_show_command":     "💻",
    "push_config":          "📝",
    "disconnect_device":    "🔌",
    "query_knowledge_base": "📚",
    "query_design_kb":      "📐",
    "query_nvd":            "🛡️",
    "get_cve_details":      "🛡️",
    "query_psirt":          "🛡️",
    "query_eox":            "📆",
    "send_email":           "📧",
    "save_audit_results":   "💾",
    "stream_finding":       "🚩",
    "run_nmap_scan":        "🔍",
    "run_dig":              "🌐",
    "run_scapy":            "📡",
    "snmp_get_devices":     "📊",
    "snmp_poll":            "📊",
    "device_copy_file":     "📁",
    "sftp_put_file":        "📤",
    "sftp_get_file":        "📥",
}

# Minimum seconds between chat_update calls on the progress message; tool
# events arriving faster are coalesced into the next update.
PROGRESS_MIN_INTERVAL = 1.5


# Same persistence pattern as gladius-overseer/app.py (separate containers, so
# each keeps its own copy): atomic replace on save, quarantine instead of
# overwrite on a corrupt file, and idle conversations expire.

def _quarantine_history_file() -> None:
    dest = HISTORY_FILE.with_name(f"{HISTORY_FILE.name}.corrupt-{int(time.time())}")
    try:
        os.replace(HISTORY_FILE, dest)
        log.error("Moved unreadable history file to %s", dest)
    except OSError as e:
        log.error("Could not quarantine unreadable history file %s: %s", HISTORY_FILE, e)


def _expire_history(history: dict, last_active: dict, now: float | None = None) -> int:
    """Drop conversations idle for longer than HISTORY_TTL_DAYS."""
    if HISTORY_TTL_DAYS <= 0:
        return 0
    now = time.time() if now is None else now
    cutoff = now - HISTORY_TTL_DAYS * 86400
    stale = [k for k in list(history) if last_active.get(k, now) < cutoff]
    for k in stale:
        history.pop(k, None)
        last_active.pop(k, None)
    return len(stale)


def _load_history() -> tuple[dict[tuple[str, str], list[dict]], dict]:
    """Load history from disk. Returns (history, last_active). A file that
    can't be parsed is moved aside rather than silently replaced on the next save."""
    history, last_active = defaultdict(list), {}
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not HISTORY_FILE.exists():
        log.info("No history file found — starting fresh at %s", HISTORY_FILE)
        return history, last_active
    try:
        raw = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("top level is not a JSON object")
    except Exception as e:
        log.error("Failed to load history from %s: %s — starting fresh", HISTORY_FILE, e)
        _quarantine_history_file()
        return history, last_active
    meta = raw.get(HISTORY_META_KEY)
    meta = meta if isinstance(meta, dict) else {}
    now = time.time()
    for k, v in raw.items():
        parts = k.split("|", 1)
        if len(parts) != 2 or not isinstance(v, list):
            continue
        key = tuple(parts)
        history[key] = v
        ts = meta.get(k)
        last_active[key] = float(ts) if isinstance(ts, (int, float)) else now
    expired = _expire_history(history, last_active, now)
    log.info("Loaded conversation history: %d thread(s) from %s (%d expired)", len(history), HISTORY_FILE, expired)
    return history, last_active


def _save_history(history: dict) -> None:
    """Persist history atomically: temp file in the same directory, then replace."""
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        serialisable = {f"{k[0]}|{k[1]}": v for k, v in history.items()}
        serialisable[HISTORY_META_KEY] = {
            f"{k[0]}|{k[1]}": _history_last_active.get(k, time.time()) for k in history
        }
        fd, tmp = tempfile.mkstemp(dir=HISTORY_FILE.parent, prefix=f".{HISTORY_FILE.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(serialisable, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, HISTORY_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        log.error("Failed to save history to %s: %s", HISTORY_FILE, e)


# Load persisted history at startup
_history, _history_last_active = _load_history()


def _thread_key(channel: str, event: dict) -> tuple[str, str]:
    # For DMs use a single "dm" bucket per channel.
    # For channel messages always use "main" regardless of thread_ts —
    # threading would otherwise create a fresh empty history per reply thread.
    if event.get("channel_type") == "im":
        return (channel, "dm")
    return (channel, "main")


def _append_history(key: tuple, role: str, content: str) -> None:
    with _history_lock:
        _history[key].append({"role": role, "content": content})
        if len(_history[key]) > MAX_HISTORY:
            _history[key] = _history[key][-MAX_HISTORY:]
        _history_last_active[key] = time.time()
        _expire_history(_history, _history_last_active)
        _save_history(_history)


# Cache bot user ID
_bot_user_id: str | None = None

def get_bot_id(client) -> str:
    global _bot_user_id
    if not _bot_user_id:
        _bot_user_id = client.auth_test()["user_id"]
    return _bot_user_id


def _chunk_text(text: str, limit: int = SLACK_BLOCK_LIMIT) -> list[str]:
    """Split text into Slack-safe chunks, preferring paragraph/line boundaries."""
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    remaining = text

    while len(remaining) > limit:
        split_at = remaining.rfind("\n\n", 0, limit)
        if split_at == -1 or split_at < limit // 2:
            split_at = remaining.rfind("\n", 0, limit)
        if split_at == -1 or split_at < limit // 4:
            split_at = limit
        chunks.append(remaining[:split_at].rstrip())
        remaining = remaining[split_at:].lstrip()

    if remaining:
        chunks.append(remaining)

    return chunks


def _build_progress_text(tool_calls: list[dict]) -> str:
    """Build a compact tool progress string from completed/in-progress tool calls."""
    lines = []
    for tc in tool_calls:
        name   = tc["name"]
        status = tc["status"]  # "running" | "done" | "error"
        emoji  = TOOL_EMOJI.get(name, "🔧")
        detail = tc.get("detail", "")

        if status == "running":
            indicator = "⏳"
        elif status == "done":
            indicator = "✅"
        else:
            indicator = "❌"

        line = f"{indicator} {emoji} `{name}`"
        if detail:
            # Trim detail to avoid blowing the block limit
            detail = detail[:80] + "…" if len(detail) > 80 else detail
            line += f" — {detail}"
        lines.append(line)

    return "\n".join(lines)


def _update_progress(client, channel: str, ts: str, tool_calls: list[dict]) -> None:
    """Update the placeholder message with current tool progress."""
    progress = _build_progress_text(tool_calls)
    text = f"⚙️ On it...\n{progress}"
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text[:SLACK_BLOCK_LIMIT]}}]
    try:
        client.chat_update(channel=channel, ts=ts, text=text[:200], blocks=blocks)
    except Exception as e:
        log.warning("Failed to update progress message: %s", e)


class _ProgressThrottle:
    """Coalesce progress updates to at most one per `min_interval` seconds.
    The latest state is always shown eventually: an update arriving too soon
    is held and sent by a timer. close() cancels anything pending so a late
    update can't overwrite the final reply."""

    def __init__(self, send, min_interval: float = PROGRESS_MIN_INTERVAL, clock=time.monotonic):
        self._send = send
        self._interval = min_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._last_sent: float | None = None
        self._pending: list[dict] | None = None
        self._timer: threading.Timer | None = None
        self._closed = False

    def push(self, tool_calls: list[dict]) -> None:
        snapshot = [dict(tc) for tc in tool_calls]
        with self._lock:
            if self._closed:
                return
            self._pending = snapshot
            if self._timer is not None:
                return
            wait = 0.0 if self._last_sent is None else self._last_sent + self._interval - self._clock()
            if wait <= 0:
                self._flush_locked()
            else:
                self._timer = threading.Timer(wait, self._on_timer)
                self._timer.daemon = True
                self._timer.start()

    def _on_timer(self) -> None:
        with self._lock:
            self._timer = None
            if not self._closed:
                self._flush_locked()

    def _flush_locked(self) -> None:
        if self._pending is None:
            return
        snapshot, self._pending = self._pending, None
        self._last_sent = self._clock()
        self._send(snapshot)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


def format_audit_blocks(audit: dict) -> list:
    """Build detailed Slack Block Kit sections for an audit result."""
    score    = audit.get("score", {})
    findings = audit.get("findings", [])

    severity_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "UNKNOWN")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_parts = [f"{sev}: {severity_counts[sev]}" for sev in order if sev in severity_counts]
    for sev, count in severity_counts.items():
        if sev not in order:
            sev_parts.append(f"{sev}: {count}")

    sev_str = " | ".join(sev_parts) if sev_parts else "None"

    # Score emoji
    overall = score.get("overall", 0)
    if isinstance(overall, (int, float)):
        score_emoji = "🟢" if overall >= 80 else "🟡" if overall >= 60 else "🔴"
    else:
        score_emoji = "⚪"

    blocks: list = [
        {"type": "divider"},
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ Audit: {audit.get('device', 'Unknown')}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Device:*\n`{audit.get('device', '?')}`"},
                {"type": "mrkdwn", "text": f"*IP:*\n`{audit.get('ip', '?')}`"},
                {"type": "mrkdwn", "text": f"*IOS:*\n{audit.get('ios', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Findings:*\n{len(findings)} total"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{score_emoji} *Score — Overall: {overall}/100*\n"
                    f"    NIST: *{score.get('nist', '?')}*  |  CIS: *{score.get('cis', '?')}*\n"
                    f"    {sev_str}"
                ),
            },
        },
    ]

    # Group findings by severity for detailed breakdown
    SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "PASS": "✅", "INFO": "ℹ️"}
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue

        emoji = SEV_EMOJI.get(sev, "⚪")
        lines = [f"*{emoji} {sev} ({len(sev_findings)})*"]

        for f in sev_findings:
            title    = f.get("title", "Untitled")
            category = f.get("category", "")
            impact   = f.get("impact", "")
            fix      = f.get("fix", "")
            commands = f.get("commands", "")
            cve_id   = f.get("cve_id", "")
            ref      = f.get("ref", "")

            line = f"• *{title}*"
            if category:
                line += f"  _{category}_"
            if cve_id:
                line += f"  `{cve_id}`"
            lines.append(line)

            if impact:
                lines.append(f"    Impact: {impact[:150]}{'…' if len(impact) > 150 else ''}")
            if fix:
                lines.append(f"    Fix: {fix[:150]}{'…' if len(fix) > 150 else ''}")
            if commands:
                cmds = commands if len(commands) <= 100 else commands[:100] + "…"
                lines.append(f"    `{cmds}`")
            if ref:
                lines.append(f"    <{ref}|Reference>")

        # Slack block text limit is ~3000 chars; split if needed
        text = "\n".join(lines)
        for chunk in _chunk_text(text, SLACK_BLOCK_LIMIT):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": chunk},
            })

    # LOW + PASS summary (don't list individually)
    low_count  = severity_counts.get("LOW", 0)
    pass_count = severity_counts.get("PASS", 0)
    info_count = severity_counts.get("INFO", 0)
    summary_parts = []
    if pass_count:
        summary_parts.append(f"✅ {pass_count} passed")
    if low_count:
        summary_parts.append(f"🔵 {low_count} low")
    if info_count:
        summary_parts.append(f"ℹ️ {info_count} info")
    if summary_parts:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": " | ".join(summary_parts)}],
        })

    blocks.append({"type": "divider"})
    return blocks


def call_gladius_streaming(
    history: list[dict],
    client,
    channel: str,
    ts: str,
) -> tuple[str, dict | None]:
    """
    Stream /api/chat SSE. Updates the Slack placeholder in real-time as tools run.
    Returns (final_text, audit_or_None).
    """
    payload     = {"messages": history, "source": "slack"}
    text_parts: list[str]  = []
    audit: dict | None     = None
    tool_calls: list[dict] = []   # tracks active/completed tool calls for progress display

    headers = {"Authorization": f"Bearer {GLADIUS_API_TOKEN}"} if GLADIUS_API_TOKEN else {}
    progress = _ProgressThrottle(lambda calls: _update_progress(client, channel, ts, calls))

    try:
        with httpx.Client(timeout=300) as http:
            with http.stream("POST", f"{GLADIUS_API}/api/chat", json=payload, headers=headers) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    try:
                        event = json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue

                    etype = event.get("type")

                    if etype == "text":
                        text_parts.append(event.get("content", ""))

                    elif etype == "tool_start":
                        name   = event.get("tool", "unknown")
                        inp    = event.get("input", {})
                        # Build a short detail string from the most useful input fields
                        detail = _summarise_tool_input(name, inp)
                        tool_calls.append({"name": name, "status": "running", "detail": detail})
                        progress.push(tool_calls)

                    elif etype == "tool_done":
                        name = event.get("tool", "unknown")
                        # Mark the most recent matching running call as done
                        for tc in reversed(tool_calls):
                            if tc["name"] == name and tc["status"] == "running":
                                tc["status"] = "done"
                                break
                        progress.push(tool_calls)

                    elif etype == "audit_saved":
                        audit = event.get("audit")

                    elif etype == "error":
                        log.error("Gladius error: %s", event.get("content"))
                        # Mark last running tool as errored
                        for tc in reversed(tool_calls):
                            if tc["status"] == "running":
                                tc["status"] = "error"
                                break
                        progress.push(tool_calls)
                        break

                    elif etype == "done":
                        break

    except httpx.RequestError as e:
        log.error("Failed to reach Gladius API: %s", e)
        return f"_Could not reach Gladius API: {e}_", None
    finally:
        progress.close()

    return "".join(text_parts), audit


# Input fields never shown in progress lines.
_SENSITIVE_INPUT_KEYS = {"password", "username", "community", "attachment_html", "body"}


def _clip(text, n: int = 60) -> str:
    text = str(text or "")
    return text[:n] + ("…" if len(text) > n else "")


def _summarise_tool_input(tool_name: str, inp: dict) -> str:
    """Return a short human-readable summary of a tool's input for the progress display."""
    if not isinstance(inp, dict):
        return ""
    if tool_name in ("connect_to_device", "disconnect_device", "snmp_poll"):
        return inp.get("host", "")
    if tool_name == "run_show_command":
        host = inp.get("host")
        return _clip(inp.get("command", "")) + (f" @ {host}" if host else "")
    if tool_name == "push_config":
        cmds = inp.get("commands", [])
        if isinstance(cmds, list):
            return _clip(", ".join(str(c) for c in cmds[:2]) + ("…" if len(cmds) > 2 else ""))
        return _clip(cmds)
    if tool_name == "run_nmap_scan":
        return f"{inp.get('target', '')} {inp.get('profile', '')}".strip()
    if tool_name == "run_dig":
        return f"{inp.get('target', '')} {inp.get('record_type', 'A')}".strip()
    if tool_name == "run_scapy":
        return f"{inp.get('mode', '')} → {inp.get('target', '')}".strip()
    if tool_name in ("query_nvd", "query_psirt"):
        return _clip(inp.get("search_term") or inp.get("advisory_id") or inp.get("severity") or "")
    if tool_name == "get_cve_details":
        return inp.get("cve_id", "")
    if tool_name == "query_eox":
        pids = inp.get("pids", "")
        return _clip(", ".join(str(p) for p in pids) if isinstance(pids, list) else pids)
    if tool_name in ("query_knowledge_base", "query_design_kb"):
        return _clip(inp.get("query", ""))
    if tool_name == "save_audit_results":
        return inp.get("device", "")
    if tool_name == "stream_finding":
        return _clip(f"{inp.get('severity', '')} {inp.get('title', '')}".strip())
    if tool_name == "send_email":
        return _clip(inp.get("recipient") or inp.get("subject") or "")
    if tool_name == "device_copy_file":
        return _clip(f"{inp.get('protocol', '')} {inp.get('direction', 'to_device')} {inp.get('remote_file', '')}".strip())
    if tool_name in ("sftp_put_file", "sftp_get_file"):
        return _clip(f"{inp.get('host', '')}:{inp.get('remote_path', '')}")
    # Generic fallback — first non-sensitive string value found
    for k, v in inp.items():
        if isinstance(v, str) and k not in _SENSITIVE_INPUT_KEYS:
            return v[:60]
    return ""


def handle_message(body: dict, client) -> None:
    event   = body.get("event", {})
    text    = event.get("text", "")
    channel = event.get("channel")

    if not _is_authorized(body, event):
        log.warning("Unauthorized message from user %s (team %s) — ignoring",
                    event.get("user"), body.get("team_id") or event.get("team"))
        return

    bot_id = get_bot_id(client)
    text   = text.replace(f"<@{bot_id}>", "").strip()

    if not text:
        return

    log.info("Received message in %s: %.80s", channel, text)

    thread_key = _thread_key(channel, event)
    _append_history(thread_key, "user", text)

    with _history_lock:
        current_history = list(_history[thread_key])

    log.info("Sending %d message(s) of history for key %s", len(current_history), thread_key)

    # Post placeholder — will be updated live as tools run
    try:
        placeholder = client.chat_postMessage(channel=channel, text="⚙️ On it...")
        ts = placeholder["ts"]
    except Exception as e:
        log.error("Failed to post placeholder: %s", e)
        return

    # Stream from Gladius — updates placeholder with tool progress in real-time
    final_text, audit = call_gladius_streaming(current_history, client, channel, ts)

    if not final_text:
        final_text = "_No response from Gladius._"

    _append_history(thread_key, "assistant", final_text)

    # Split into Slack-safe chunks
    chunks      = _chunk_text(final_text)
    total_chunks = len(chunks)
    log.info("Response is %d chars → %d chunk(s)", len(final_text), total_chunks)

    # Replace the progress placeholder with the first response chunk
    first_chunk = chunks[0]
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": first_chunk}}]
    if total_chunks == 1 and audit:
        blocks += format_audit_blocks(audit)

    try:
        client.chat_update(channel=channel, ts=ts, text=first_chunk, blocks=blocks)
    except Exception as e:
        log.error("Failed to update placeholder with response: %s", e)
        return

    # Post remaining chunks as follow-up messages
    for i, chunk in enumerate(chunks[1:], start=2):
        is_last    = (i == total_chunks)
        chunk_blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": chunk}}]
        if is_last and audit:
            chunk_blocks += format_audit_blocks(audit)
        try:
            client.chat_postMessage(channel=channel, text=chunk, blocks=chunk_blocks)
        except Exception as e:
            log.error("Failed to post chunk %d/%d: %s", i, total_chunks, e)


@app.event("message")
def on_dm(body: dict, client) -> None:
    """Handle direct messages to the bot."""
    event = body.get("event", {})
    if (
        event.get("channel_type") == "im"
        and not event.get("bot_id")
        and not event.get("subtype")
    ):
        handle_message(body, client)


@app.event("app_mention")
def on_mention(body: dict, client) -> None:
    """Handle @mentions in channels."""
    handle_message(body, client)


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"status": "ok", "service": "gladius-slack"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass


if __name__ == "__main__":
    if not BOT_TOKEN:
        raise RuntimeError("SLACK_BOT_TOKEN is not set")
    if not APP_TOKEN:
        raise RuntimeError("SLACK_APP_TOKEN is not set")
    if not SLACK_ALLOWED_USERS:
        raise RuntimeError("SLACK_ALLOWED_USERS is not set — refusing to start unauthorized")

    threading.Thread(
        target=lambda: HTTPServer(("0.0.0.0", 9090), _HealthHandler).serve_forever(),
        daemon=True
    ).start()
    log.info("Health endpoint listening on :9090")

    log.info("Starting Gladius Slack bot (Socket Mode)...")
    handler = SocketModeHandler(app, APP_TOKEN)
    handler.start()
