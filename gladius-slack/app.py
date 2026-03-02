import os
import json
import logging
import threading
import httpx
from pathlib import Path
from collections import defaultdict
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gladius-slack")

GLADIUS_API = os.getenv("GLADIUS_API_URL", "http://gladius-api:8080")
BOT_TOKEN   = os.getenv("SLACK_BOT_TOKEN")
APP_TOKEN   = os.getenv("SLACK_APP_TOKEN")

app = App(token=BOT_TOKEN)

# ── Persistent conversation history ───────────────────────────────────────────
MAX_HISTORY   = 60
HISTORY_FILE  = Path(os.getenv("HISTORY_FILE", "/data/history.json"))
_history_lock = threading.Lock()

# Slack hard limit for block text fields is 3001 chars; stay comfortably under
SLACK_BLOCK_LIMIT = 2900

# Tool name → emoji mapping for progress updates
TOOL_EMOJI = {
    "connect_to_device":    "🔌",
    "run_command":          "💻",
    "push_config":          "📝",
    "run_nmap":             "🔍",
    "run_dig":              "🌐",
    "run_scapy":            "📡",
    "query_knowledge_base": "📚",
    "search_cves":          "🛡️",
    "cve_latest":           "📋",
    "save_audit_results":   "💾",
    "send_email":           "📧",
    "read_file":            "📄",
    "bash":                 "⚡",
}


def _load_history() -> dict[tuple[str, str], list[dict]]:
    """Load history from disk. Returns an empty defaultdict if the file doesn't exist yet."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not HISTORY_FILE.exists():
        log.info("No history file found — starting fresh at %s", HISTORY_FILE)
        return defaultdict(list)
    try:
        raw: dict = json.loads(HISTORY_FILE.read_text())
        loaded = defaultdict(list)
        for k, v in raw.items():
            parts = k.split("|", 1)
            if len(parts) == 2:
                loaded[tuple(parts)] = v
        log.info("Loaded conversation history: %d thread(s) from %s", len(loaded), HISTORY_FILE)
        return loaded
    except Exception as e:
        log.warning("Failed to load history from %s: %s — starting fresh", HISTORY_FILE, e)
        return defaultdict(list)


def _save_history(history: dict) -> None:
    """Persist history to disk."""
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        serialisable = {f"{k[0]}|{k[1]}": v for k, v in history.items()}
        HISTORY_FILE.write_text(json.dumps(serialisable, indent=2))
    except Exception as e:
        log.error("Failed to save history to %s: %s", HISTORY_FILE, e)


# Load persisted history at startup
_history: dict[tuple[str, str], list[dict]] = _load_history()


def _thread_key(channel: str, event: dict) -> tuple[str, str]:
    thread_ts    = event.get("thread_ts")
    channel_type = event.get("channel_type", "")
    if thread_ts:
        return (channel, thread_ts)
    if channel_type == "im":
        return (channel, "dm")
    return (channel, "main")


def _append_history(key: tuple, role: str, content: str) -> None:
    with _history_lock:
        _history[key].append({"role": role, "content": content})
        if len(_history[key]) > MAX_HISTORY:
            _history[key] = _history[key][-MAX_HISTORY:]
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


def format_audit_blocks(audit: dict) -> list:
    """Build a compact Slack Block Kit section for an audit result."""
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

    return [
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Audit: {audit.get('device', 'Unknown')}*  `{audit.get('ip', '')}`\n"
                    f"IOS: {audit.get('ios', 'N/A')}\n"
                    f"Score — Overall: *{score.get('overall', '?')}*  |  "
                    f"NIST: {score.get('nist', '?')}  |  CIS: {score.get('cis', '?')}\n"
                    f"Findings ({len(findings)}): {sev_str}"
                ),
            },
        },
    ]


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
    payload     = {"messages": history}
    text_parts: list[str]  = []
    audit: dict | None     = None
    tool_calls: list[dict] = []   # tracks active/completed tool calls for progress display

    try:
        with httpx.Client(timeout=300) as http:
            with http.stream("POST", f"{GLADIUS_API}/api/chat", json=payload) as resp:
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
                        _update_progress(client, channel, ts, tool_calls)

                    elif etype == "tool_done":
                        name = event.get("tool", "unknown")
                        # Mark the most recent matching running call as done
                        for tc in reversed(tool_calls):
                            if tc["name"] == name and tc["status"] == "running":
                                tc["status"] = "done"
                                break
                        _update_progress(client, channel, ts, tool_calls)

                    elif etype == "audit_saved":
                        audit = event.get("audit")

                    elif etype == "error":
                        log.error("Gladius error: %s", event.get("content"))
                        # Mark last running tool as errored
                        for tc in reversed(tool_calls):
                            if tc["status"] == "running":
                                tc["status"] = "error"
                                break
                        _update_progress(client, channel, ts, tool_calls)
                        break

                    elif etype == "done":
                        break

    except httpx.RequestError as e:
        log.error("Failed to reach Gladius API: %s", e)
        return f"_Could not reach Gladius API: {e}_", None

    return "".join(text_parts), audit


def _summarise_tool_input(tool_name: str, inp: dict) -> str:
    """Return a short human-readable summary of a tool's input for the progress display."""
    if tool_name == "connect_to_device":
        return inp.get("host", "")
    if tool_name == "run_command":
        cmds = inp.get("commands", [])
        if isinstance(cmds, list):
            return ", ".join(cmds[:2]) + ("…" if len(cmds) > 2 else "")
        return str(cmds)[:60]
    if tool_name == "run_nmap":
        return f"{inp.get('target','')} {inp.get('scan_type','')}".strip()
    if tool_name == "run_dig":
        return f"{inp.get('domain','')} {inp.get('record_type','A')}".strip()
    if tool_name == "run_scapy":
        return f"{inp.get('mode','')} → {inp.get('target','')}".strip()
    if tool_name in ("search_cves", "cve_latest"):
        return inp.get("keyword", inp.get("product", ""))
    if tool_name == "query_knowledge_base":
        q = inp.get("query", "")
        return q[:60] + ("…" if len(q) > 60 else "")
    if tool_name == "save_audit_results":
        return inp.get("device_name", "")
    if tool_name == "send_email":
        return inp.get("recipient", "")
    if tool_name == "read_file":
        return inp.get("path", "")
    if tool_name == "bash":
        cmd = inp.get("command", "")
        return cmd[:60] + ("…" if len(cmd) > 60 else "")
    # Generic fallback — first string value found
    for v in inp.values():
        if isinstance(v, str):
            return v[:60]
    return ""


def handle_message(body: dict, client) -> None:
    event   = body.get("event", {})
    text    = event.get("text", "")
    channel = event.get("channel")

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


if __name__ == "__main__":
    if not BOT_TOKEN:
        raise RuntimeError("SLACK_BOT_TOKEN is not set")
    if not APP_TOKEN:
        raise RuntimeError("SLACK_APP_TOKEN is not set")

    log.info("Starting Gladius Slack bot (Socket Mode)...")
    handler = SocketModeHandler(app, APP_TOKEN)
    handler.start()
