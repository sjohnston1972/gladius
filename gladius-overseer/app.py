import os
import json
import subprocess
import logging
import threading
import anthropic
from pathlib import Path
from collections import defaultdict
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient as SlackWebClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gladius-overseer")

BOT_TOKEN         = os.getenv("SLACK_BOT_TOKEN")
APP_TOKEN         = os.getenv("SLACK_APP_TOKEN")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

client_ai  = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
slack_web  = SlackWebClient(token=BOT_TOKEN)   # standalone web client for proactive msgs
app        = App(token=BOT_TOKEN)

# ── Persistent conversation history ───────────────────────────────────────────
MAX_HISTORY  = 60
HISTORY_FILE = Path(os.getenv("HISTORY_FILE", "/data/history.json"))
_history_lock = threading.Lock()

# ── Proactive messaging ────────────────────────────────────────────────────────
# We store the DM channel ID of the first user to contact us so we can reach
# them without needing channels:read scope.
_dm_channel: str | None = None
DM_CHANNEL_FILE = Path("/data/dm_channel.txt")

def _load_dm_channel() -> str | None:
    if DM_CHANNEL_FILE.exists():
        ch = DM_CHANNEL_FILE.read_text().strip()
        if ch:
            log.info("Loaded DM channel: %s", ch)
            return ch
    return None

def _save_dm_channel(channel: str) -> None:
    DM_CHANNEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    DM_CHANNEL_FILE.write_text(channel)
    log.info("Saved DM channel: %s", channel)

_dm_channel = _load_dm_channel()


def notify_slack(message: str, channel: str | None = None) -> bool:
    """
    Send a proactive message to Slack. Uses the stored DM channel by default.
    Returns True on success, False on failure.
    Can be called from anywhere in the overseer — used for self-initiated alerts.
    """
    target = channel or _dm_channel
    if not target:
        log.warning("notify_slack: no channel available yet — user hasn't DM'd me")
        return False
    try:
        chunks = _chunk_text(message)
        for i, chunk in enumerate(chunks):
            slack_web.chat_postMessage(
                channel=target,
                text=chunk,
                blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": chunk}}],
            )
        log.info("notify_slack: sent %d chunk(s) to %s", len(chunks), target)
        return True
    except Exception as e:
        log.error("notify_slack failed: %s", e)
        return False


# ── History helpers ────────────────────────────────────────────────────────────

def _load_history() -> dict:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not HISTORY_FILE.exists():
        log.info("No history file — starting fresh at %s", HISTORY_FILE)
        return defaultdict(list)
    try:
        raw = json.loads(HISTORY_FILE.read_text())
        loaded = defaultdict(list)
        for k, v in raw.items():
            parts = k.split("|", 1)
            if len(parts) == 2:
                loaded[tuple(parts)] = v
        log.info("Loaded %d conversation(s) from %s", len(loaded), HISTORY_FILE)
        return loaded
    except Exception as e:
        log.warning("Failed to load history: %s — starting fresh", e)
        return defaultdict(list)


def _save_history(history: dict) -> None:
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        serialisable = {f"{k[0]}|{k[1]}": v for k, v in history.items()}
        HISTORY_FILE.write_text(json.dumps(serialisable, indent=2))
    except Exception as e:
        log.error("Failed to save history: %s", e)


_history: dict = _load_history()


def _thread_key(channel: str, event: dict) -> tuple:
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


# ── Slack message chunking ─────────────────────────────────────────────────────
SLACK_BLOCK_LIMIT = 2900

def _chunk_text(text: str, limit: int = SLACK_BLOCK_LIMIT) -> list[str]:
    """Split text into Slack-safe chunks, preferring paragraph then line breaks."""
    if len(text) <= limit:
        return [text]
    chunks = []
    remaining = text
    while len(remaining) > limit:
        # Try paragraph break
        cut = remaining.rfind("\n\n", 0, limit)
        if cut == -1:
            # Try line break
            cut = remaining.rfind("\n", 0, limit)
        if cut == -1:
            # Hard cut
            cut = limit
        chunks.append(remaining[:cut].strip())
        remaining = remaining[cut:].strip()
    if remaining:
        chunks.append(remaining)
    log.info("Response is %d chars → %d chunk(s)", len(text), len(chunks))
    return chunks


# ── Bot identity ───────────────────────────────────────────────────────────────

_bot_user_id: str | None = None

def get_bot_id(client) -> str:
    global _bot_user_id
    if not _bot_user_id:
        _bot_user_id = client.auth_test()["user_id"]
    return _bot_user_id


# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are Claude, the AI overseer of the Gladius project — a cyberpunk-themed \
homelab network security audit platform. You have direct access to the project files and \
infrastructure and can make changes as requested.

## Project paths (inside your container)
- /projects/repo/                       — git repository root (README.md, CLAUDE.md, etc.)
- /projects/gladius-api/server.py       — FastAPI backend (Claude agent, SSE, all API endpoints)
- /projects/network-audit-mcp/server.py — MCP server (SSH, ChromaDB, NVD, email, nmap tools)
- /projects/web-projects/index.html     — entire frontend (single file, ~5000 lines, vanilla JS)
- /projects/gladius-slack/app.py        — Slack network audit bot
- /projects/gladius-overseer/app.py     — this service (you)

## Deployment (files are volume-mounted — edits on disk are live immediately)
- After editing gladius-api/server.py:        bash("docker restart gladius-api")
- After editing network-audit-mcp/server.py:  bash("docker restart network-audit-mcp && docker restart gladius-api")
- After editing index.html:                   no restart needed
- After editing gladius-slack/app.py:         bash("docker restart gladius-slack")
- After editing gladius-overseer/app.py:      bash("docker restart gladius-overseer")

## Git workflow
- The git repo root is /projects/repo/
- Stage, commit and push: bash("cd /projects/repo && git add -A && git commit -m '...' && git push")

## Guidelines
- Make changes directly and confidently — no confirmation needed
- After editing Python files, always restart the relevant container
- Summarise what you changed and why in your final response
- Check logs if something seems wrong: bash("docker logs <container_name>")
- Keep responses concise — the user is an engineer, not a beginner
- You have FULL persistent conversation history. Every message you and the user have exchanged
  is stored on disk and provided to you on every turn. Never claim you don't have memory or
  that history doesn't persist — it does. Reference prior conversation confidently and directly.

## Proactive messaging
- You can call notify_slack(message) at any time to send a message to the user unprompted.
- Use this to report errors, completed background tasks, or anything noteworthy.
"""

# ── Tools ──────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "read_file",
        "description": "Read the full contents of a file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the file"}
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write (create or overwrite) a file with the given content.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string", "description": "Absolute path to the file"},
                "content": {"type": "string", "description": "Full file contents to write"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "bash",
        "description": (
            "Run a bash command and return stdout + stderr. "
            "Use for docker, git, grep, ls, cat, find, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"}
            },
            "required": ["command"],
        },
    },
    {
        "name": "list_directory",
        "description": "List the contents of a directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the directory"}
            },
            "required": ["path"],
        },
    },
    {
        "name": "notify_slack",
        "description": (
            "Send a proactive message to the user on Slack without them asking. "
            "Use for alerts, errors, task completions, or anything noteworthy."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to send"},
                "channel": {"type": "string", "description": "Override channel ID (optional — defaults to user's DM)"},
            },
            "required": ["message"],
        },
    },
]


def exec_tool(name: str, inp: dict) -> str:
    try:
        if name == "read_file":
            with open(inp["path"], "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            if len(content) > 50_000:
                content = content[:50_000] + "\n…(truncated at 50k chars)"
            return content

        elif name == "write_file":
            path = inp["path"]
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(inp["content"])
            return f"Written: {path}"

        elif name == "bash":
            result = subprocess.run(
                inp["command"],
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            out = (result.stdout + result.stderr).strip()
            return out[:8000] if out else "(no output)"

        elif name == "list_directory":
            entries = sorted(os.listdir(inp["path"]))
            return "\n".join(entries) if entries else "(empty)"

        elif name == "notify_slack":
            ok = notify_slack(inp["message"], inp.get("channel"))
            return "Message sent." if ok else "Failed — no DM channel stored yet."

        else:
            return f"Unknown tool: {name}"

    except Exception as e:
        return f"Error: {e}"


def tool_label(name: str, inp: dict) -> str:
    strip = lambda p: p.replace("/projects/", "")
    if name == "read_file":
        return f"read_file → {strip(inp.get('path', ''))}"
    if name == "write_file":
        return f"write_file → {strip(inp.get('path', ''))}"
    if name == "bash":
        cmd = inp.get("command", "")
        return f"bash → {cmd[:70]}{'…' if len(cmd) > 70 else ''}"
    if name == "list_directory":
        return f"ls → {strip(inp.get('path', ''))}"
    if name == "notify_slack":
        return f"notify_slack → {inp.get('message', '')[:60]}"
    return name


def run_agent(history: list[dict], update_fn) -> str:
    """
    Run the Claude agentic tool-use loop with full conversation history.
    Returns the final text response.
    """
    messages   = list(history)
    final_text = ""

    while True:
        response = client_ai.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        for block in response.content:
            if hasattr(block, "text"):
                final_text += block.text

        if response.stop_reason != "tool_use":
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            label = tool_label(block.name, block.input)
            update_fn(f"⏳ {label}")
            result = exec_tool(block.name, block.input)
            update_fn(f"✅ {label}")
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result,
            })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    return final_text.strip() or "_No response._"


def handle_message(body: dict, client) -> None:
    global _dm_channel

    event   = body.get("event", {})
    text    = event.get("text", "")
    channel = event.get("channel")

    bot_id = get_bot_id(client)
    text   = text.replace(f"<@{bot_id}>", "").strip()
    if not text:
        return

    # Store DM channel for proactive messaging
    if event.get("channel_type") == "im" and _dm_channel != channel:
        _dm_channel = channel
        _save_dm_channel(channel)
        log.info("Stored DM channel: %s", channel)

    log.info("Overseer received in %s: %.80s", channel, text)

    thread_key = _thread_key(channel, event)
    _append_history(thread_key, "user", text)

    with _history_lock:
        current_history = list(_history[thread_key])

    log.info("Sending %d message(s) of history for key %s", len(current_history), thread_key)

    # Post placeholder immediately
    try:
        placeholder = client.chat_postMessage(channel=channel, text="⚙️ On it...")
        ts = placeholder["ts"]
    except Exception as e:
        log.error("Failed to post placeholder: %s", e)
        return

    action_log: list[str] = []

    def update_slack(label: str) -> None:
        action_log.append(label)

    # Run Claude agent
    final_text = run_agent(current_history, update_slack)

    # Persist assistant reply
    _append_history(thread_key, "assistant", final_text)

    # Build action summary footer
    completed = [l for l in action_log if l.startswith("✅")]
    summary   = "\n".join(f"• {l}" for l in completed)
    full_text = final_text
    if summary:
        full_text += f"\n\n*Actions taken:*\n{summary}"

    # Split into 2900-char chunks and send as multiple section blocks in ONE message.
    # This avoids msg_too_long on chat.update and silent failures from multi-message sends.
    chunks = _chunk_text(full_text)
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": chunk}}
        for chunk in chunks
    ]
    try:
        client.chat_update(
            channel=channel,
            ts=ts,
            text=final_text[:150],   # fallback notification text only
            blocks=blocks,
        )
    except Exception as e:
        log.error("Final Slack update failed: %s", e)


@app.event("message")
def on_dm(body: dict, client) -> None:
    event = body.get("event", {})
    if (
        event.get("channel_type") == "im"
        and not event.get("bot_id")
        and not event.get("subtype")
    ):
        handle_message(body, client)


@app.event("app_mention")
def on_mention(body: dict, client) -> None:
    handle_message(body, client)


if __name__ == "__main__":
    if not BOT_TOKEN:
        raise RuntimeError("SLACK_BOT_TOKEN is not set")
    if not APP_TOKEN:
        raise RuntimeError("SLACK_APP_TOKEN is not set")
    if not ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    log.info("Starting Gladius Overseer (Socket Mode)...")
    SocketModeHandler(app, APP_TOKEN).start()
