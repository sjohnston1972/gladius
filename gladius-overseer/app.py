import os
import json
import shlex
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

# ── Slack user-ID authorization allowlist ──────────────────────────────────────
SLACK_ALLOWED_USERS = {
    u.strip() for u in os.getenv("SLACK_ALLOWED_USERS", "").split(",") if u.strip()
}
SLACK_ALLOWED_TEAM = os.getenv("SLACK_ALLOWED_TEAM", "").strip()

client_ai  = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
slack_web  = SlackWebClient(token=BOT_TOKEN)
app        = App(token=BOT_TOKEN)


def _is_authorized(body: dict, event: dict) -> bool:
    """Only allow messages from an explicit Slack user/team allowlist read from env.
    The overseer runs a Claude agent with a bash tool and file/docker access, so this
    check is the primary gate on who can trigger arbitrary command execution."""
    user_id = event.get("user")
    team_id = body.get("team_id") or event.get("team")
    if SLACK_ALLOWED_TEAM and team_id != SLACK_ALLOWED_TEAM:
        return False
    return bool(user_id) and user_id in SLACK_ALLOWED_USERS


# ── Sandbox: file-access root + command allowlist ──────────────────────────────
# All file reads/writes/listings from LLM-driven tools are confined under this
# root. Anything that resolves (after following symlinks) outside of it is
# rejected, regardless of how it was spelled (absolute path, "..", symlink, etc).
OVERSEER_ROOT = Path(os.getenv("OVERSEER_ROOT", "/projects")).resolve()

# Real container names, taken from each service's docker-compose.yml. This is
# the only set of values docker_restart will accept.
ALLOWED_CONTAINERS = {
    "gladius-api",
    "gladius-overseer",
    "gladius-pentest-mcp",
    "gladius-pyats",
    "gladius-slack",
    "gladius-snmp",
    "network-audit-mcp",
}

BASH_TIMEOUT = 120

# The `bash` tool is intentionally NOT a general command runner: it accepts
# only a fixed set of read-only/inspection binaries, each with its own
# allowlist of flags. `docker` is deliberately absent — restarts go through
# the dedicated `docker_restart` tool below, which validates the container
# name against ALLOWED_CONTAINERS instead of parsing a free-form string.
# Because subprocess is always invoked with an argv list (shell=False),
# shell metacharacters (`;`, `|`, `&`, backticks, `$()`, `>`, newlines, ...)
# are never interpreted — they are inert literal argument text.
BASH_COMMAND_SPECS = {
    "ls":   {"allowed_flags": {"-l", "-a", "-la", "-al", "-h", "-lh", "-alh", "-1", "-R"}, "paths": True},
    "cat":  {"allowed_flags": set(), "paths": True},
    "grep": {"allowed_flags": {"-r", "-n", "-i", "-l", "-c", "-v", "-E", "-w", "-e"}, "paths": True},
    "find": {
        "allowed_flags": {"-name", "-iname", "-type", "-maxdepth", "-mindepth"},
        # Flags that can execute code or mutate the filesystem must never be
        # reachable, no matter how the allowlist above is edited later.
        "denied_flags": {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprintf", "-fprint", "-fprint0"},
        "paths": True,
    },
    "git": {
        # Subcommands only — no "-c" is ever accepted (git -c core.fsmonitor=<cmd>
        # is a known way to get arbitrary command execution from a "read-only"
        # looking git invocation), and "config"/"submodule"/"filter-branch"/
        # "hook"-adjacent subcommands are excluded for the same reason.
        "allowed_subcommands": {
            "status", "log", "diff", "show", "add", "commit", "push", "pull",
            "fetch", "checkout", "branch", "stash", "remote",
        },
        "paths": False,
    },
}


class BashRejected(Exception):
    """Raised when a bash command fails allowlist validation."""


def _resolve_under_root(path_str: str) -> Path:
    """Resolve `path_str` (following symlinks) and ensure it stays under
    OVERSEER_ROOT. Raises ValueError otherwise. Confines both relative and
    absolute paths, and cannot be escaped with "..", a symlink, or by
    pointing at an absolute path outside the root."""
    p = Path(path_str)
    if not p.is_absolute():
        p = OVERSEER_ROOT / p
    resolved = p.resolve()
    if resolved != OVERSEER_ROOT and OVERSEER_ROOT not in resolved.parents:
        raise ValueError(f"Path '{path_str}' resolves outside the allowed root ({OVERSEER_ROOT})")
    return resolved


def _validate_bash_argv(argv: list[str]) -> None:
    """Validate a parsed bash command against BASH_COMMAND_SPECS. Raises
    BashRejected on anything not explicitly allowed."""
    if not argv:
        raise BashRejected("Empty command.")

    binary = argv[0]
    spec = BASH_COMMAND_SPECS.get(binary)
    if spec is None:
        allowed = ", ".join(sorted(BASH_COMMAND_SPECS))
        raise BashRejected(f"Command '{binary}' is not allowlisted. Allowed: {allowed}")

    rest = argv[1:]

    if binary == "git":
        if not rest:
            raise BashRejected("git requires a subcommand.")
        subcmd = rest[0]
        if subcmd == "-c" or subcmd.startswith("-c"):
            raise BashRejected("git -c (config override) is not permitted.")
        if subcmd not in spec["allowed_subcommands"]:
            allowed = ", ".join(sorted(spec["allowed_subcommands"]))
            raise BashRejected(f"git subcommand '{subcmd}' is not allowlisted. Allowed: {allowed}")
        for arg in rest[1:]:
            if arg == "-c" or arg.startswith("-c="):
                raise BashRejected("git -c (config override) is not permitted.")
        return

    denied_flags = spec.get("denied_flags", set())
    allowed_flags = spec["allowed_flags"]
    seen_positional = False
    for arg in rest:
        if arg.startswith("-"):
            if arg in denied_flags:
                raise BashRejected(f"Flag '{arg}' is not permitted for '{binary}'.")
            if arg not in allowed_flags:
                raise BashRejected(f"Flag '{arg}' is not allowlisted for '{binary}'.")
            continue
        if not spec.get("paths"):
            continue
        # For grep, the first positional argument is the search pattern (not
        # a path to open) unless -e was used to supply it as a flag; every
        # positional argument after that is a file path and must be confined.
        if binary == "grep" and not seen_positional:
            seen_positional = True
            continue
        seen_positional = True
        try:
            _resolve_under_root(arg)
        except ValueError as e:
            raise BashRejected(str(e))


# ── Persistent conversation history ───────────────────────────────────────────
MAX_HISTORY  = 60
HISTORY_FILE = Path(os.getenv("HISTORY_FILE", "/data/history.json"))
_history_lock = threading.Lock()

# ── Proactive messaging ────────────────────────────────────────────────────────
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
    """Send a proactive message to Slack. Uses the stored DM channel by default."""
    target = channel or _dm_channel
    if not target:
        log.warning("notify_slack: no channel available yet")
        return False
    try:
        chunks = _chunk_text(message)
        for chunk in chunks:
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
        cut = remaining.rfind("\n\n", 0, limit)
        if cut == -1:
            cut = remaining.rfind("\n", 0, limit)
        if cut == -1:
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

## CRITICAL: Two separate locations — live files vs git repo

The live files (what containers actually run) and the git repository are in DIFFERENT directories.
You have access to both. You must keep them in sync when making or reverting changes.

### Live file paths (inside your container) — what containers actually serve
- /projects/gladius-api/server.py       — running FastAPI backend
- /projects/network-audit-mcp/server.py — running MCP server
- /projects/web-projects/index.html     — file nginx is actively serving
- /projects/gladius-slack/app.py        — running Slack audit bot
- /projects/gladius-overseer/app.py     — this running service

### Git repo paths (inside your container) — tracked by git, used for history/revert
- /projects/repo/                           — git root (README.md, CLAUDE.md, etc.)
- /projects/repo/gladius-api/server.py
- /projects/repo/network-audit-mcp/server.py
- /projects/repo/web-projects/gladius/index.html
- /projects/repo/gladius-slack/app.py
- /projects/repo/gladius-overseer/app.py

## Workflow: making changes

1. Edit the LIVE file (e.g. /projects/gladius-api/server.py) — takes effect immediately
2. Restart the container if it's a Python service
3. Copy the changed live file into the repo so git tracks it
4. Commit and push

## Deployment after editing live files
Use the docker_restart tool (NOT bash) to restart a container — pass the container name:
- After editing gladius-api/server.py:        docker_restart("gladius-api")
- After editing network-audit-mcp/server.py:  docker_restart("network-audit-mcp") then docker_restart("gladius-api")
- After editing index.html:                   no restart needed
- After editing gladius-slack/app.py:         docker_restart("gladius-slack")
- After editing gladius-overseer/app.py:      docker_restart("gladius-overseer")
  IMPORTANT: docker_restart only ever restarts a container — it cannot stop, remove, or run one.
  There is no way to stop/rm/run a container through your tools.

## Guidelines
- Always keep the repo in sync with the live files after any change
- Before making large or risky edits, commit the current state as a checkpoint first
- After editing Python files, always restart the relevant container
- You have FULL persistent conversation history stored on disk.

## SELF-MODIFICATION — CRITICAL
- Do NOT read, write, or modify /projects/gladius-overseer/app.py unless the user's
  message explicitly asks you to change, fix, or update the overseer or yourself.
- A request for "status", "system update", or anything not explicitly about the overseer
  code must NEVER trigger reading or editing your own app.py.
- Only modify yourself when directly instructed. For everything else, leave your own
  files completely alone.

## RESPONSE FORMAT — CRITICAL
- Give a SHORT summary of what was done — 2 to 5 lines maximum
- NEVER list tool calls, file reads, commands run, or intermediate steps
- NEVER say "I read X", "I ran Y", "I checked Z" — just state the outcome
- If you made changes: say what changed and confirm it's live. Nothing more.
- If asked a question: answer it directly. No preamble.
- If a task failed: say what failed and why in one line.
- NO bullet-by-bullet narration of your work process — summary only.
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
            "Run a read-only inspection command and return stdout + stderr. "
            "Only ls, cat, grep, find, and a safe subset of git subcommands are "
            "permitted (no docker — use docker_restart for that). File paths must "
            "be under the project root."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command to execute, e.g. 'git status' or 'cat gladius-api/server.py'"}
            },
            "required": ["command"],
        },
    },
    {
        "name": "docker_restart",
        "description": "Restart one of the Gladius containers by name. This is the only way to restart a container.",
        "input_schema": {
            "type": "object",
            "properties": {
                "container": {
                    "type": "string",
                    "description": f"Container name. One of: {', '.join(sorted(ALLOWED_CONTAINERS))}",
                }
            },
            "required": ["container"],
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


def _run_docker_restart(container: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "restart", container],
        shell=False,
        capture_output=True,
        text=True,
        timeout=BASH_TIMEOUT,
    )


def exec_tool(name: str, inp: dict) -> str:
    try:
        if name == "read_file":
            try:
                path = _resolve_under_root(inp["path"])
            except ValueError as e:
                return f"Error: {e}"
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            if len(content) > 50_000:
                content = content[:50_000] + "\n…(truncated at 50k chars)"
            return content

        elif name == "write_file":
            try:
                path = _resolve_under_root(inp["path"])
            except ValueError as e:
                return f"Error: {e}"
            parent = path.parent
            parent.mkdir(parents=True, exist_ok=True)
            # Re-check after mkdir in case a symlink was introduced by the
            # directory creation itself (defence in depth).
            try:
                _resolve_under_root(str(path))
            except ValueError as e:
                return f"Error: {e}"
            with open(path, "w", encoding="utf-8") as f:
                f.write(inp["content"])
            return f"Written: {path}"

        elif name == "bash":
            cmd = inp["command"]
            try:
                argv = shlex.split(cmd)
                _validate_bash_argv(argv)
            except (BashRejected, ValueError) as e:
                return f"Rejected: {e}"
            result = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=BASH_TIMEOUT,
            )
            out = (result.stdout + result.stderr).strip()
            return out[:8000] if out else "(no output)"

        elif name == "docker_restart":
            container = inp.get("container", "")
            if container not in ALLOWED_CONTAINERS:
                allowed = ", ".join(sorted(ALLOWED_CONTAINERS))
                return f"Rejected: '{container}' is not an allowed container. Allowed: {allowed}"
            if container == "gladius-overseer":
                # Defer so the reply is posted first — otherwise we kill
                # ourselves before responding. Same timeout as the normal
                # (synchronous) path is applied inside the deferred call.
                def _deferred():
                    import time
                    time.sleep(8)
                    try:
                        _run_docker_restart(container)
                    except Exception as e:
                        log.error("Deferred restart of %s failed: %s", container, e)
                threading.Thread(target=_deferred, daemon=True).start()
                return "Restart scheduled — will execute in ~8 seconds after this reply is sent."
            result = _run_docker_restart(container)
            out = (result.stdout + result.stderr).strip()
            return out[:8000] if out else f"Restarted {container}."

        elif name == "list_directory":
            try:
                path = _resolve_under_root(inp["path"])
            except ValueError as e:
                return f"Error: {e}"
            entries = sorted(os.listdir(path))
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
    if name == "docker_restart":
        return f"docker_restart → {inp.get('container', '')}"
    if name == "list_directory":
        return f"ls → {strip(inp.get('path', ''))}"
    if name == "notify_slack":
        return f"notify_slack → {inp.get('message', '')[:60]}"
    return name


def run_agent(history: list[dict]) -> str:
    """
    Run the Claude agentic tool-use loop with full conversation history.
    Returns the final text response. Tool calls are logged only — never shown to user.
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
            log.info("Tool: %s", label)
            result = exec_tool(block.name, block.input)
            log.info("Tool done: %s", label)
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

    if not _is_authorized(body, event):
        log.warning("Unauthorized message from user %s (team %s) — ignoring, no agent run",
                    event.get("user"), body.get("team_id") or event.get("team"))
        return

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

    # Show a minimal "working" indicator — no tool detail, just a spinner
    placeholder_ts = None
    try:
        placeholder = client.chat_postMessage(channel=channel, text="⚙️ On it...")
        placeholder_ts = placeholder["ts"]
    except Exception as e:
        log.error("Failed to post placeholder: %s", e)

    # Run Claude agent — all tool calls happen silently in the background
    final_text = run_agent(current_history)

    # Persist assistant reply
    _append_history(thread_key, "assistant", final_text)

    # Delete the "On it..." placeholder
    if placeholder_ts:
        try:
            client.chat_delete(channel=channel, ts=placeholder_ts)
        except Exception as e:
            log.warning("Could not delete placeholder: %s", e)

    # Post final summary as NEW message(s) — each triggers a real Slack notification
    chunks = _chunk_text(final_text)
    for chunk in chunks:
        try:
            client.chat_postMessage(
                channel=channel,
                text=chunk,
                blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": chunk}}],
            )
        except Exception as e:
            log.error("Failed to post response chunk: %s", e)


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
    if not SLACK_ALLOWED_USERS:
        raise RuntimeError("SLACK_ALLOWED_USERS is not set — refusing to start unauthorized")

    log.info("Starting Gladius Overseer (Socket Mode)...")
    SocketModeHandler(app, APP_TOKEN).start()
