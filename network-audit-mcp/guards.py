#!/usr/bin/env python3
"""Pure, dependency-free guards for network-audit-mcp tools.

Extracted from server.py so they can be unit-tested without importing the full
MCP server, which loads an embedding model and connects to ChromaDB at import
time. Everything here depends only on the standard library.
"""

import hashlib
import hmac
import re
import time

# ---------------------------------------------------------------------------
# run_show_command read-only guard
# ---------------------------------------------------------------------------

# Verbs run_show_command is allowed to execute. The first whitespace-delimited
# token of the command (lower-cased) must be one of these verbs or an
# unambiguous IOS abbreviation of one (e.g. 'sh', 'sho' -> show; 'tr' ->
# traceroute). Everything else — including erase/clear/format/boot/request and
# any config/write verb — is rejected.
READ_ONLY_VERBS = ("show", "ping", "traceroute", "dir", "more")


def is_allowed_show_command(command: str) -> tuple[bool, str]:
    """Return (ok, reason) for a run_show_command request.

    Rejects any command containing a CR or LF (so a single argument cannot
    smuggle extra command lines past the check) and any command whose first
    token is not an allowed read-only verb or a prefix abbreviation of one.
    """
    if command is None:
        return False, "empty command"
    if "\r" in command or "\n" in command:
        return False, "command must be a single line (no CR/LF)"
    stripped = command.strip()
    if not stripped:
        return False, "empty command"
    token = stripped.split()[0].lower()
    # Exact match, or an abbreviation that is a prefix of exactly one verb.
    matches = [v for v in READ_ONLY_VERBS if v == token or v.startswith(token)]
    if token in READ_ONLY_VERBS:
        return True, "ok"
    if len(token) >= 2 and len(matches) == 1:
        return True, "ok"
    return False, f"'{token}' is not an allowed read-only verb"


# ---------------------------------------------------------------------------
# Out-of-band approval tokens for config-changing tools (push_config,
# device_copy_file, sftp_put_file).
#
# When GLADIUS_REQUIRE_APPROVAL_TOKEN is enabled, a config-changing tool
# refuses to run unless it is given an approval_token that verifies as an
# HMAC-SHA256 (keyed with GLADIUS_APPROVAL_SECRET) over the canonical
# representation of host + expiry + the exact operation. gladius-api / the UI
# mint the token when the operator clicks Approve; the model cannot forge it.
# ---------------------------------------------------------------------------


def canonical_approval_payload(operation: list[str], host: str, expiry: int) -> str:
    """Canonical string signed by an approval token.

    `operation` is the exact, ordered list of strings describing the change
    (for push_config: the config command list; for a file transfer: a single
    element fully describing the transfer). Lines are stripped and joined with
    '\\n' so whitespace-only differences do not change the signature.
    """
    host = (host or "").strip()
    lines = "\n".join((s or "").strip() for s in operation)
    return f"{host}\n{int(expiry)}\n{lines}"


def sign_approval(operation: list[str], host: str, expiry: int, secret: str) -> str:
    msg = canonical_approval_payload(operation, host, expiry).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def mint_approval_token(operation: list[str], host: str, expiry: int, secret: str) -> str:
    """Produce an approval token of the form '<expiry>.<hexsig>'.

    Used by gladius-api / the UI; included here so the format has a single
    definition and can be exercised by the unit tests.
    """
    return f"{int(expiry)}.{sign_approval(operation, host, int(expiry), secret)}"


def verify_approval_token(
    token: str,
    operation: list[str],
    host: str,
    secret: str,
    now: float | None = None,
) -> tuple[bool, str]:
    """Return (ok, reason). Verifies signature, expiry and binding to this
    exact host + operation. Constant-time signature comparison."""
    now = time.time() if now is None else now
    if not secret:
        return False, "approval secret not configured"
    if not token or "." not in token:
        return False, "malformed approval token"
    exp_str, sig = token.split(".", 1)
    try:
        expiry = int(exp_str)
    except ValueError:
        return False, "malformed approval token expiry"
    if expiry < now:
        return False, "approval token expired"
    expected = sign_approval(operation, host, expiry, secret)
    if not hmac.compare_digest(expected, sig):
        return False, "approval token does not match this host/command list"
    return True, "ok"


# ---------------------------------------------------------------------------
# Credential redaction for tool output (device_copy_file)
# ---------------------------------------------------------------------------

# Matches 'scheme://user:pass@' or 'scheme://user@' and strips the userinfo.
_CRED_URL_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]+@")


def redact_credentials(text: str) -> str:
    """Replace inline URL credentials (scheme://user:pass@host) with
    scheme://***@host so passwords echoed by the device never reach the model,
    the SSE stream, Slack history or the audit logs."""
    if not text:
        return text
    return _CRED_URL_RE.sub(r"\1***@", text)


# ---------------------------------------------------------------------------
# nmap custom-args allow-list (run_nmap_scan custom profile)
# ---------------------------------------------------------------------------

# Scan-tuning flags only — no output (-o*), scripts (--script*), data dir,
# resume, or input-from-file (-iL) which could write files inside the MCP
# container (which holds device credentials) or load arbitrary NSE scripts.
_NMAP_FLAG_WHITELIST = {"-sS", "-sT", "-sU", "-sV", "-O", "-Pn", "--open", "--reason"}
_NMAP_VALUE_FLAGS = {"-p", "--top-ports"}
_NMAP_T_RE = re.compile(r"^-T[0-5]$")
_NMAP_PORTVAL_RE = re.compile(r"^[0-9,\-]+$")


def filter_nmap_args(tokens: list[str]) -> list[str]:
    """Keep only safe, scan-tuning nmap flags from an already shlex-split list.

    Value-taking flags (-p, --top-ports) keep their following token only when
    it is a plain port/number spec. Anything not explicitly allowed is dropped.
    """
    safe: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t in _NMAP_FLAG_WHITELIST or _NMAP_T_RE.match(t):
            safe.append(t)
            i += 1
            continue
        if t in _NMAP_VALUE_FLAGS:
            if i + 1 < n and _NMAP_PORTVAL_RE.match(tokens[i + 1]):
                safe.extend([t, tokens[i + 1]])
                i += 2
                continue
            # flag without a valid value — drop it
            i += 1
            continue
        # anything else (output, scripts, datadir, resume, -iL, ...) dropped
        i += 1
    return safe
