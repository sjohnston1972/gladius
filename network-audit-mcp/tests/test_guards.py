"""Unit tests for network-audit-mcp pure guards (no network/devices)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import guards  # noqa: E402


# ---------------------------------------------------------------------------
# run_show_command read-only guard (#34)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "show running-config",
    "show version",
    "sh run",            # IOS abbreviation
    "sho ver",           # IOS abbreviation
    "sh ip int brief",
    "ping 10.0.0.1",
    "traceroute 8.8.8.8",
    "dir flash:",
    "more flash:config.txt",
    "  show clock  ",     # leading/trailing whitespace
    "show run | include hostname",
    "sh run | i ssh",
    "show log | begin Oct",
    "show ip route | section ospf",
])
def test_allowed_show_commands(command):
    ok, _ = guards.is_allowed_show_command(command)
    assert ok, f"{command!r} should be allowed"


@pytest.mark.parametrize("command", [
    "configure terminal",
    "conf t",
    "write memory",
    "copy running-config startup-config",
    "erase startup-config",
    "clear counters",
    "format flash:",
    "boot system flash:image.bin",
    "request platform software",
    "reload",
    "no shutdown",
    "delete flash:foo",
    # output modifiers that write to device storage
    "show run | redirect flash:out.txt",
    "show run | red flash:out.txt",
    "show run | append flash:out.txt",
    "show run | tee flash:out.txt",
    "show run | include x | tee flash:out.txt",
    "",
    "   ",
])
def test_blocked_show_commands(command):
    ok, _ = guards.is_allowed_show_command(command)
    assert not ok, f"{command!r} should be blocked"


@pytest.mark.parametrize("command", [
    "show version\nconfigure terminal",   # smuggled second line
    "show version\r\nwrite memory",
    "show ver\rreload",
])
def test_multiline_rejected(command):
    ok, reason = guards.is_allowed_show_command(command)
    assert not ok
    assert "single line" in reason.lower() or "CR/LF" in reason


# ---------------------------------------------------------------------------
# Approval token (#33 / #34)
# ---------------------------------------------------------------------------

SECRET = "top-secret-shared-key"
NOW = 1_000_000


def test_valid_token_round_trip():
    cmds = ["interface Gi0/1", "shutdown"]
    exp = NOW + 300
    token = guards.mint_approval_token(cmds, "10.0.0.1", exp, SECRET)
    ok, reason = guards.verify_approval_token(token, cmds, "10.0.0.1", SECRET, now=NOW)
    assert ok, reason


def test_expired_token_rejected():
    cmds = ["interface Gi0/1"]
    token = guards.mint_approval_token(cmds, "10.0.0.1", NOW - 1, SECRET)
    ok, reason = guards.verify_approval_token(token, cmds, "10.0.0.1", SECRET, now=NOW)
    assert not ok and "expired" in reason


def test_wrong_host_rejected():
    cmds = ["interface Gi0/1"]
    exp = NOW + 300
    token = guards.mint_approval_token(cmds, "10.0.0.1", exp, SECRET)
    ok, _ = guards.verify_approval_token(token, cmds, "10.0.0.2", SECRET, now=NOW)
    assert not ok


def test_different_commands_rejected():
    exp = NOW + 300
    token = guards.mint_approval_token(["shutdown"], "10.0.0.1", exp, SECRET)
    ok, _ = guards.verify_approval_token(token, ["no shutdown"], "10.0.0.1", SECRET, now=NOW)
    assert not ok


def test_whitespace_insensitive_commands():
    exp = NOW + 300
    token = guards.mint_approval_token(["  shutdown  "], "10.0.0.1", exp, SECRET)
    ok, _ = guards.verify_approval_token(token, ["shutdown"], "10.0.0.1", SECRET, now=NOW)
    assert ok


def test_tampered_signature_rejected():
    exp = NOW + 300
    token = guards.mint_approval_token(["shutdown"], "10.0.0.1", exp, SECRET)
    bad = token[:-1] + ("0" if token[-1] != "0" else "1")
    ok, _ = guards.verify_approval_token(bad, ["shutdown"], "10.0.0.1", SECRET, now=NOW)
    assert not ok


def test_malformed_and_missing_secret():
    ok, reason = guards.verify_approval_token("", ["x"], "h", SECRET, now=NOW)
    assert not ok and "malformed" in reason
    ok, reason = guards.verify_approval_token("abc.def", ["x"], "h", SECRET, now=NOW)
    assert not ok
    ok, reason = guards.verify_approval_token("123.def", ["x"], "h", "", now=NOW)
    assert not ok and "secret" in reason


# ---------------------------------------------------------------------------
# Credential redaction (#97)
# ---------------------------------------------------------------------------

def test_redact_credentials():
    assert guards.redact_credentials("copy ftp://bob:secret@10.0.0.9/img.bin flash:") == \
        "copy ftp://***@10.0.0.9/img.bin flash:"
    assert guards.redact_credentials("scp://user@host/path") == "scp://***@host/path"
    assert guards.redact_credentials("tftp://10.0.0.9/img.bin") == "tftp://10.0.0.9/img.bin"
    assert guards.redact_credentials("") == ""


# ---------------------------------------------------------------------------
# nmap custom-args allow-list (#98)
# ---------------------------------------------------------------------------

def test_filter_nmap_args_allows_tuning():
    assert guards.filter_nmap_args(["-sS", "-T4", "--open"]) == ["-sS", "-T4", "--open"]
    assert guards.filter_nmap_args(["-p", "22,80,443"]) == ["-p", "22,80,443"]
    assert guards.filter_nmap_args(["--top-ports", "100"]) == ["--top-ports", "100"]


def test_filter_nmap_args_drops_dangerous():
    assert guards.filter_nmap_args(["-oN", "/tmp/out.txt"]) == []
    assert guards.filter_nmap_args(["--script", "http-shellshock"]) == []
    assert guards.filter_nmap_args(["--datadir", "/evil"]) == []
    assert guards.filter_nmap_args(["-iL", "/etc/passwd"]) == []
    assert guards.filter_nmap_args(["--resume", "/tmp/x"]) == []
    # value flag with a non-port value is dropped
    assert guards.filter_nmap_args(["-p", "/etc/passwd"]) == []
    # mixed: keep the safe, drop the rest
    assert guards.filter_nmap_args(["-sV", "-oX", "x.xml", "-T5"]) == ["-sV", "-T5"]
