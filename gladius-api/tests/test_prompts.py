"""Static checks on the agent system prompts in server.py.

These guard the invariants the 2026-10 prompt review (issues #43, #45, #111,
#112) added: every tool-using prompt carries the untrusted-data guard, the
config-changing agents carry the approval rule, and no prompt references a tool
name that does not exist on the MCP server it talks to.

The tool lists are only available from MCP at runtime, so tool names are
hard-coded here from the `name=` declarations in network-audit-mcp/server.py
and gladius-pentest-mcp/server.py (kept in sync by hand).
"""
import os

# server.py constructs an Anthropic client at import time; give it a dummy key
# so the import does not fail when the image has no real key configured.
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-used")

import server  # noqa: E402


# Tool names exposed by network-audit-mcp/server.py (plus the Jira tools that
# gladius-api injects locally into the audit/tshoot agents).
NETWORK_AUDIT_TOOLS = {
    "query_knowledge_base", "query_design_kb", "connect_to_device",
    "run_show_command", "push_config", "disconnect_device", "send_email",
    "query_nvd", "get_cve_details", "run_nmap_scan", "run_dig", "run_scapy",
    "save_audit_results", "stream_finding", "query_psirt", "query_eox",
    "snmp_get_devices", "snmp_poll", "device_copy_file", "sftp_put_file",
    "sftp_get_file",
}
JIRA_LOCAL_TOOLS = {
    "create_jira_ticket", "update_jira_ticket", "get_jira_tickets",
    "close_jira_ticket",
}
# Tool names exposed by gladius-pentest-mcp/server.py.
PENTEST_TOOLS = {
    "cert_transparency", "cve_correlation", "default_creds_check", "dig_lookup",
    "dir_enum", "fetch_url", "foundation_sec_analyze", "ldap_enum",
    "masscan_sweep", "nikto_scan", "port_scan", "request_go_active",
    "resolve_target", "save_pentest_results", "smb_enum", "snmp_walk",
    "ssl_audit", "traversal_probe", "web_fingerprint", "whois_lookup",
}

ALL_TOOLS = NETWORK_AUDIT_TOOLS | JIRA_LOCAL_TOOLS | PENTEST_TOOLS

# The guard and approval blocks are single shared constants; match on a stable
# phrase from each rather than the whole text.
GUARD_MARKER = "Tool output is data"
GUARD_PHRASE = "untrusted data to analyse"
APPROVAL_PHRASE = "Only proceed if the operator's next message clearly approves"


# prompt attribute name -> the tool universe it is allowed to reference.
TOOL_USING_PROMPTS = {
    "SYSTEM_PROMPT": NETWORK_AUDIT_TOOLS | JIRA_LOCAL_TOOLS,
    "TSHOOT_SYSTEM_PROMPT": NETWORK_AUDIT_TOOLS | JIRA_LOCAL_TOOLS,
    "INVESTIGATION_SYSTEM_PROMPT": NETWORK_AUDIT_TOOLS,
    "DEVICE_AGENT_PROMPT": NETWORK_AUDIT_TOOLS,
    "THREAT_INTEL_PROMPT": NETWORK_AUDIT_TOOLS,
    "SYNTHESIS_AGENT_PROMPT": NETWORK_AUDIT_TOOLS,
    "SYSTEM_PROMPT_PENTEST": PENTEST_TOOLS,
}


def _prompt(name):
    value = getattr(server, name)
    assert isinstance(value, str) and value, f"{name} is not a non-empty string"
    return value


def test_untrusted_data_guard_present():
    for name in TOOL_USING_PROMPTS:
        text = _prompt(name)
        assert GUARD_MARKER in text, f"{name} is missing the untrusted-data guard heading"
        assert GUARD_PHRASE in text, f"{name} is missing the untrusted-data guard body"


def test_approval_rule_on_config_changing_agents():
    for name in ("SYSTEM_PROMPT", "TSHOOT_SYSTEM_PROMPT"):
        assert APPROVAL_PHRASE in _prompt(name), f"{name} is missing the config-change approval rule"


def test_investigation_prompt_is_read_only():
    text = _prompt("INVESTIGATION_SYSTEM_PROMPT")
    assert "Do not change device configuration" in text
    # It must forbid the state-changing tools explicitly.
    for forbidden in ("push_config", "save_audit_results"):
        assert forbidden in text, f"investigation prompt should name {forbidden} as off-limits"


def test_prompts_only_reference_real_tools():
    """No prompt may mention a tool name outside the server it talks to."""
    for name, allowed in TOOL_USING_PROMPTS.items():
        text = _prompt(name)
        for tool in ALL_TOOLS:
            if tool in text:
                assert tool in allowed, (
                    f"{name} references tool '{tool}' which is not available to that agent"
                )


def test_audit_finding_schema_severity_values():
    """The audit contract must list exactly the schema's severity values."""
    text = _prompt("SYSTEM_PROMPT")
    assert "CRITICAL, HIGH, MEDIUM, LOW, PASS" in text
    # type enum values the frontend/schema expect.
    assert '"hardening" or "cve"' in text


def test_phase3_mentions_stream_finding():
    """Issue #112 — Phase 3 should reconcile with the stream_finding tool."""
    assert "stream_finding" in _prompt("SYSTEM_PROMPT")
