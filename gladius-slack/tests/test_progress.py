"""Progress display: real MCP tool names, input summaries and update throttling."""
import time

import pytest

MCP_TOOLS = [
    "connect_to_device", "run_show_command", "push_config", "disconnect_device",
    "query_knowledge_base", "query_design_kb", "query_nvd", "get_cve_details",
    "send_email", "save_audit_results", "run_nmap_scan", "run_dig", "run_scapy",
    "stream_finding", "query_psirt", "query_eox", "snmp_get_devices", "snmp_poll",
    "device_copy_file", "sftp_put_file", "sftp_get_file",
]


def test_every_mcp_tool_has_an_emoji(app):
    assert set(MCP_TOOLS) <= set(app.TOOL_EMOJI)


@pytest.mark.parametrize("tool,inp,expected", [
    ("connect_to_device", {"host": "10.0.0.1"}, "10.0.0.1"),
    ("run_show_command", {"command": "show version"}, "show version"),
    ("run_show_command", {"command": "show ip int br", "host": "R1"}, "show ip int br @ R1"),
    ("push_config", {"commands": ["a", "b", "c"], "confirmed": True}, "a, b…"),
    ("run_nmap_scan", {"target": "10.0.0.0/24", "profile": "quick"}, "10.0.0.0/24 quick"),
    ("query_nvd", {"search_term": "IOS XE 17.6.1"}, "IOS XE 17.6.1"),
    ("get_cve_details", {"cve_id": "CVE-2024-20399"}, "CVE-2024-20399"),
    ("save_audit_results", {"device": "SW-CORE-01", "ip": "10.0.0.1"}, "SW-CORE-01"),
    ("query_eox", {"pids": ["C9300-48P", "ISR4331"]}, "C9300-48P, ISR4331"),
])
def test_summaries_use_real_fields(app, tool, inp, expected):
    assert app._summarise_tool_input(tool, inp) == expected


def test_fallback_never_shows_credentials(app):
    assert app._summarise_tool_input("some_new_tool", {"password": "pw", "username": "u"}) == ""
    assert "pw" not in app._summarise_tool_input("connect_to_device", {"host": "h", "password": "pw"})


class FakeClock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_throttle_coalesces_and_flushes_latest(app):
    sent = []
    clock = FakeClock()
    th = app._ProgressThrottle(sent.append, min_interval=0.2, clock=clock)
    th.push([{"name": "a"}])                       # first update goes out immediately
    th.push([{"name": "a"}, {"name": "b"}])        # too soon — held
    th.push([{"name": "a"}, {"name": "b"}, {"name": "c"}])
    assert len(sent) == 1
    clock.t += 0.2
    time.sleep(0.5)                                 # let the real timer fire
    assert len(sent) == 2 and [c["name"] for c in sent[-1]] == ["a", "b", "c"]
    th.close()


def test_throttle_close_drops_pending(app):
    sent = []
    clock = FakeClock()
    th = app._ProgressThrottle(sent.append, min_interval=0.2, clock=clock)
    th.push([{"name": "a"}])
    th.push([{"name": "b"}])
    th.close()
    time.sleep(0.4)
    th.push([{"name": "c"}])
    assert len(sent) == 1
