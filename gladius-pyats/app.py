#!/usr/bin/env python3
"""
Gladius Automation Factory
Ollama (qwen2.5-coder:7b) powered pyATS/Genie automation script generator and executor.
"""

import os
import json
import uuid
import sqlite3
import asyncio
import base64
import logging
import subprocess
import tempfile
import sys
import ast
import re
import smtplib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Any, Optional, Union

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
log = logging.getLogger(__name__)

OLLAMA_URL        = os.getenv("OLLAMA_URL",        "http://192.168.1.250:11434")
OLLAMA_MODEL      = os.getenv("OLLAMA_MODEL",      "qwen2.5-coder:7b")
SNMP_URL          = os.getenv("SNMP_URL",          "http://gladius-snmp:8000")
DB_PATH           = os.getenv("DB_PATH",           "/data/scripts.db")
DEV_SWITCH_IP     = os.getenv("DEV_SWITCH_IP",     "192.168.20.22")
DEV_SWITCH_HN     = os.getenv("DEV_SWITCH_HN",     "DEV")
LAB_USERNAME      = os.getenv("LAB_USERNAME",      "")
LAB_PASSWORD      = os.getenv("LAB_PASSWORD",      "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL      = os.getenv("CLAUDE_MODEL",      "claude-sonnet-4-6")

# Jira Cloud integration
GLADIUS_API_URL = os.getenv("GLADIUS_API_URL", "http://gladius-api:8080")

JIRA_URL        = os.getenv("JIRA_URL", "")
JIRA_EMAIL      = os.getenv("JIRA_EMAIL", "")
JIRA_API_TOKEN  = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT    = os.getenv("JIRA_PROJECT", "")
JIRA_ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE", "Task")
JIRA_CONFIGURED = bool(JIRA_URL and JIRA_EMAIL and JIRA_API_TOKEN and JIRA_PROJECT)


# ── Database ──────────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scripts (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                description     TEXT,
                platform        TEXT DEFAULT 'iosxe',
                script          TEXT NOT NULL,
                template_id     TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                last_run_at     TEXT,
                last_run_status TEXT DEFAULT 'NEVER',
                last_run_output TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id            TEXT PRIMARY KEY,
                hostname      TEXT NOT NULL,
                ip            TEXT NOT NULL,
                platform      TEXT DEFAULT 'iosxe',
                username      TEXT,
                password      TEXT,
                is_dev_switch INTEGER DEFAULT 0,
                source        TEXT DEFAULT 'manual'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id          TEXT PRIMARY KEY,
                device_id   TEXT NOT NULL,
                device_name TEXT NOT NULL,
                feature     TEXT NOT NULL,
                data        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                type         TEXT NOT NULL DEFAULT 'learn',
                device_ids   TEXT NOT NULL DEFAULT '[]',
                features     TEXT NOT NULL DEFAULT '[]',
                cron_expr    TEXT NOT NULL DEFAULT '0 * * * *',
                notify_slack TEXT DEFAULT '',
                notify_email TEXT DEFAULT '',
                enabled      INTEGER DEFAULT 1,
                last_run_at  TEXT,
                last_status  TEXT,
                created_at   TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schedule_history (
                id           TEXT PRIMARY KEY,
                schedule_id  TEXT NOT NULL,
                type         TEXT NOT NULL,
                status       TEXT NOT NULL,
                summary      TEXT,
                diff_text    TEXT,
                ran_at       TEXT NOT NULL,
                FOREIGN KEY (schedule_id) REFERENCES schedules(id)
            )
        """)
        # Add analysis column to schedule_history if missing (migration)
        try:
            conn.execute("ALTER TABLE schedule_history ADD COLUMN analysis TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        # Add jira_auto_ticket column if missing (migration)
        try:
            conn.execute("ALTER TABLE schedules ADD COLUMN jira_auto_ticket TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # column already exists
        # Seed default dev switch if no devices exist
        existing = conn.execute("SELECT id FROM devices WHERE ip=?", (DEV_SWITCH_IP,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO devices (id, hostname, ip, platform, is_dev_switch, source) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), DEV_SWITCH_HN, DEV_SWITCH_IP, "iosxe", 1, "default")
            )
    log.info("Database initialised at %s", DB_PATH)


# ── Script Sanitizer ──────────────────────────────────────────────────────────
# Replaces whatever CommonSetup/CommonCleanup the LLM generates with the
# known-correct boilerplate. Only Testcase classes need to be model-generated.

_SETUP_BOILERPLATE = """\
class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev
"""

_CLEANUP_BOILERPLATE = """\
class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for d in testbed.devices.values():
            try: d.disconnect()
            except Exception: pass
"""

def _pyats_passed(output: str) -> bool:
    """Return True only if the pyATS output contains no real failures.
    The summary table always prints 'Number of FAILED/ERRORED/BLOCKED' lines
    even when the count is 0, so we can't just search for the word."""
    for line in output.splitlines():
        # Real failure: 'result of ... is => FAILED/ERRORED/BLOCKED'
        if re.search(r'is =>\s+(FAILED|ERRORED|BLOCKED)', line):
            return False
        # Summary table: 'Number of FAILED   N' where N > 0
        m = re.search(r'Number of (FAILED|ERRORED|BLOCKED)\s+(\d+)', line)
        if m and int(m.group(2)) > 0:
            return False
    return True


def sanitize_script(script: str) -> str:
    """Replace LLM-generated CommonSetup/CommonCleanup with correct boilerplate,
    and fix common hallucinated API patterns."""
    script = re.sub(
        r'class CommonSetup\(aetest\.CommonSetup\):.*?(?=\nclass |\Z)',
        _SETUP_BOILERPLATE + '\n',
        script, flags=re.DOTALL
    )
    script = re.sub(
        r'class CommonCleanup\(aetest\.CommonCleanup\):.*?(?=\nclass |\nif __name__|\Z)',
        _CLEANUP_BOILERPLATE + '\n',
        script, flags=re.DOTALL
    )
    # Fix hallucinated aetest.errlog.* → log.*
    script = re.sub(r'\baetest\.errlog\.(error|warning|info|debug)\b', r'log.\1', script)
    # Ensure 'import json' is present if GLADIUS_DATA is used
    if 'GLADIUS_DATA' in script and 'import json' not in script:
        script = 'import json\n' + script
    return script


# ── Testbed Builder ───────────────────────────────────────────────────────────

def build_testbed_yaml(devices: list) -> str:
    tb = {"devices": {}}
    for d in devices:
        dev_key  = d.get("hostname", d.get("ip"))
        username = d.get("username") or LAB_USERNAME
        password = d.get("password") or LAB_PASSWORD
        platform = d.get("platform", "iosxe")
        ip       = d.get("ip")
        tb["devices"][dev_key] = {
            "os":       platform,
            "platform": platform,
            "type":     "router",
            "connections": {
                "cli": {
                    "protocol": "ssh",
                    "ip":       ip,
                    "port":     22,
                }
            },
            "credentials": {
                "default": {
                    "username": username,
                    "password": password,
                }
            }
        }
    return yaml.dump(tb, default_flow_style=False)


# ── pyATS Template Library ────────────────────────────────────────────────────

TEMPLATES = [
    {
        "id": "interface_health",
        "name": "Interface Health Check",
        "description": "Checks all interfaces for operational status and error counters",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: Interface Health Check — operational status and error counters."""
import json
from pyats import aetest
from genie.testbed import load

ERROR_THRESHOLD = 100


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class InterfaceHealthTest(aetest.Testcase):
    @aetest.test
    def check_interfaces(self, dev):
        try:
            parsed = dev.parse('show interfaces')
        except Exception as e:
            self.failed(f'show interfaces parse failed: {e}')
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Interface Status', 'data': parsed})}")
        down = [i for i, d in parsed.items() if d.get('enabled') is not False and d.get('oper_status', '').lower() not in ('up', 'connected')]
        if down:
            self.failed(f'{len(down)} interface(s) not UP')
        else:
            self.passed(f'{len(parsed)} interfaces checked')

    @aetest.test
    def check_error_counters(self, dev):
        try:
            parsed = dev.parse('show interfaces')
        except Exception as e:
            self.failed(f'show interfaces parse failed: {e}')
        issues = []
        for intf, info in parsed.items():
            c = info.get('counters', {})
            if any((c.get(k, 0) or 0) > ERROR_THRESHOLD for k in ('in_errors', 'out_errors', 'in_crc_errors')):
                issues.append(intf)
        if issues:
            self.failed(f'{len(issues)} interface(s) over error threshold')
        else:
            self.passed(f'All {len(parsed)} interfaces within error threshold')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "bgp_verification",
        "name": "BGP Neighbor Verification",
        "description": "Verifies BGP neighbor adjacency states and prefix exchange",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: BGP Neighbor Verification — adjacency states and prefix counts."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class BgpNeighborTest(aetest.Testcase):
    @aetest.test
    def check_bgp_summary(self, dev):
        try:
            parsed = dev.parse('show bgp all summary')
        except Exception as e:
            self.skipped(f'BGP not configured or parse failed: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'BGP Summary', 'data': parsed})}")
        total = sum(len(afd.get('neighbor', {})) for vd in parsed.get('vrf', {}).values() for afd in vd.get('address_family', {}).values())
        self.passed(f'{total} BGP neighbor(s) found')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "ospf_health",
        "name": "OSPF Neighbor Health",
        "description": "Verifies OSPF neighbor adjacencies are FULL/2WAY",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: OSPF Neighbor Health — adjacency states."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class OspfNeighborTest(aetest.Testcase):
    @aetest.test
    def check_adjacencies(self, dev):
        try:
            parsed = dev.parse('show ip ospf neighbor detail')
        except Exception as e:
            self.skipped(f'OSPF not configured: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'OSPF Neighbors', 'data': parsed})}")
        total = sum(len(id_.get('neighbors', {})) for id_ in parsed.get('interfaces', {}).values())
        self.passed(f'{total} OSPF neighbor(s) found')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "cdp_discovery",
        "name": "CDP/LLDP Neighbor Discovery",
        "description": "Collects and reports all CDP and LLDP neighbors",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: CDP/LLDP Neighbor Discovery — topology mapping."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class CdpDiscoveryTest(aetest.Testcase):
    @aetest.test
    def collect_cdp(self, dev):
        try:
            parsed = dev.parse('show cdp neighbors detail')
        except Exception as e:
            self.skipped(f'CDP unavailable: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'CDP Neighbors', 'data': parsed})}")
        count = len(parsed.get('index', {}))
        self.passed(f'{count} CDP neighbor(s) found')

    @aetest.test
    def collect_lldp(self, dev):
        try:
            parsed = dev.parse('show lldp neighbors detail')
        except Exception as e:
            self.skipped(f'LLDP unavailable: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'LLDP Neighbors', 'data': parsed})}")
        count = sum(len(v) for v in parsed.get('interfaces', {}).values())
        self.passed(f'{count} LLDP neighbor(s) found')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "vlan_audit",
        "name": "VLAN Database Audit",
        "description": "Audits VLAN database and trunk port configuration",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: VLAN Database Audit — VLANs and trunks."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class VlanAuditTest(aetest.Testcase):
    @aetest.test
    def check_vlan_database(self, dev):
        try:
            parsed = dev.parse('show vlan')
        except Exception as e:
            self.failed(f'VLAN parse failed: {e}')
        print(f"GLADIUS_DATA:{json.dumps({'label': 'VLAN Database', 'data': parsed})}")
        count = len(parsed.get('vlans', {}))
        self.passed(f'{count} VLAN(s) found')

    @aetest.test
    def check_trunk_ports(self, dev):
        try:
            parsed = dev.parse('show interfaces trunk')
        except Exception as e:
            self.skipped(f'Trunk check skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Trunk Ports', 'data': parsed})}")
        count = len(parsed.get('interface', {}))
        self.passed(f'{count} trunk port(s) found')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "acl_audit",
        "name": "ACL Configuration Audit",
        "description": "Audits ACLs, hit counts, and interface bindings",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: ACL Configuration Audit — lists and hit counts."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class AclAuditTest(aetest.Testcase):
    @aetest.test
    def check_acls(self, dev):
        try:
            parsed = dev.parse('show ip access-lists')
        except Exception as e:
            self.skipped(f'ACL parse failed: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'IP Access Lists', 'data': parsed})}")
        count = len(parsed.get('acls', {}))
        self.passed(f'{count} ACL(s) found')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "routing_table",
        "name": "Routing Table Verification",
        "description": "Checks routing table and route summary",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: Routing Table Verification — routes and summary."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class RoutingTableTest(aetest.Testcase):
    @aetest.test
    def check_route_summary(self, dev):
        try:
            parsed = dev.parse('show ip route summary')
        except Exception as e:
            self.skipped(f'Route summary parse skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Route Summary', 'data': parsed})}")
        self.passed('Route summary collected')

    @aetest.test
    def check_routes(self, dev):
        try:
            parsed = dev.parse('show ip route')
        except Exception as e:
            self.skipped(f'Route table parse skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'IP Route Table', 'data': parsed})}")
        routes = (parsed.get('vrf', {}).get('default', {})
                        .get('address_family', {}).get('ipv4', {})
                        .get('routes', {}))
        self.passed(f'{len(routes)} route(s) in table')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "system_health",
        "name": "System Health Check",
        "description": "Checks CPU utilisation, memory usage, uptime, and platform details",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: System Health Check — CPU, memory, platform, uptime."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class SystemHealthTest(aetest.Testcase):
    @aetest.test
    def check_cpu(self, dev):
        try:
            parsed = dev.parse('show processes cpu')
        except Exception as e:
            self.skipped(f'CPU check skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'CPU Utilisation', 'data': parsed})}")
        u5m = parsed.get('five_min_cpu', 0) or 0
        self.passed(f'CPU 5min average: {u5m}%')

    @aetest.test
    def check_memory(self, dev):
        try:
            parsed = dev.parse('show processes memory')
        except Exception as e:
            self.skipped(f'Memory check skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Memory Utilisation', 'data': parsed})}")
        total = parsed.get('processor_pool', {}).get('total', 0) or 0
        used = parsed.get('processor_pool', {}).get('used', 0) or 0
        pct = (used / total * 100) if total > 0 else 0
        self.passed(f'Memory: {pct:.1f}% used')

    @aetest.test
    def check_version(self, dev):
        try:
            parsed = dev.parse('show version')
        except Exception as e:
            self.skipped(f'Version info skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Device Version', 'data': parsed})}")
        v = parsed.get('version', {})
        self.passed(f"{v.get('hostname', '?')} — {v.get('platform', '?')} — IOS {v.get('version', '?')}")


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "ntp_audit",
        "name": "NTP Synchronisation Audit",
        "description": "Verifies NTP associations, stratum, and clock synchronisation status",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: NTP Synchronisation Audit — peers, stratum, sync state."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class NtpAuditTest(aetest.Testcase):
    @aetest.test
    def check_associations(self, dev):
        try:
            parsed = dev.parse('show ntp associations')
        except Exception as e:
            self.skipped(f'NTP associations check skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'NTP Associations', 'data': parsed})}")
        peers = len(parsed.get('peer', {}))
        self.passed(f'{peers} NTP peer(s) configured')

    @aetest.test
    def check_sync_status(self, dev):
        try:
            parsed = dev.parse('show ntp status')
        except Exception as e:
            self.skipped(f'NTP status check skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'NTP Status', 'data': parsed})}")
        ss = parsed.get('clock_state', {}).get('system_status', {})
        synced = ss.get('clock_state', 'unknown')
        self.passed(f'NTP state: {synced}')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "aaa_audit",
        "name": "AAA/TACACS Configuration Audit",
        "description": "Audits AAA authentication, authorisation, accounting and TACACS/RADIUS config",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: AAA/TACACS Audit — new-model, servers, accounting, fallback."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class AaaAuditTest(aetest.Testcase):
    @aetest.test
    def check_aaa_config(self, dev):
        try:
            run = dev.execute('show running-config')
        except Exception as e:
            self.failed(f'Could not retrieve running config: {e}')
        checks = {
            'aaa_new_model': 'aaa new-model' in run,
            'tacacs_configured': 'tacacs' in run.lower(),
            'aaa_accounting': 'aaa accounting' in run,
            'local_fallback': 'local' in run and 'aaa authentication' in run,
        }
        print(f"GLADIUS_DATA:{json.dumps({'label': 'AAA Configuration Checks', 'data': checks})}")
        failed = [k for k, v in checks.items() if not v]
        if failed:
            self.failed(f'{len(failed)} AAA checks failed: {", ".join(failed)}')
        else:
            self.passed('All AAA checks passed')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "spanning_tree",
        "name": "Spanning Tree Health",
        "description": "Checks STP mode, topology change counts, and root status",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: Spanning Tree Health — topology stability and TCN counts."""
import json
from pyats import aetest
from genie.testbed import load


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class SpanningTreeTest(aetest.Testcase):
    @aetest.test
    def check_stp_summary(self, dev):
        try:
            parsed = dev.parse('show spanning-tree summary')
        except Exception as e:
            self.skipped(f'STP summary skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Spanning Tree Summary', 'data': parsed})}")
        mode = parsed.get('mode', 'unknown')
        vlans = len(parsed.get('vlans', {}))
        self.passed(f'STP mode: {mode}, {vlans} VLAN(s)')

    @aetest.test
    def check_stp_detail(self, dev):
        try:
            parsed = dev.parse('show spanning-tree detail')
        except Exception as e:
            self.skipped(f'STP detail skipped: {e}')
            return
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Spanning Tree Detail', 'data': parsed})}")
        self.passed('STP detail collected')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
    {
        "id": "interface_errors",
        "name": "Interface Error Counter Monitoring",
        "description": "Deep-dives CRC, input/output, discards, and queue drop counters",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: Interface Error Counter Monitoring — CRC, drops, input/output errors."""
import json
from pyats import aetest
from genie.testbed import load

ERROR_THRESHOLD = 10


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev


class InterfaceErrorTest(aetest.Testcase):
    @aetest.test
    def check_error_counters(self, dev):
        try:
            parsed = dev.parse('show interfaces')
        except Exception as e:
            self.failed(f'show interfaces parse failed: {e}')
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Interface Counters', 'data': parsed})}")
        violations = []
        for intf, info in parsed.items():
            c = info.get('counters', {})
            if any((c.get(k, 0) or 0) > ERROR_THRESHOLD for k in ('in_errors', 'out_errors', 'in_crc_errors')):
                violations.append(intf)
        if violations:
            self.failed(f'{len(violations)} interface(s) exceeding error threshold')
        else:
            self.passed(f'All {len(parsed)} interfaces within error threshold')


class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for dev in testbed.devices.values():
            try: dev.disconnect()
            except Exception: pass


if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
'''
    },
]


# ── Pydantic Models ───────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role:    str
    content: str

class ChatRequest(BaseModel):
    messages:       list[ChatMessage]
    script_context: Optional[list[dict]] = []
    model:          Optional[str] = None

class ScriptCreate(BaseModel):
    name:        str
    description: str = ""
    platform:    str = "iosxe"
    script:      str
    template_id: Optional[str] = None

class ScriptUpdate(BaseModel):
    name:        Optional[str] = None
    description: Optional[str] = None
    platform:    Optional[str] = None
    script:      Optional[str] = None

class RunRequest(BaseModel):
    device_id: str
    dry_run:   bool = False

class ValidateRequest(BaseModel):
    script:  Optional[str] = None
    dry_run: bool = True

class DeviceCreate(BaseModel):
    hostname:     str
    ip:           str
    platform:     str  = "iosxe"
    username:     Optional[str]  = None
    password:     Optional[str]  = None
    is_dev_switch: bool = False

class LearnRequest(BaseModel):
    device_ids: list[str]
    features:   list[str]

class DiffRequest(BaseModel):
    snapshot_a: str
    snapshot_b: str

class AnalyzeRequest(BaseModel):
    diff_text:  str
    feature:    str
    device:     str
    device_b:   Optional[str] = None
    before_ts:  Optional[str] = None
    after_ts:   Optional[str] = None
    model:      Optional[str] = None

class ScheduleCreate(BaseModel):
    name:             str
    type:             str = "learn"          # "learn" or "learn_diff"
    device_ids:       list[str]
    features:         list[str]
    cron_expr:        str = "0 * * * *"      # hourly default
    notify_slack:     Optional[str] = ""
    notify_email:     Optional[str] = ""
    jira_auto_ticket: Optional[str] = ""     # "", "all", "medium_plus", "high_only"
    enabled:          bool = True

class ScheduleUpdate(BaseModel):
    name:             Optional[str] = None
    device_ids:       Optional[list[str]] = None
    features:         Optional[list[str]] = None
    cron_expr:        Optional[str] = None
    notify_slack:     Optional[str] = None
    notify_email:     Optional[str] = None
    jira_auto_ticket: Optional[str] = None
    enabled:          Optional[bool] = None


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(title="Gladius Automation Factory")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def startup():
    init_db()
    log.info("Automation Factory started — Ollama: %s  model: %s", OLLAMA_URL, OLLAMA_MODEL)
    log.info("Dev switch: %s (%s)", DEV_SWITCH_HN, DEV_SWITCH_IP)


# ── Running Tasks (register with gladius-api) ─────────────────────────────────

_active_procs: dict[str, asyncio.subprocess.Process] = {}  # task_id → subprocess
_cancelled_tasks: set[str] = set()                          # task_ids that have been killed

async def _register_task(agent: str, description: str) -> str | None:
    """Register a task with gladius-api. Returns task_id or None on failure."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{GLADIUS_API_URL}/api/tasks/register", json={
                "agent": agent, "description": description, "source": "automation",
            })
            if r.status_code == 200:
                return r.json().get("id")
    except Exception as e:
        log.warning("Failed to register task: %s", e)
    return None


async def _complete_task(task_id: str | None):
    """Mark a task as completed in gladius-api."""
    if not task_id:
        return
    _active_procs.pop(task_id, None)
    _cancelled_tasks.discard(task_id)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{GLADIUS_API_URL}/api/tasks/{task_id}/complete")
    except Exception as e:
        log.warning("Failed to complete task %s: %s", task_id, e)


@app.post("/api/tasks/{task_id}/kill")
async def kill_task(task_id: str):
    """Kill a running task by terminating its subprocess."""
    _cancelled_tasks.add(task_id)
    proc = _active_procs.pop(task_id, None)
    if proc and proc.returncode is None:
        try:
            proc.kill()
            log.info("Killed subprocess for task %s (pid=%s)", task_id, proc.pid)
        except Exception as e:
            log.warning("Failed to kill process for task %s: %s", task_id, e)
    await _complete_task(task_id)
    return {"ok": True, "task_id": task_id}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    ollama_ok = False
    try:
        r = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        ollama_ok = r.status_code == 200
    except Exception:
        pass
    with get_db() as conn:
        script_count = conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0]
    return {
        "status":       "ok" if ollama_ok else "degraded",
        "ollama":        ollama_ok,
        "script_count":  script_count,
    }


# ── Ollama Streaming Chat ─────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are the Gladius Automation Factory agent, an expert in both Python and pyATS/Genie for network automation.

You can generate TWO types of scripts:

1. **pyATS scripts** — when the user asks to run checks against live network devices via the Gladius execution engine (testbed, parse, connect/disconnect). These use the pyATS/aetest framework with GLADIUS_DATA output protocol.
2. **Plain Python scripts** — when the user asks for general Python code, standalone tools, data processing, file manipulation, API clients, netmiko/paramiko/nornir/scapy scripts, or anything that does NOT need the pyATS aetest framework.

## How to decide which type
- If the user says "pyATS", "aetest", "Genie parser", "testbed", or asks to run a check that should execute in Gladius → **pyATS script**
- If the user says "Python", "script", "netmiko", "paramiko", "nornir", "scapy", "requests", "write a tool", "automate", or asks for general coding help → **plain Python script**
- If ambiguous, ask yourself: does this need the pyATS aetest framework and a testbed? If not → **plain Python**
- NEVER wrap plain Python code in pyATS CommonSetup/Testcase/CommonCleanup boilerplate — only use that framework when explicitly needed

## Plain Python script rules
- Write clean, production-quality Python with appropriate libraries (netmiko, paramiko, nornir, scapy, requests, httpx, etc.)
- Use markdown code fences with ```python
- Include proper error handling, type hints where helpful, and concise comments
- For network scripts, use well-known libraries — do NOT force pyATS patterns onto non-pyATS requests
- After generating a complete script, output: SAVE_SCRIPT: {"name": "Script Name", "description": "Brief description", "platform": "python"}

## pyATS script requirements (ONLY for pyATS scripts)
- CRITICAL imports — always use exactly these three lines at the top of every script:
    import json
    from pyats import aetest
    from genie.testbed import load
  Never use "import aetest" or "from pyats.topology import load" — both will fail.
  Never use "import logging" or "log.info()" — causes duplicate output with pyATS.
- CRITICAL structure — every script MUST use EXACTLY this boilerplate (do not vary it):

    class CommonSetup(aetest.CommonSetup):
        @aetest.subsection
        def connect(self, testbed):
            self.parent.parameters['dev'] = next(iter(testbed.devices.values()))
            self.parent.parameters['dev'].connect(log_stdout=False)

    class SomeDescriptiveTestcase(aetest.Testcase):
        @aetest.test
        def check_something(self, dev):       # 'dev' is auto-injected from parent parameters
            try:
                parsed = dev.parse('show ...')
            except Exception as e:
                self.failed(f'Parser failed: {e}')
            print(f"GLADIUS_DATA:{json.dumps({'label': 'Descriptive Label', 'data': parsed})}")
            self.passed(f'Summary: collected N items')

    class CommonCleanup(aetest.CommonCleanup):
        @aetest.subsection
        def disconnect(self, testbed):
            for d in testbed.devices.values():
                try: d.disconnect()
                except Exception: pass

  RULES:
  - Always use @aetest.subsection in CommonSetup/CommonCleanup (never @aetest.setup/@aetest.cleanup)
  - Always store device as self.parent.parameters['dev'] in connect — never self.parameters, never self.device
  - Always receive device in test methods as 'dev' parameter — pyATS injects it automatically
  - CommonCleanup always disconnects via testbed.devices.values(), not via the 'dev' parameter

## GLADIUS_DATA output protocol (CRITICAL — every script MUST follow this)
- ALL data output MUST use: print(f"GLADIUS_DATA:{json.dumps({'label': '...', 'data': parsed})}")
- The label should be human-readable (e.g. 'IP Interface Brief', 'BGP Neighbors', 'ARP Table')
- The data MUST be the raw Genie parsed dict — do NOT extract or reformat fields
- NEVER use log.info(), print() without GLADIUS_DATA prefix, or any other output method for data
- self.passed() / self.failed() are for pass/fail summary text ONLY — never put data dicts in them
- Each @aetest.test method should: parse one command → print GLADIUS_DATA → self.passed/failed with summary

## Data gathering rules
- ALWAYS use dev.parse('show ...') for structured data — returns a Genie dict
- NEVER use dev.execute('show ...') for data gathering — raw CLI text cannot be rendered as tables
- The ONLY exception: use dev.execute('show running-config') for text-pattern checks (e.g. AAA audit)
  For text checks, emit results as: print(f"GLADIUS_DATA:{json.dumps({'label': '...', 'data': {'check': bool, 'detail': '...'}})}")
- Handle exceptions: wrap every dev.parse() in try/except, call self.failed(f'Parser failed: {e}')
- End every script with: if __name__ == '__main__': import sys; aetest.main(testbed=load(sys.argv[1]))
- Wrap complete scripts in ```python ... ``` code blocks

## Genie parser reference — key fields per command

### device.parse('show version')
  out['version']['version_short']       # e.g. '17.6'
  out['version']['platform']            # e.g. 'Catalyst L3 Switch'
  out['version']['hostname']
  out['version']['uptime']
  out['version']['os']                  # 'IOS-XE'
  out['version']['image_id']
  out['version']['rom']
  out['version']['curr_config_register']

### device.parse('show interfaces')
  out[intf]['oper_status']              # 'up' | 'down'
  out[intf]['line_protocol']            # 'up' | 'down'
  out[intf]['enabled']                  # bool
  out[intf]['mtu']
  out[intf]['bandwidth']                # kbps
  out[intf]['duplex_mode']              # 'full' | 'half' | 'auto'
  out[intf]['port_speed']               # '1000mb/s' etc
  out[intf]['counters']['in_errors']
  out[intf]['counters']['out_errors']
  out[intf]['counters']['in_crc_errors']
  out[intf]['counters']['rate']['in_rate']   # bps
  out[intf]['counters']['rate']['out_rate']  # bps
  out[intf]['description']              # may be absent

### device.parse('show ip interface brief')
  out['interface'][intf]['ip_address']
  out['interface'][intf]['status']      # 'up' | 'down' | 'administratively down'
  out['interface'][intf]['proto']       # 'up' | 'down'

### device.parse('show ip bgp summary')
  out['instance']['default']['vrf']['default']['neighbor'][peer]['session_state']  # 'Established' etc
  out['instance']['default']['vrf']['default']['neighbor'][peer]['up_down']
  out['instance']['default']['vrf']['default']['neighbor'][peer]['state_pfxrcd']   # prefix count or 'Idle'

### device.parse('show ip ospf neighbor')
  out['interfaces'][intf]['neighbors'][nbr_id]['state']   # 'FULL/DR' etc
  out['interfaces'][intf]['neighbors'][nbr_id]['dead_time']
  out['interfaces'][intf]['neighbors'][nbr_id]['address']

### device.parse('show ip route summary')
  out['vrf']['default']['route_source']['connected']['networks']
  out['vrf']['default']['route_source']['static']['networks']
  out['vrf']['default']['route_source']['ospf']['networks']   # key is process id
  out['vrf']['default']['total_prefixes']

### device.parse('show vlan')
  out['vlans'][vlan_id]['name']
  out['vlans'][vlan_id]['state']        # 'active' | 'suspend'
  out['vlans'][vlan_id]['interfaces']   # list of interface names

### device.parse('show spanning-tree')
  out['rapid_pvst'][vlan_key]['vlans'][vlan_id]['role']      # 'root' | 'designated' etc per vlan
  out['rapid_pvst'][vlan_key]['interfaces'][intf]['status']  # 'forwarding' | 'blocking' etc
  out['rapid_pvst'][vlan_key]['interfaces'][intf]['role']

### device.parse('show cdp neighbors detail')
  out['index'][idx]['device_id']
  out['index'][idx]['entry_addresses']['ip']   # may be a dict of IPs
  out['index'][idx]['platform']
  out['index'][idx]['capabilities']
  out['index'][idx]['local_interface']
  out['index'][idx]['port_id']
  out['index'][idx]['software_version']

### device.parse('show ntp status')
  out['clock_state']['system_status']['associations_address']
  out['clock_state']['system_status']['sync_source']
  out['clock_state']['system_status']['stratum']
  out['clock_state']['system_status']['refid']
  # NTP status: check out['clock_state']['system_status'] exists and stratum < 16

### device.parse('show ntp associations')
  out['peer'][peer_ip]['configured']     # bool
  out['peer'][peer_ip]['reachability']   # octal reach value, 377 = fully reachable
  out['peer'][peer_ip]['local_mode']     # 'client'

### device.parse('show processes cpu sorted')
  out['five_sec_cpu_total']              # % CPU 5 sec
  out['one_min_cpu']                     # % CPU 1 min
  out['five_min_cpu']                    # % CPU 5 min
  out['sort'][pid]['five_sec_cpu']
  out['sort'][pid]['process']            # process name

### device.parse('show processes memory sorted')
  out['processor_pool']['total']
  out['processor_pool']['used']
  out['processor_pool']['free']
  out['sort'][pid]['allocated']
  out['sort'][pid]['process']

### device.parse('show environment all')   # or 'show environment'
  out['switch'][sw]['fan'][slot]['state']         # 'OK'
  out['switch'][sw]['power_supply'][slot]['state']
  out['switch'][sw]['temperature'][sensor]['state']
  out['switch'][sw]['temperature'][sensor]['value']

### device.parse('show running-config')
  out['lines']   # list of raw config lines — use for text-based checks when no structured parser exists

### device.learn('interface')   # full interface feature snapshot
  ops.info[intf]['oper_status']
  ops.info[intf]['enabled']
  ops.info[intf]['counters']['in_errors']
  # Same fields as show interfaces but accessed via learn()

### device.learn('bgp')
  ops.info['instance']['default']['vrf']['default']['neighbor'][peer]['session_state']

### device.learn('ospf')
  ops.info['vrf']['default']['address_family']['ipv4']['instance'][proc]['areas'][area]['interfaces'][intf]['state']

### device.learn('vlan')
  ops.info['vlans'][vlan_id]['state']
  ops.info['vlans'][vlan_id]['interfaces']   # list

## Complete working examples — always follow these patterns exactly

### Example 1: data gathering script (show version + interfaces)
```python
import json
from pyats import aetest
from genie.testbed import load

class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev

class DeviceSnapshot(aetest.Testcase):
    @aetest.test
    def check_version(self, dev):
        try:
            parsed = dev.parse('show version')
        except Exception as e:
            self.failed(f'show version parse failed: {e}')
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Device Version', 'data': parsed})}")
        hostname = parsed.get('version', {}).get('hostname', 'unknown')
        version = parsed.get('version', {}).get('version_short', 'unknown')
        self.passed(f'{hostname} running IOS {version}')

    @aetest.test
    def check_interfaces(self, dev):
        try:
            parsed = dev.parse('show ip interface brief')
        except Exception as e:
            self.failed(f'show ip interface brief parse failed: {e}')
        print(f"GLADIUS_DATA:{json.dumps({'label': 'IP Interface Brief', 'data': parsed})}")
        up = [i for i, d in parsed.get('interface', {}).items() if d.get('status') == 'up']
        self.passed(f'{len(up)} interfaces up')

class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for d in testbed.devices.values():
            try: d.disconnect()
            except Exception: pass

if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
```

### Example 2: validation script with pass/fail logic
```python
import json
from pyats import aetest
from genie.testbed import load

ERROR_THRESHOLD = 100

class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev

class InterfaceErrorCheck(aetest.Testcase):
    @aetest.test
    def check_errors(self, dev):
        try:
            parsed = dev.parse('show interfaces')
        except Exception as e:
            self.failed(f'show interfaces parse failed: {e}')
        print(f"GLADIUS_DATA:{json.dumps({'label': 'Interface Counters', 'data': parsed})}")
        failures = []
        for intf, data in parsed.items():
            c = data.get('counters', {})
            errs = (c.get('in_errors') or 0) + (c.get('out_errors') or 0)
            if errs > ERROR_THRESHOLD:
                failures.append(f'{intf}: {errs} errors')
        if failures:
            self.failed(f'{len(failures)} interfaces over threshold')
        else:
            self.passed(f'All {len(parsed)} interfaces within threshold')

class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for d in testbed.devices.values():
            try: d.disconnect()
            except Exception: pass

if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
```

### Example 3: running-config text check (when no Genie parser exists)
```python
import json
from pyats import aetest
from genie.testbed import load

class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev

class AAACheck(aetest.Testcase):
    @aetest.test
    def check_aaa(self, dev):
        try:
            run = dev.execute('show running-config')
        except Exception as e:
            self.failed(f'Could not retrieve running config: {e}')
        checks = {
            'aaa_new_model': 'aaa new-model' in run,
            'tacacs_configured': 'tacacs' in run.lower(),
            'local_fallback': 'local' in run and 'aaa authentication' in run,
        }
        print(f"GLADIUS_DATA:{json.dumps({'label': 'AAA Configuration Checks', 'data': checks})}")
        failed = [k for k, v in checks.items() if not v]
        if failed:
            self.failed(f'{len(failed)} AAA checks failed: {", ".join(failed)}')
        else:
            self.passed('All AAA checks passed')

class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for d in testbed.devices.values():
            try: d.disconnect()
            except Exception: pass

if __name__ == '__main__':
    import sys
    aetest.main(testbed=load(sys.argv[1]))
```

Every pyATS script you write MUST follow these examples exactly — same imports (json, aetest, load), same CommonSetup, same CommonCleanup, same try/except pattern, same GLADIUS_DATA output.

After generating a complete script, output a save hint on its own line:
SAVE_SCRIPT: {"name": "Script Name", "description": "Brief description", "platform": "iosxe"}

Valid platform values for pyATS scripts: iosxe, ios, nxos, eos
For plain Python scripts use: "platform": "python"

You have access to the existing script repository and can reference or build upon existing scripts when asked.

IMPORTANT: Do not default to pyATS for every request. If the user asks for a Python script, netmiko script, or general coding task, give them clean standalone Python — no aetest, no testbed, no GLADIUS_DATA."""


class ReviewRequest(BaseModel):
    output:  str
    model:   Optional[str] = None
    device:  Optional[str] = None


@app.post("/api/review")
async def review_output(req: ReviewRequest):
    model  = req.model or OLLAMA_MODEL
    device = req.device or "unknown"
    prompt = (
        f"A pyATS health check ran against network device {device}. "
        "Format the results below as a concise markdown table with columns: Test, Result, Details. "
        "Do not wrap in code fences. Keep it brief.\n\n"
        f"{req.output}"
    )

    is_claude = model.startswith("claude-")

    async def generate_ollama():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST", f"{OLLAMA_URL}/api/chat",
                    json={"model": model, "messages": [{"role": "user", "content": prompt}], "stream": True, "options": {"num_ctx": 32768}}
                ) as response:
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk   = json.loads(line)
                            content = chunk.get("message", {}).get("content", "")
                            if content:
                                yield f"data: {json.dumps({'type': 'text', 'content': content})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                                return
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    async def generate_claude():
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                async with client.stream(
                    "POST", "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 16384,
                        "stream": True,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                ) as response:
                    if response.status_code != 200:
                        body = await response.aread()
                        yield f"data: {json.dumps({'type': 'error', 'content': f'Claude API {response.status_code}: {body.decode()}'})}\n\n"
                        return
                    async for line in response.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        payload = line[6:]
                        if payload == "[DONE]":
                            break
                        try:
                            evt = json.loads(payload)
                            if evt.get("type") == "content_block_delta":
                                text = evt.get("delta", {}).get("text", "")
                                if text:
                                    yield f"data: {json.dumps({'type': 'text', 'content': text})}\n\n"
                            elif evt.get("type") == "message_stop":
                                break
                        except json.JSONDecodeError:
                            continue
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return StreamingResponse(
        generate_claude() if is_claude else generate_ollama(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


APITEST_SYSTEM_PROMPT = """You are Gladius API, an API testing and validation agent specialising in REST API endpoint testing, schema validation, and API documentation analysis.

## Behaviour
- Test API endpoints by describing HTTP requests, expected responses, and validation checks
- Use markdown code fences with the language tag (```python, ```bash, ```json, etc.)
- Default to Python (httpx/requests) for test scripts, curl for quick examples
- For each endpoint test, clearly show: method, URL, headers, body, expected status, expected response schema
- Validate response structures against documented schemas when available
- Flag mismatches between documentation and actual API behaviour
- Check for common API issues: missing auth, incorrect content types, missing CORS headers, slow response times
- When testing CRUD operations, test the full lifecycle: create → read → update → delete
- Report results in a structured format: endpoint, method, status, pass/fail, notes
- For network device APIs (RESTCONF, NETCONF, Meraki, DNA Center), use appropriate auth patterns
- If a question is ambiguous, give the most likely interpretation rather than asking for clarification
- Never fabricate API endpoints or response schemas — if unsure, say so"""


CLAUDE_MODELS = ["claude-sonnet-4-6", "claude-haiku-4-5-20251001"]

@app.get("/api/models")
async def list_models():
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            data = r.json()
            names = [m["name"] for m in data.get("models", [])]
    except Exception as e:
        names = [OLLAMA_MODEL]
    # Append Claude models if API key is configured
    if ANTHROPIC_API_KEY:
        names = CLAUDE_MODELS + names
    return {"models": names, "default": OLLAMA_MODEL}


@app.post("/api/chat")
async def chat(req: ChatRequest):
    model = req.model or OLLAMA_MODEL
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    if req.script_context:
        ctx_lines = "\n".join(
            f"- {s['name']}: {s.get('description', '')} (platform: {s.get('platform', 'iosxe')})"
            for s in req.script_context
        )
        messages.append({"role": "user",      "content": f"Existing scripts in repository:\n{ctx_lines}"})
        messages.append({"role": "assistant", "content": "Understood. I have the script repository loaded."})

    for m in req.messages:
        messages.append({"role": m.role, "content": m.content})

    async def generate():
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                async with client.stream(
                    "POST", f"{OLLAMA_URL}/api/chat",
                    json={"model": model, "messages": messages, "stream": True, "options": {"num_ctx": 32768}}
                ) as response:
                    if response.status_code != 200:
                        yield f"data: {json.dumps({'type': 'error', 'content': f'Ollama error {response.status_code}'})}\n\n"
                        return
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk   = json.loads(line)
                            content = chunk.get("message", {}).get("content", "")
                            if content:
                                yield f"data: {json.dumps({'type': 'text', 'content': content})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                                return
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── API Test Agent Chat ───────────────────────────────────────────────────────

class ApitestRequest(BaseModel):
    messages: list[ChatMessage]
    model:    Optional[str] = None

@app.post("/api/coder")
async def apitest_chat(req: ApitestRequest):
    model = req.model or "qwen2.5-coder:14b"
    messages = [{"role": "system", "content": APITEST_SYSTEM_PROMPT}]
    for m in req.messages:
        messages.append({"role": m.role, "content": m.content})

    async def generate():
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                async with client.stream(
                    "POST", f"{OLLAMA_URL}/api/chat",
                    json={"model": model, "messages": messages, "stream": True, "options": {"num_ctx": 32768}}
                ) as response:
                    if response.status_code != 200:
                        yield f"data: {json.dumps({'type': 'error', 'content': f'Ollama error {response.status_code}'})}\n\n"
                        return
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk   = json.loads(line)
                            content = chunk.get("message", {}).get("content", "")
                            if content:
                                yield f"data: {json.dumps({'type': 'text', 'content': content})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                                return
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── ITSM Agent Chat ──────────────────────────────────────────────────────────

ITSM_SYSTEM_PROMPT = f"""You are Gladius ITSM, an IT Service Management agent specialising in incident management, change management, and helpdesk ticket creation for network infrastructure.

## Behaviour
- When given an alert (interface down, BGP peer loss, OSPF adjacency drop, high latency, etc.), draft a structured incident ticket
- Use ITIL-aligned terminology: Incident, Problem, Change Request, Known Error, Service Request
- Always include: Priority (P1-P4), Category, Affected Service, Impact, Urgency, Description, Remediation Steps
- For interface/BGP/OSPF alerts, assess blast radius — what services and users are affected
- Draft tickets in a structured markdown format ready to paste into ServiceNow, Jira Service Management, or similar ITSM tools
- For change requests, include: Justification, Risk Assessment, Rollback Plan, Test Plan, Approvers, Maintenance Window
- For escalations, summarise the timeline, actions taken so far, and business impact
- Generate Root Cause Analysis (RCA) reports with: Timeline, Root Cause, Contributing Factors, Impact Summary, Corrective Actions, Preventive Actions
- When multiple alerts arrive, correlate them — a BGP drop and interface down on the same device is likely one incident, not two
- Suggest appropriate priority levels based on impact and urgency:
  - P1: Complete service outage, revenue impact, >100 users affected
  - P2: Degraded service, redundancy lost, 10-100 users affected
  - P3: Minor issue, workaround available, <10 users affected
  - P4: Cosmetic, informational, no user impact
- Use markdown code fences for ticket templates and structured output
- If a question is ambiguous, give the most likely interpretation rather than asking for clarification
- Never fabricate device names, IPs, or alert data — use what the user provides
- When asked to email a ticket, format it as a clean, professional incident report ready to send
- Default notification recipient: stevie.johnston@gmail.com
- This agent is connected to Jira (project: {JIRA_PROJECT or 'not configured'}). After you draft a ticket, the user can create it directly in Jira with one click.
- Always include a clear "Incident Title:" line that can be used as the Jira issue summary.
- Always include "Priority: P1/P2/P3/P4" explicitly so it can be mapped to Jira priority.
- You have access to live Jira ticket data. When the user asks about open tickets, who's assigned, ticket status, workload, etc., answer using the ticket data provided in your context.
- Format ticket lists as tables when showing multiple tickets.
- If asked about a specific ticket (e.g. GSR-5), provide all available details.

## CRITICAL — Duplicate Ticket Detection (always do this)
Every time you display or discuss tickets, you MUST check for duplicates and output a merge recommendation if found. Follow these rules:

1. Two or more tickets are duplicates when they share the same device name AND were created within 5 minutes of each other.
2. When you find duplicates, you MUST output a section titled "## Merge Recommendation" at the end of your response.
3. In that section: list the duplicate ticket keys, explain they were caused by the same root event (e.g. a device going unreachable triggers IF DOWN + BGP DOWN + OSPF DOWN simultaneously), name the ticket that should be kept as the parent (always pick the EARLIEST created ticket by timestamp — lowest ticket number), and state the others should be closed as duplicates with a link to the parent.
4. Example format:
   ## Merge Recommendation
   Tickets GSR-10, GSR-11, GSR-12 all relate to **device-name** and were created within 1 minute of each other. These are the same incident — the device went unreachable, triggering separate interface, BGP, and OSPF alerts.
   - **Keep as parent:** GSR-10 (earliest created)
   - **Close as duplicate:** GSR-11, GSR-12 — link to GSR-10
5. If no duplicates exist, do NOT output a merge section.

## Closing Tickets
When you recommend closing a ticket (duplicate, resolved, not an issue), include a line in this exact format so the system can auto-close it:
CLOSE_TICKET: GSR-XX | Reason for closing (e.g. "Duplicate of GSR-10", "Resolved — interface recovered")
You can include multiple CLOSE_TICKET lines if recommending closing several tickets."""


class ItsmRequest(BaseModel):
    messages: list[ChatMessage]
    model:    Optional[str] = None

@app.post("/api/itsm")
async def itsm_chat(req: ItsmRequest):
    model = req.model or "qwen2.5:7b"

    # Inject live Jira ticket context if configured
    jira_context = ""
    if JIRA_CONFIGURED:
        try:
            open_issues = await _jira_search(
                f"project = {JIRA_PROJECT} AND status != Done ORDER BY updated DESC", 20
            )
            if open_issues:
                lines = [f"## Current Jira Tickets ({JIRA_PROJECT})"]
                for t in open_issues:
                    created = t.get('created', '')[:19].replace('T', ' ') if t.get('created') else ''
                    labels  = ', '.join(t.get('labels', [])) or 'none'
                    lines.append(
                        f"- **{t['key']}** [{t['status']}] P:{t['priority']} "
                        f"Assignee:{t['assignee']} Created:{created} "
                        f"Labels:{labels} — {t['summary']}"
                    )
                jira_context = "\n".join(lines) + (
                    "\n\nUse this data to answer questions about open tickets, assignees, statuses, and workload."
                    "\nIMPORTANT: Review the ticket list for potential duplicates — tickets for the same device/site "
                    "created within a few minutes of each other are almost certainly caused by the same root incident. "
                    "Flag these and recommend merging them."
                )
        except Exception as e:
            log.warning("Failed to fetch Jira context for ITSM: %s", e)

    system = ITSM_SYSTEM_PROMPT
    if jira_context:
        system += "\n\n" + jira_context

    messages = [{"role": "system", "content": system}]
    for m in req.messages:
        messages.append({"role": m.role, "content": m.content})

    async def generate():
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                async with client.stream(
                    "POST", f"{OLLAMA_URL}/api/chat",
                    json={"model": model, "messages": messages, "stream": True, "options": {"num_ctx": 32768}}
                ) as response:
                    if response.status_code != 200:
                        yield f"data: {json.dumps({'type': 'error', 'content': f'Ollama error {response.status_code}'})}\n\n"
                        return
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk   = json.loads(line)
                            content = chunk.get("message", {}).get("content", "")
                            if content:
                                yield f"data: {json.dumps({'type': 'text', 'content': content})}\n\n"
                            if chunk.get("done"):
                                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                                return
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Jira Query & Ticket API ───────────────────────────────────────────────────

async def _jira_search(jql: str, max_results: int = 50) -> list[dict]:
    """Run a JQL query and return simplified issue list (paginated)."""
    if not JIRA_CONFIGURED:
        return []
    url = f"{JIRA_URL.rstrip('/')}/rest/api/3/search/jql"
    all_raw = []
    page_size = min(max_results, 100)
    next_token = None
    async with httpx.AsyncClient(timeout=30.0) as client:
        while len(all_raw) < max_results:
            params = {
                "jql": jql,
                "maxResults": page_size,
                "fields": "summary,status,priority,assignee,reporter,created,updated,labels,issuetype",
            }
            if next_token:
                params["nextPageToken"] = next_token
            resp = await client.get(url, params=params, headers=_jira_headers())
            if resp.status_code != 200:
                log.error("Jira search failed: %s %s", resp.status_code, resp.text)
                break
            data = resp.json()
            batch = data.get("issues", [])
            all_raw.extend(batch)
            next_token = data.get("nextPageToken")
            if not next_token or len(batch) < page_size:
                break
    issues = []
    for issue in all_raw:
        f = issue["fields"]
        issues.append({
            "key": issue["key"],
            "summary": f.get("summary", ""),
            "status": (f.get("status") or {}).get("name", "Unknown"),
            "priority": (f.get("priority") or {}).get("name", "None"),
            "assignee": (f.get("assignee") or {}).get("displayName", "Unassigned"),
            "reporter": (f.get("reporter") or {}).get("displayName", "Unknown"),
            "type": (f.get("issuetype") or {}).get("name", "Task"),
            "created": f.get("created", ""),
            "updated": f.get("updated", ""),
            "labels": f.get("labels", []),
            "url": f"{JIRA_URL.rstrip('/')}/browse/{issue['key']}",
        })
    return issues


@app.get("/api/jira/issues")
async def jira_issues(status: str = "", assignee: str = "", label: str = "", q: str = ""):
    """Query Jira issues. Params build JQL filters."""
    if not JIRA_CONFIGURED:
        raise HTTPException(503, "Jira not configured")
    clauses = [f"project = {JIRA_PROJECT}"]
    if status:
        clauses.append(f'status = "{status}"')
    if assignee:
        clauses.append(f'assignee = "{assignee}"')
    if label:
        clauses.append(f'labels = "{label}"')
    if q:
        clauses.append(f'text ~ "{q}"')
    jql = " AND ".join(clauses) + " ORDER BY updated DESC"
    issues = await _jira_search(jql)
    return {"issues": issues, "count": len(issues), "jql": jql}


@app.get("/api/jira/open")
async def jira_open_tickets():
    """Return all open (non-Done/Closed) tickets for the project."""
    if not JIRA_CONFIGURED:
        return {"issues": [], "count": 0, "configured": False}
    jql = f'project = {JIRA_PROJECT} AND status = "In Progress" ORDER BY created DESC'
    issues = await _jira_search(jql, max_results=1000)
    return {"issues": issues, "count": len(issues), "configured": True}


@app.get("/api/jira/issue/{issue_key}")
async def jira_issue_detail(issue_key: str):
    """Get full detail for a single Jira issue including description and comments."""
    if not JIRA_CONFIGURED:
        raise HTTPException(503, "Jira not configured")
    url = f"{JIRA_URL.rstrip('/')}/rest/api/3/issue/{issue_key}"
    params = {"fields": "summary,status,priority,assignee,reporter,created,updated,labels,issuetype,description,comment"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, params=params, headers=_jira_headers())
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, f"Jira API error: {resp.text}")
        data = resp.json()
    f = data["fields"]
    # Extract plain text from ADF description
    desc_text = ""
    desc = f.get("description")
    if desc and isinstance(desc, dict):
        for block in desc.get("content", []):
            for item in block.get("content", []):
                if item.get("type") == "text":
                    desc_text += item.get("text", "") + "\n"
    comments = []
    for c in (f.get("comment", {}).get("comments", []))[-10:]:
        body = ""
        if isinstance(c.get("body"), dict):
            for block in c["body"].get("content", []):
                for item in block.get("content", []):
                    if item.get("type") == "text":
                        body += item.get("text", "")
        comments.append({
            "author": (c.get("author") or {}).get("displayName", "Unknown"),
            "created": c.get("created", ""),
            "body": body,
        })
    return {
        "key": data["key"],
        "summary": f.get("summary", ""),
        "status": (f.get("status") or {}).get("name", "Unknown"),
        "priority": (f.get("priority") or {}).get("name", "None"),
        "assignee": (f.get("assignee") or {}).get("displayName", "Unassigned"),
        "reporter": (f.get("reporter") or {}).get("displayName", "Unknown"),
        "type": (f.get("issuetype") or {}).get("name", "Task"),
        "created": f.get("created", ""),
        "updated": f.get("updated", ""),
        "labels": f.get("labels", []),
        "description": desc_text.strip(),
        "comments": comments,
        "url": f"{JIRA_URL.rstrip('/')}/browse/{data['key']}",
    }


class JiraCreateRequest(BaseModel):
    summary:     str
    description: Any   # str (paragraph-per-line) OR ADF doc dict {"type":"doc",...} OR ADF content list
    priority:    str = "P3"
    labels:      list[str] = []
    issue_type:  Optional[str] = None
    project_key: Optional[str] = None


@app.get("/api/jira/status")
async def jira_status():
    return {
        "configured": JIRA_CONFIGURED,
        "project": JIRA_PROJECT if JIRA_CONFIGURED else None,
        "url": JIRA_URL if JIRA_CONFIGURED else None,
    }


@app.post("/api/jira/create")
async def jira_create(req: JiraCreateRequest):
    if not JIRA_CONFIGURED:
        raise HTTPException(503, "Jira not configured — set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT env vars")
    try:
        result = await _create_jira_ticket(
            summary=req.summary,
            description=req.description,
            priority=req.priority,
            labels=req.labels or ["gladius"],
            issue_type=req.issue_type,
            project_key=req.project_key,
        )
        return {"ok": True, **result}
    except Exception as e:
        log.error("Jira ticket creation failed: %s", e)
        raise HTTPException(500, str(e))


@app.post("/api/jira/comment")
async def jira_add_comment(body: dict):
    """Add a comment to an existing Jira issue."""
    if not JIRA_CONFIGURED:
        raise HTTPException(503, "Jira not configured")
    issue_key = body.get("issue_key", "").strip()
    comment   = body.get("comment", "").strip()
    if not issue_key or not comment:
        raise HTTPException(400, "issue_key and comment required")
    url = f"{JIRA_URL.rstrip('/')}/rest/api/3/issue/{issue_key}/comment"
    # Build ADF body for the comment
    adf_body = {
        "body": {
            "version": 1, "type": "doc",
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]}
                        for line in comment.split("\n") if line.strip()]
        }
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=adf_body, headers=_jira_headers())
        if resp.status_code not in (200, 201):
            log.error("Jira comment failed: %s", resp.text)
            raise HTTPException(resp.status_code, f"Jira API error: {resp.text}")
    log.info("Comment added to %s", issue_key)
    return {"ok": True, "issue_key": issue_key}


@app.post("/api/jira/close")
async def jira_close_ticket(body: dict):
    """Transition a Jira issue to Done/Closed status."""
    if not JIRA_CONFIGURED:
        raise HTTPException(503, "Jira not configured")
    issue_key = body.get("issue_key", "").strip()
    comment   = body.get("comment", "").strip()
    if not issue_key:
        raise HTTPException(400, "issue_key required")

    headers = _jira_headers()
    base = JIRA_URL.rstrip('/')

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Get available transitions for this issue
        resp = await client.get(f"{base}/rest/api/3/issue/{issue_key}/transitions", headers=headers)
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, f"Failed to get transitions: {resp.text}")
        transitions = resp.json().get("transitions", [])

        # Find a "Done" or "Closed" or "Resolved" transition
        done_id = None
        for t in transitions:
            name_lower = t["name"].lower()
            if name_lower in ("done", "closed", "resolved", "close", "resolve"):
                done_id = t["id"]
                break
        if not done_id:
            avail = ", ".join(f"{t['name']} (id:{t['id']})" for t in transitions)
            raise HTTPException(400, f"No done/closed transition found. Available: {avail}")

        # Add a closing comment if provided
        if comment:
            adf_body = {
                "body": {
                    "version": 1, "type": "doc",
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]}
                                for line in comment.split("\n") if line.strip()]
                }
            }
            await client.post(f"{base}/rest/api/3/issue/{issue_key}/comment", json=adf_body, headers=headers)

        # Execute the transition
        resp = await client.post(
            f"{base}/rest/api/3/issue/{issue_key}/transitions",
            json={"transition": {"id": done_id}},
            headers=headers,
        )
        if resp.status_code not in (200, 204):
            raise HTTPException(resp.status_code, f"Transition failed: {resp.text}")

    log.info("Ticket %s closed (transition %s)", issue_key, done_id)
    return {"ok": True, "issue_key": issue_key, "status": "Done"}


@app.post("/api/jira/parse-ticket")
async def jira_parse_ticket(body: dict):
    """Extract structured fields from ITSM agent markdown output."""
    text = body.get("text", "")
    summary = ""
    priority = "P3"

    p_match = re.search(r"Priority[:\s]+(P[1-4])", text, re.IGNORECASE)
    if p_match:
        priority = p_match.group(1).upper()

    s_match = re.search(r"(?:Incident Title|Summary|Subject|Ticket Title)[:\s]+(.+)", text, re.IGNORECASE)
    if s_match:
        summary = s_match.group(1).strip().strip("*").strip()
    else:
        h_match = re.search(r"^#+\s+(.+)", text, re.MULTILINE)
        if h_match:
            summary = h_match.group(1).strip()

    return {
        "summary": summary or "Gladius ITSM Ticket",
        "priority": priority,
        "description": text,
    }


# ── Script Repository ─────────────────────────────────────────────────────────

@app.get("/api/scripts")
async def list_scripts():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, description, platform, template_id, "
            "created_at, updated_at, last_run_at, last_run_status "
            "FROM scripts ORDER BY updated_at DESC"
        ).fetchall()
    return {"scripts": [dict(r) for r in rows]}


@app.get("/api/scripts/{script_id}")
async def get_script(script_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scripts WHERE id=?", (script_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Script not found")
    return dict(row)


@app.post("/api/scripts")
async def create_script(body: ScriptCreate):
    now = datetime.now(timezone.utc).isoformat()
    sid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scripts (id, name, description, platform, script, template_id, "
            "created_at, updated_at, last_run_status) VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, body.name, body.description, body.platform, sanitize_script(body.script),
             body.template_id, now, now, "NEVER")
        )
    return {"id": sid, "name": body.name}


@app.put("/api/scripts/{script_id}")
async def update_script(script_id: str, body: ScriptUpdate):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        row = conn.execute("SELECT id FROM scripts WHERE id=?", (script_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Script not found")
        updates = {k: v for k, v in body.dict().items() if v is not None}
        updates["updated_at"] = now
        sets = ", ".join(f"{k}=?" for k in updates)
        conn.execute(f"UPDATE scripts SET {sets} WHERE id=?", list(updates.values()) + [script_id])
    return {"id": script_id, "updated": True}


@app.delete("/api/scripts/{script_id}")
async def delete_script(script_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM scripts WHERE id=?", (script_id,))
    return {"deleted": script_id}


# ── Script Validation ─────────────────────────────────────────────────────────

@app.post("/api/scripts/{script_id}/validate")
async def validate_script(script_id: str, body: ValidateRequest):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scripts WHERE id=?", (script_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Script not found")

    script_content = sanitize_script(body.script if body.script else row["script"])

    # Stage 1: syntax check
    try:
        ast.parse(script_content)
    except SyntaxError as e:
        return {"passed": False, "stage": "syntax", "error": str(e), "output": ""}

    # Stage 2: pyATS structure check
    warnings = []
    for marker in ("from pyats import aetest", "class CommonSetup", "class CommonCleanup",
                   "def connect", "def disconnect"):
        if marker not in script_content:
            warnings.append(f"Missing: {marker}")
    if warnings:
        return {"passed": False, "stage": "structure", "error": "; ".join(warnings), "output": ""}

    if not body.dry_run:
        return {"passed": True, "stage": "static", "output": "Static validation passed"}

    # Stage 3: dry-run against dev switch
    with get_db() as conn:
        dev_row = conn.execute("SELECT * FROM devices WHERE is_dev_switch=1 LIMIT 1").fetchone()

    if dev_row:
        dev_info = dict(dev_row)
    else:
        dev_info = {"hostname": DEV_SWITCH_HN, "ip": DEV_SWITCH_IP, "platform": "iosxe"}

    testbed_yaml = build_testbed_yaml([dev_info])

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path  = os.path.join(tmpdir, "test_script.py")
        testbed_path = os.path.join(tmpdir, "testbed.yaml")
        with open(script_path,  "w") as f:
            f.write(script_content)
        with open(testbed_path, "w") as f:
            f.write(testbed_yaml)
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, script_path, testbed_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=tmpdir
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode() + stderr.decode()
            passed = proc.returncode == 0 and _pyats_passed(output)
            now    = datetime.now(timezone.utc).isoformat()
            with get_db() as conn:
                conn.execute(
                    "UPDATE scripts SET last_run_at=?, last_run_status=?, last_run_output=? WHERE id=?",
                    (now, "PASS" if passed else "FAIL", output, script_id)
                )
            return {"passed": passed, "stage": "dry_run", "output": output,
                    "device": dev_info.get("ip", DEV_SWITCH_IP)}
        except asyncio.TimeoutError:
            proc.kill()
            return {"passed": False, "stage": "dry_run", "error": "Timed out (120s)", "output": ""}
        except Exception as e:
            return {"passed": False, "stage": "dry_run", "error": str(e), "output": ""}


# ── Script Execution ──────────────────────────────────────────────────────────

MAX_AUTOFIX_RETRIES = 2

async def _autofix_script(script: str, error: str, model: str | None = None) -> str | None:
    """Send broken script + error to Ollama, return fixed script or None."""
    fix_model = model or OLLAMA_MODEL
    prompt = (
        "The following pyATS/Genie test script has an error. "
        "Fix the script and return ONLY the complete corrected Python script inside a single ```python code fence. "
        "Do not explain, do not add commentary outside the code fence.\n\n"
        f"ERROR:\n{error}\n\n"
        f"SCRIPT:\n```python\n{script}\n```"
    )
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": fix_model, "messages": [{"role": "user", "content": prompt}], "stream": False, "options": {"num_ctx": 32768}},
            )
            if r.status_code != 200:
                return None
            content = r.json().get("message", {}).get("content", "")
            # Extract code from ```python ... ``` fence
            m = re.search(r'```python\s*\n(.*?)```', content, re.DOTALL)
            if m:
                return m.group(1).strip()
            # Fallback: try ``` ... ```
            m = re.search(r'```\s*\n(.*?)```', content, re.DOTALL)
            if m:
                return m.group(1).strip()
    except Exception as e:
        log.warning("Autofix request failed: %s", e)
    return None


async def _run_script_once(script_content: str, testbed_yaml: str, timeout: int = 300, task_id: str | None = None):
    """Run a pyATS script, return (passed, output). If task_id given, register proc for kill support."""
    with tempfile.TemporaryDirectory() as tmpdir:
        script_path  = os.path.join(tmpdir, "test_script.py")
        testbed_path = os.path.join(tmpdir, "testbed.yaml")
        with open(script_path,  "w") as f:
            f.write(script_content)
        with open(testbed_path, "w") as f:
            f.write(testbed_yaml)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path, testbed_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=tmpdir
        )
        if task_id:
            _active_procs[task_id] = proc
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        finally:
            if task_id:
                _active_procs.pop(task_id, None)
        if task_id and task_id in _cancelled_tasks:
            return False, "⚠ Task killed by user."
        output = stdout.decode() + stderr.decode()
        passed = proc.returncode == 0 and _pyats_passed(output)
        return passed, output


def _is_script_error(output: str) -> bool:
    """Return True if the output indicates a script-level error (syntax, import, attribute)."""
    return bool(re.search(r'(SyntaxError|IndentationError|NameError|ImportError|AttributeError|TypeError):', output))


@app.post("/api/scripts/{script_id}/run")
async def run_script(script_id: str, body: RunRequest):
    with get_db() as conn:
        script_row = conn.execute("SELECT * FROM scripts WHERE id=?",    (script_id,)).fetchone()
        dev_row    = conn.execute("SELECT * FROM devices WHERE id=?", (body.device_id,)).fetchone()

    if not script_row:
        raise HTTPException(404, "Script not found")
    if not dev_row:
        raise HTTPException(404, "Device not found")

    dev_info     = dict(dev_row)
    display_name = dev_info["hostname"]
    testbed_yaml = build_testbed_yaml([dev_info])

    script_content = sanitize_script(script_row["script"])
    autofix_log = []

    try:
        passed, output = await _run_script_once(script_content, testbed_yaml)

        # Auto-fix loop: if the script has a code error, ask LLM to fix and re-run
        retries = 0
        while not passed and _is_script_error(output) and retries < MAX_AUTOFIX_RETRIES:
            retries += 1
            log.info("Auto-fix attempt %d/%d for script %s", retries, MAX_AUTOFIX_RETRIES, script_id)
            autofix_log.append(f"--- AUTO-FIX ATTEMPT {retries}/{MAX_AUTOFIX_RETRIES} ---")

            # Extract just the error portion for the LLM (last 60 lines)
            error_lines = output.strip().split("\n")
            error_tail = "\n".join(error_lines[-60:])
            autofix_log.append(f"Error detected:\n{error_tail}")

            fixed = await _autofix_script(script_content, error_tail)
            if not fixed:
                autofix_log.append("LLM could not produce a fix. Stopping.")
                break

            script_content = sanitize_script(fixed)
            autofix_log.append("LLM returned fixed script. Re-running...")
            passed, output = await _run_script_once(script_content, testbed_yaml)

            if passed:
                autofix_log.append("Fixed script PASSED. Saving corrected version to database.")
                # Save the working fixed script back to DB
                with get_db() as conn:
                    conn.execute("UPDATE scripts SET script=?, updated_at=? WHERE id=?",
                                 (script_content, datetime.now(timezone.utc).isoformat(), script_id))
            else:
                autofix_log.append("Fixed script still failing.")

        status = "PASS" if passed else "FAIL"
        now    = datetime.now(timezone.utc).isoformat()

        # Prepend autofix log to output if any fix attempts were made
        full_output = output
        if autofix_log:
            full_output = "\n".join(autofix_log) + "\n\n--- FINAL RUN OUTPUT ---\n" + output

        with get_db() as conn:
            conn.execute(
                "UPDATE scripts SET last_run_at=?, last_run_status=?, last_run_output=? WHERE id=?",
                (now, status, full_output, script_id)
            )
        return {"passed": passed, "status": status, "device": display_name,
                "output": full_output, "run_at": now,
                "autofix_applied": len(autofix_log) > 0}
    except asyncio.TimeoutError:
        return {"passed": False, "status": "FAIL", "error": "Timed out (300s)", "output": ""}
    except Exception as e:
        return {"passed": False, "status": "FAIL", "error": str(e), "output": ""}


# ── Template Library ──────────────────────────────────────────────────────────

@app.get("/api/templates")
async def list_templates():
    return {"templates": [
        {"id": t["id"], "name": t["name"], "description": t["description"], "platform": t["platform"]}
        for t in TEMPLATES
    ]}


@app.get("/api/templates/{template_id}")
async def get_template(template_id: str):
    for t in TEMPLATES:
        if t["id"] == template_id:
            return t
    raise HTTPException(404, "Template not found")


@app.post("/api/templates/{template_id}/deploy")
async def deploy_template(template_id: str):
    for t in TEMPLATES:
        if t["id"] == template_id:
            now = datetime.now(timezone.utc).isoformat()
            sid = str(uuid.uuid4())
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO scripts (id, name, description, platform, script, template_id, "
                    "created_at, updated_at, last_run_status) VALUES (?,?,?,?,?,?,?,?,?)",
                    (sid, t["name"], t["description"], t["platform"], t["script"], t["id"], now, now, "NEVER")
                )
            return {"id": sid, "name": t["name"]}
    raise HTTPException(404, "Template not found")


# ── Device Management ─────────────────────────────────────────────────────────

@app.get("/api/devices")
async def list_devices():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, hostname, ip, platform, is_dev_switch, source FROM devices ORDER BY hostname"
        ).fetchall()
    return {"devices": [dict(r) for r in rows]}


@app.post("/api/devices")
async def add_device(body: DeviceCreate):
    did = str(uuid.uuid4())
    with get_db() as conn:
        if body.is_dev_switch:
            conn.execute("UPDATE devices SET is_dev_switch=0")
        conn.execute(
            "INSERT INTO devices (id, hostname, ip, platform, username, password, is_dev_switch, source) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (did, body.hostname, body.ip, body.platform, body.username, body.password,
             int(body.is_dev_switch), "manual")
        )
    return {"id": did, "hostname": body.hostname}


@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
    return {"deleted": device_id}


@app.post("/api/devices/{device_id}/set_dev_switch")
async def set_dev_switch(device_id: str):
    with get_db() as conn:
        conn.execute("UPDATE devices SET is_dev_switch=0")
        conn.execute("UPDATE devices SET is_dev_switch=1 WHERE id=?", (device_id,))
    return {"dev_switch": device_id}


@app.post("/api/devices/sync_snmp")
async def sync_snmp_devices():
    try:
        r = httpx.get(f"{SNMP_URL}/devices", timeout=10)
        r.raise_for_status()
        snmp_devices = r.json().get("devices", [])
    except Exception as e:
        raise HTTPException(503, f"SNMP sync failed: {e}")

    synced = 0
    with get_db() as conn:
        for d in snmp_devices:
            ip       = d.get("host", "")
            hostname = d.get("sysName", ip).split(".")[0]
            if not ip:
                continue
            existing = conn.execute("SELECT id FROM devices WHERE ip=?", (ip,)).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO devices (id, hostname, ip, platform, is_dev_switch, source) VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()), hostname, ip, "iosxe", 0, "snmp")
                )
                synced += 1
    return {"synced": synced, "total": len(snmp_devices)}


# ── Testbed Export ────────────────────────────────────────────────────────────

@app.get("/api/testbed")
async def get_testbed():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY hostname").fetchall()
    devices = [dict(r) for r in rows]
    if not devices:
        return {"yaml": "", "devices": []}
    safe = [{k: v for k, v in d.items() if k != "password"} for d in devices]
    return {"yaml": build_testbed_yaml(devices), "devices": safe}


# ── Genie Learn / Diff ────────────────────────────────────────────────────────

GENIE_LEARN_FEATURES = [
    {"id": "interface",  "name": "Interfaces",      "description": "Interface status, counters, IP addresses"},
    {"id": "bgp",        "name": "BGP",              "description": "BGP neighbors, prefixes, AS numbers"},
    {"id": "ospf",       "name": "OSPF",             "description": "OSPF neighbors, areas, LSAs"},
    {"id": "routing",    "name": "Routing Table",    "description": "Full routing table (all protocols)"},
    {"id": "vlan",       "name": "VLANs",            "description": "VLAN database and port assignments"},
    {"id": "stp",        "name": "Spanning Tree",    "description": "STP instances, root bridge, port states"},
    {"id": "arp",        "name": "ARP Table",        "description": "ARP cache entries"},
    {"id": "vrf",        "name": "VRF",              "description": "VRF instances and route targets"},
    {"id": "hsrp",       "name": "HSRP",             "description": "HSRP groups and standby state"},
    {"id": "ntp",        "name": "NTP",              "description": "NTP associations and sync status"},
    {"id": "acl",        "name": "ACLs",             "description": "Access control lists and entries"},
    {"id": "dot1x",      "name": "802.1X",           "description": "Dot1x authentication status"},
    {"id": "lldp",       "name": "LLDP",             "description": "LLDP neighbor discovery"},
    {"id": "cdp",        "name": "CDP",              "description": "CDP neighbor discovery"},
    {"id": "mcast",      "name": "Multicast",        "description": "Multicast groups and routing"},
    {"id": "platform",   "name": "Platform",         "description": "Hardware, software version, inventory"},
    {"id": "config",     "name": "Running Config",   "description": "Full running configuration"},
]


_PARSER_FEATURES = {
    "cdp": "show cdp neighbors detail",
    "config": "show running-config",
}

def _build_learn_script(feature: str) -> str:
    """Build a minimal pyATS script that learns a Genie feature and prints JSON."""
    if feature in _PARSER_FEATURES:
        return _build_parse_script(feature, _PARSER_FEATURES[feature])
    return f'''#!/usr/bin/env python3
"""Gladius: Genie Learn — {feature}"""
import json
import sys
from pyats import aetest
from genie.testbed import load

class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev

class LearnFeature(aetest.Testcase):
    @aetest.test
    def learn(self, dev):
        try:
            learned = dev.learn('{feature}')
        except Exception as e:
            self.failed(f'Learn {feature} failed: {{e}}')
        info = getattr(learned, 'info', None)
        if info is None:
            info = {{}}
        print(f"GLADIUS_LEARN:{{json.dumps(info, default=str)}}")
        self.passed('{feature} learned successfully')

class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for d in testbed.devices.values():
            try: d.disconnect()
            except Exception: pass

if __name__ == '__main__':
    aetest.main(testbed=load(sys.argv[1]))
'''


def _build_parse_script(feature: str, command: str) -> str:
    """Build a pyATS script that parses a show command and prints JSON."""
    return f'''#!/usr/bin/env python3
"""Gladius: Genie Parse — {feature}"""
import json
import sys
from pyats import aetest
from genie.testbed import load

class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        _dev = next(iter(testbed.devices.values()))
        _dev.connect(log_stdout=False)
        self.parent.parameters['dev'] = _dev
        self.parent.parameters['device'] = _dev

class ParseFeature(aetest.Testcase):
    @aetest.test
    def parse(self, dev):
        try:
            parsed = dev.parse('{command}')
        except Exception as e:
            self.failed(f'Parse {feature} failed: {{e}}')
        if not parsed:
            parsed = {{}}
        print(f"GLADIUS_LEARN:{{json.dumps(parsed, default=str)}}")
        self.passed('{feature} parsed successfully')

class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def disconnect(self, testbed):
        for d in testbed.devices.values():
            try: d.disconnect()
            except Exception: pass

if __name__ == '__main__':
    aetest.main(testbed=load(sys.argv[1]))
'''


def _extract_learn_data(output: str) -> dict | None:
    """Extract JSON from GLADIUS_LEARN: line in script output."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith('GLADIUS_LEARN:'):
            try:
                return json.loads(line[14:])
            except json.JSONDecodeError:
                pass
    return None


@app.get("/api/learn/features")
async def list_learn_features():
    return {"features": GENIE_LEARN_FEATURES}


@app.post("/api/learn")
async def run_learn(body: LearnRequest, _skip_task: bool = False):
    """Run Genie learn for selected features on selected devices."""
    with get_db() as conn:
        dev_rows = []
        for did in body.device_ids:
            row = conn.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()
            if row:
                dev_rows.append(dict(row))
    if not dev_rows:
        raise HTTPException(400, "No valid devices selected")

    dev_names = ", ".join(d["hostname"] for d in dev_rows[:3])
    feat_names = ", ".join(body.features[:3])
    task_id = None if _skip_task else await _register_task(
        "Learn", f"Genie Learn — {dev_names} — {feat_names}"
    )

    results = []
    for dev_info in dev_rows:
        testbed_yaml = build_testbed_yaml([dev_info])
        for feature in body.features:
            if feature not in [f["id"] for f in GENIE_LEARN_FEATURES]:
                results.append({"device": dev_info["hostname"], "feature": feature,
                                "success": False, "error": f"Unknown feature: {feature}"})
                continue

            script = _build_learn_script(feature)
            try:
                passed, output = await _run_script_once(script, testbed_yaml, timeout=120, task_id=task_id)
            except asyncio.TimeoutError:
                results.append({"device": dev_info["hostname"], "feature": feature,
                                "success": False, "error": "Timed out (120s)"})
                continue
            except Exception as e:
                results.append({"device": dev_info["hostname"], "feature": feature,
                                "success": False, "error": str(e)})
                continue

            # Check if task was killed
            if task_id and task_id in _cancelled_tasks:
                results.append({"device": dev_info["hostname"], "feature": feature,
                                "success": False, "error": "Task killed by user"})
                await _complete_task(task_id)
                return {"results": results, "killed": True}

            data = _extract_learn_data(output)
            if data is None:
                results.append({"device": dev_info["hostname"], "feature": feature,
                                "success": False, "error": "No structured data returned",
                                "output": output[-2000:]})
                continue

            snap_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO snapshots (id, device_id, device_name, feature, data, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (snap_id, dev_info["id"], dev_info["hostname"], feature,
                     json.dumps(data, default=str), now)
                )
            results.append({"device": dev_info["hostname"], "feature": feature,
                            "success": True, "snapshot_id": snap_id, "created_at": now})

    await _complete_task(task_id)
    return {"results": results}


@app.get("/api/learn/snapshots")
async def list_snapshots(device_id: Optional[str] = None, feature: Optional[str] = None):
    """List snapshots, optionally filtered by device and/or feature."""
    query = "SELECT id, device_id, device_name, feature, created_at FROM snapshots"
    params = []
    clauses = []
    if device_id:
        clauses.append("device_id=?")
        params.append(device_id)
    if feature:
        clauses.append("feature=?")
        params.append(feature)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return {"snapshots": [dict(r) for r in rows]}


@app.get("/api/learn/snapshots/{snapshot_id}")
async def get_snapshot(snapshot_id: str):
    """Get full snapshot data."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Snapshot not found")
    result = dict(row)
    result["data"] = json.loads(result["data"])
    return result


@app.delete("/api/learn/snapshots/{snapshot_id}")
async def delete_snapshot(snapshot_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM snapshots WHERE id=?", (snapshot_id,))
    return {"deleted": snapshot_id}


@app.post("/api/learn/diff")
async def diff_snapshots(body: DiffRequest):
    """Diff two snapshots and return the differences."""
    with get_db() as conn:
        row_a = conn.execute("SELECT * FROM snapshots WHERE id=?", (body.snapshot_a,)).fetchone()
        row_b = conn.execute("SELECT * FROM snapshots WHERE id=?", (body.snapshot_b,)).fetchone()
    if not row_a or not row_b:
        raise HTTPException(404, "One or both snapshots not found")

    a_info = dict(row_a)
    b_info = dict(row_b)
    data_a = json.loads(a_info["data"])
    data_b = json.loads(b_info["data"])

    # Use recursive dict diff since we can't import genie.utils.diff in the API process
    diff_lines = _dict_diff(data_a, data_b, prefix="")
    diff_text = "\n".join(diff_lines) if diff_lines else "No differences found."

    return {
        "diff": diff_text,
        "has_changes": len(diff_lines) > 0,
        "snapshot_a": {"id": a_info["id"], "device": a_info["device_name"],
                       "feature": a_info["feature"], "created_at": a_info["created_at"]},
        "snapshot_b": {"id": b_info["id"], "device": b_info["device_name"],
                       "feature": b_info["feature"], "created_at": b_info["created_at"]},
    }


def _dict_diff(a, b, prefix="") -> list[str]:
    """Recursively diff two dicts/values, returning human-readable diff lines."""
    lines = []
    if isinstance(a, dict) and isinstance(b, dict):
        all_keys = set(list(a.keys()) + list(b.keys()))
        for key in sorted(all_keys):
            path = f"{prefix}.{key}" if prefix else key
            if key not in a:
                lines.append(f"+ {path}: {json.dumps(b[key], default=str)}")
            elif key not in b:
                lines.append(f"- {path}: {json.dumps(a[key], default=str)}")
            else:
                lines.extend(_dict_diff(a[key], b[key], path))
    elif isinstance(a, list) and isinstance(b, list):
        if a != b:
            lines.append(f"  {prefix}:")
            lines.append(f"  - {json.dumps(a, default=str)}")
            lines.append(f"  + {json.dumps(b, default=str)}")
    else:
        if a != b:
            lines.append(f"  {prefix}:")
            lines.append(f"  - {json.dumps(a, default=str)}")
            lines.append(f"  + {json.dumps(b, default=str)}")
    return lines


@app.post("/api/learn/analyze")
async def analyze_diff(body: AnalyzeRequest):
    """Send a diff to Ollama for natural language analysis."""
    model = body.model or OLLAMA_MODEL
    device_b = body.device_b or body.device
    before_ts = body.before_ts or "unknown time"
    after_ts = body.after_ts or "unknown time"

    same_device = body.device == device_b
    if same_device:
        context = (
            f"You are analyzing changes on device '{body.device}' for the '{body.feature}' feature.\n"
            f"BEFORE snapshot was taken at: {before_ts}\n"
            f"AFTER snapshot was taken at: {after_ts}\n\n"
            f"This is a TEMPORAL diff — same device, two points in time.\n"
            f"Lines starting with '-' show the BEFORE state (older).\n"
            f"Lines starting with '+' show the AFTER state (newer/current).\n"
        )
    else:
        context = (
            f"You are comparing the '{body.feature}' feature between two devices.\n"
            f"Device A (BEFORE/baseline): '{body.device}' at {before_ts}\n"
            f"Device B (AFTER/comparison): '{device_b}' at {after_ts}\n\n"
            f"Lines starting with '-' are ONLY in device A.\n"
            f"Lines starting with '+' are ONLY in device B.\n"
            f"Differences between devices are expected — focus on anomalies.\n"
        )

    prompt = (
        f"{context}"
        f"\nDiff:\n```\n{body.diff_text}\n```\n\n"
        f"IMPORTANT RULES:\n"
        f"- The '-' lines are BEFORE, '+' lines are AFTER. Do not confuse the direction.\n"
        f"- If a counter goes from 100 (before) to 200 (after), it INCREASED, not decreased.\n"
        f"- Interface counters (in/out octets, packets, broadcasts, multicasts) are cumulative and ALWAYS increase over time. This is NORMAL traffic — never flag counter increments as issues.\n"
        f"- Interface error/discard counters (CRC errors, input errors, output errors, runts, giants, throttles, overruns, discards) also increment over time. Small steady increases are normal. Only flag LARGE SPIKES in errors (e.g. thousands of new errors between polls).\n"
        f"- Focus on operationally significant changes (state changes, new/removed entries, error SPIKES).\n"
        f"- Ignore cosmetic differences (uptime, timestamps, counters that naturally increment).\n\n"
        f"Provide a concise analysis in EXACTLY this format:\n\n"
        f"SEVERITY: <LOW|MEDIUM|HIGH>\n\n"
        f"Choose severity based on:\n"
        f"- LOW: cosmetic changes, normal counter increments (traffic octets/packets/broadcasts), expected state transitions, uptime changes\n"
        f"- MEDIUM: configuration changes, new/removed entries, non-critical state changes, moderate error counter increases\n"
        f"- HIGH: security changes, link/protocol state flaps, LARGE error counter spikes (thousands of new errors), route changes, ACL modifications\n\n"
        f"SUMMARY: <one-line summary of what changed>\n\n"
        f"ANALYSIS:\n"
        f"1. What changed and its potential impact\n"
        f"2. Whether any changes are concerning (security, stability, performance)\n"
        f"3. Recommended actions if any"
    )
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(f"{OLLAMA_URL}/api/generate", json={
                "model": model, "prompt": prompt, "stream": False,
                "options": {"num_ctx": 32768}
            })
            r.raise_for_status()
            analysis = r.json().get("response", "")
    except Exception as e:
        raise HTTPException(502, f"Ollama analysis failed: {e}")

    return {"analysis": analysis, "model": model}


# ── SCHEDULE CRUD ──────────────────────────────────────────────────────────────

@app.get("/api/learn/schedules")
async def list_schedules():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
    schedules = []
    for r in rows:
        d = dict(r)
        d["next_run_at"] = _cron_next_run(d.get("cron_expr", "")) if d.get("enabled") else None
        schedules.append(d)
    return {"schedules": schedules}


@app.post("/api/learn/schedules")
async def create_schedule(body: ScheduleCreate):
    sid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO schedules (id,name,type,device_ids,features,cron_expr,notify_slack,notify_email,jira_auto_ticket,enabled,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (sid, body.name, body.type, json.dumps(body.device_ids), json.dumps(body.features),
             body.cron_expr, body.notify_slack or "", body.notify_email or "",
             body.jira_auto_ticket or "", 1 if body.enabled else 0, now)
        )
    return {"id": sid, "created_at": now}


@app.patch("/api/learn/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, body: ScheduleUpdate):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Schedule not found")
        updates, params = [], []
        if body.name is not None:
            updates.append("name=?"); params.append(body.name)
        if body.device_ids is not None:
            updates.append("device_ids=?"); params.append(json.dumps(body.device_ids))
        if body.features is not None:
            updates.append("features=?"); params.append(json.dumps(body.features))
        if body.cron_expr is not None:
            updates.append("cron_expr=?"); params.append(body.cron_expr)
        if body.notify_slack is not None:
            updates.append("notify_slack=?"); params.append(body.notify_slack)
        if body.notify_email is not None:
            updates.append("notify_email=?"); params.append(body.notify_email)
        if body.jira_auto_ticket is not None:
            updates.append("jira_auto_ticket=?"); params.append(body.jira_auto_ticket)
        if body.enabled is not None:
            updates.append("enabled=?"); params.append(1 if body.enabled else 0)
        if updates:
            params.append(schedule_id)
            conn.execute(f"UPDATE schedules SET {','.join(updates)} WHERE id=?", params)
    return {"ok": True}


@app.delete("/api/learn/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM schedule_history WHERE schedule_id=?", (schedule_id,))
        conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    return {"ok": True}


@app.get("/api/learn/schedules/reasoning-log")
async def schedule_reasoning_log(limit: int = 30):
    """Return all schedule history entries that have a stored AI analysis."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT h.id, h.schedule_id, h.status, h.summary, h.diff_text, h.analysis, h.ran_at, s.name as sched_name "
            "FROM schedule_history h LEFT JOIN schedules s ON h.schedule_id = s.id "
            "WHERE h.analysis IS NOT NULL AND h.analysis != '' "
            "ORDER BY h.ran_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return {"entries": [dict(r) for r in rows]}


@app.get("/api/learn/schedules/{schedule_id}/history")
async def schedule_history(schedule_id: str, limit: int = 20):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM schedule_history WHERE schedule_id=? ORDER BY ran_at DESC LIMIT ?",
            (schedule_id, limit)
        ).fetchall()
    return {"history": [dict(r) for r in rows]}


@app.get("/api/learn/schedules/history/{history_id}/analysis")
async def schedule_history_analysis(history_id: str):
    """Return the Ollama analysis text for a single history entry."""
    with get_db() as conn:
        row = conn.execute("SELECT id, schedule_id, analysis, summary, ran_at FROM schedule_history WHERE id=?", (history_id,)).fetchone()
    if not row:
        raise HTTPException(404, "History entry not found")
    return {"id": row["id"], "analysis": row["analysis"] or "", "summary": row["summary"] or "", "ran_at": row["ran_at"]}


@app.post("/api/learn/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: str):
    """Manually trigger a scheduled job."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Schedule not found")
    sched = dict(row)
    asyncio.create_task(_execute_schedule(sched))
    return {"ok": True, "message": "Schedule triggered"}


# ── NOTIFICATIONS ──────────────────────────────────────────────────────────────

SMTP_SERVER   = os.getenv("SMTP_SERVER", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM_NAME", "Gladius Auto")


def _send_slack(webhook_url: str, text: str):
    """Send a message to a Slack webhook."""
    try:
        r = httpx.post(webhook_url, json={"text": text}, timeout=10)
        r.raise_for_status()
    except Exception as e:
        log.error("Slack notification failed: %s", e)


def _send_email_notification(to: str, subject: str, body_html: str):
    """Send an email notification via SMTP."""
    if not SMTP_SERVER or not to:
        log.warning("Email notification skipped — SMTP not configured or no recipient")
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{SMTP_FROM} <{SMTP_USERNAME}>"
        msg["To"] = to
        msg.attach(MIMEText(body_html, "html"))
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USERNAME, SMTP_PASSWORD)
            s.send_message(msg)
    except Exception as e:
        log.error("Email notification failed: %s", e)


def _notify_schedule(sched: dict, subject: str, body: str, html: str):
    """Send notifications for a schedule result."""
    slack_url = sched.get("notify_slack", "")
    email_to  = sched.get("notify_email", "")
    if slack_url:
        _send_slack(slack_url, f"*{subject}*\n{body}")
    if email_to:
        _send_email_notification(email_to, f"[Gladius] {subject}", html)


# ── JIRA INTEGRATION ─────────────────────────────────────────────────────────

JIRA_PRIORITY_MAP = {
    "P1": "Highest",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low",
}


def _jira_headers() -> dict:
    creds = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


async def _create_jira_ticket(
    summary: str,
    description: Any,
    priority: str = "P3",
    labels: list[str] | None = None,
    issue_type: str | None = None,
    project_key: str | None = None,
) -> dict:
    """Create a Jira Cloud issue. Returns {"key": "NET-123", "id": "...", "url": "..."}.

    `description` may be:
      - a string  → split into ADF paragraphs (one per line)
      - a list    → treated as ADF content array, wrapped in a doc node
      - a dict with type=="doc" → used directly as the ADF document
    """
    if not JIRA_CONFIGURED:
        raise ValueError("Jira not configured — set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT")

    proj = project_key or JIRA_PROJECT
    itype = issue_type or JIRA_ISSUE_TYPE
    jira_priority = JIRA_PRIORITY_MAP.get(priority, "Medium")

    # Jira Cloud v3 uses ADF (Atlassian Document Format) for description.
    # Accept pre-built ADF (richest formatting) or a plain string (back-compat).
    if isinstance(description, dict) and description.get("type") == "doc":
        description_adf = description
    elif isinstance(description, list):
        description_adf = {"type": "doc", "version": 1, "content": description}
    else:
        text = str(description or "")
        adf_content = [
            {"type": "paragraph", "content": [{"type": "text", "text": line}]}
            for line in text.split("\n") if line.strip()
        ]
        description_adf = {"type": "doc", "version": 1, "content": adf_content or [
            {"type": "paragraph", "content": [{"type": "text", "text": "No description provided"}]}
        ]}

    payload = {
        "fields": {
            "project": {"key": proj},
            "summary": summary[:255],
            "description": description_adf,
            "issuetype": {"name": itype},
            "priority": {"name": jira_priority},
            "labels": labels or ["gladius", "auto-generated"],
        }
    }

    url = f"{JIRA_URL.rstrip('/')}/rest/api/3/issue"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload, headers=_jira_headers())
        if resp.status_code not in (200, 201):
            log.error("Jira create failed: %s %s", resp.status_code, resp.text)
            raise ValueError(f"Jira API error {resp.status_code}: {resp.text}")
        data = resp.json()
        issue_key = data["key"]
        return {
            "key": issue_key,
            "id": data["id"],
            "url": f"{JIRA_URL.rstrip('/')}/browse/{issue_key}",
        }


# ── CRON PARSER & SCHEDULER ──────────────────────────────────────────────────

def _cron_matches(cron_expr: str, dt: datetime) -> bool:
    """Check if a cron expression matches a given datetime (minute granularity).
    Supports: minute hour day-of-month month day-of-week
    Fields: number, *, */N, comma-separated, ranges (N-M).
    """
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False
    fields = [dt.minute, dt.hour, dt.day, dt.month, dt.isoweekday() % 7]  # 0=Sun

    for field_val, pattern in zip(fields, parts):
        if not _cron_field_matches(pattern, field_val):
            return False
    return True


def _cron_field_matches(pattern: str, value: int) -> bool:
    if pattern == "*":
        return True
    for part in pattern.split(","):
        if "/" in part:
            base, step = part.split("/", 1)
            step = int(step)
            if base == "*":
                if value % step == 0:
                    return True
            else:
                start = int(base)
                if value >= start and (value - start) % step == 0:
                    return True
        elif "-" in part:
            lo, hi = part.split("-", 1)
            if int(lo) <= value <= int(hi):
                return True
        else:
            if int(part) == value:
                return True
    return False


def _cron_next_run(cron_expr: str, after: datetime | None = None) -> str | None:
    """Return ISO timestamp of the next minute that matches *cron_expr*."""
    try:
        dt = (after or datetime.now(timezone.utc)).replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(60 * 24 * 400):          # scan up to ~400 days
            if _cron_matches(cron_expr, dt):
                return dt.isoformat()
            dt += timedelta(minutes=1)
    except Exception:
        pass
    return None


async def _execute_schedule(sched: dict):
    """Execute a learn (and optionally diff) schedule."""
    sched_id = sched["id"]
    sched_type = sched.get("type", "learn")
    device_ids = json.loads(sched["device_ids"]) if isinstance(sched["device_ids"], str) else sched["device_ids"]
    features = json.loads(sched["features"]) if isinstance(sched["features"], str) else sched["features"]

    log.info("Executing schedule '%s' (type=%s, devices=%d, features=%d)",
             sched["name"], sched_type, len(device_ids), len(features))

    label = "Learn + Diff" if sched_type == "learn_diff" else "Learn"
    sched_task_id = await _register_task(label, f"Schedule: {sched['name']}")

    now_iso = datetime.now(timezone.utc).isoformat()
    status = "success"
    summary_parts = []
    diff_text = ""

    # Step 1: Run learn
    try:
        learn_body = LearnRequest(device_ids=device_ids, features=features)
        learn_result = await run_learn(learn_body, _skip_task=True)
        results = learn_result.get("results", [])
        ok_count = sum(1 for r in results if r.get("success"))
        fail_count = sum(1 for r in results if not r.get("success"))
        summary_parts.append(f"Learn: {ok_count} succeeded, {fail_count} failed")
        if fail_count > 0:
            status = "partial"
            fails = [f"{r['device']}/{r['feature']}: {r.get('error','?')}" for r in results if not r.get("success")]
            summary_parts.append("Failures: " + "; ".join(fails))
        new_snap_ids = [r["snapshot_id"] for r in results if r.get("success") and "snapshot_id" in r]
    except Exception as e:
        log.error("Schedule learn failed: %s", e)
        status = "error"
        summary_parts.append(f"Learn error: {e}")
        new_snap_ids = []

    # Step 2: If learn_diff, run diff against previous snapshots
    if sched_type == "learn_diff" and new_snap_ids:
        diff_parts = []
        for snap_id in new_snap_ids:
            with get_db() as conn:
                new_snap = conn.execute("SELECT * FROM snapshots WHERE id=?", (snap_id,)).fetchone()
                if not new_snap:
                    continue
                new_snap = dict(new_snap)
                # Find the most recent previous snapshot for the same device+feature
                prev = conn.execute(
                    "SELECT id FROM snapshots WHERE device_id=? AND feature=? AND id!=? ORDER BY created_at DESC LIMIT 1",
                    (new_snap["device_id"], new_snap["feature"], snap_id)
                ).fetchone()
            if not prev:
                continue
            try:
                diff_body = DiffRequest(snapshot_a=prev["id"], snapshot_b=snap_id)
                diff_result = await diff_snapshots(diff_body)
                if diff_result.get("has_changes"):
                    diff_parts.append(
                        f"=== {new_snap['device_name']} / {new_snap['feature']} ===\n{diff_result['diff']}"
                    )
            except Exception as e:
                diff_parts.append(f"Diff error for {new_snap['device_name']}/{new_snap['feature']}: {e}")

        if diff_parts:
            diff_text = "\n\n".join(diff_parts)
            summary_parts.append(f"Diff: {len(diff_parts)} change(s) detected")
        else:
            summary_parts.append("Diff: no changes detected")

    summary = " | ".join(summary_parts)

    # Save to history
    hist_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO schedule_history (id,schedule_id,type,status,summary,diff_text,ran_at) VALUES (?,?,?,?,?,?,?)",
            (hist_id, sched_id, sched_type, status, summary, diff_text, now_iso)
        )
        conn.execute("UPDATE schedules SET last_run_at=?, last_status=? WHERE id=?",
                      (now_iso, status, sched_id))

    # Analyze diffs with Ollama before notifying
    analysis_text = ""
    if diff_text:
        try:
            log.info("Schedule '%s': analyzing diff with Ollama…", sched["name"])
            analyze_body = AnalyzeRequest(
                diff_text=diff_text,
                feature="scheduled",
                device=sched["name"],
                before_ts=now_iso,
                after_ts=now_iso,
            )
            analyze_result = await analyze_diff(analyze_body)
            analysis_text = analyze_result.get("analysis", "")
        except Exception as e:
            log.error("Schedule Ollama analysis failed (falling back to raw diff): %s", e)

    # Persist analysis text to history row
    if analysis_text:
        try:
            with get_db() as conn:
                conn.execute("UPDATE schedule_history SET analysis=? WHERE id=?", (analysis_text, hist_id))
        except Exception as e:
            log.error("Failed to save analysis to history: %s", e)

    # Notifications
    subject = f"Schedule '{sched['name']}' — {status.upper()}"
    if analysis_text:
        body_plain = summary + "\n\n" + analysis_text
        body_html = _build_schedule_email_html(sched, status, summary, diff_text, analysis_text)
    else:
        body_plain = summary + (f"\n\n{diff_text}" if diff_text else "")
        body_html = _build_schedule_email_html(sched, status, summary, diff_text, "")
    _notify_schedule(sched, subject, body_plain, body_html)

    # Jira auto-ticket for scheduled diffs with changes
    jira_auto = sched.get("jira_auto_ticket", "")
    if JIRA_CONFIGURED and jira_auto and diff_text:
        jira_severity = "P3"
        jira_summary = f"Network Change Detected — {sched['name']}"
        should_ticket = True

        if analysis_text:
            sev_match = re.search(r"SEVERITY:\s*(LOW|MEDIUM|HIGH)", analysis_text, re.IGNORECASE)
            if sev_match:
                sev = sev_match.group(1).upper()
                if sev == "HIGH":
                    jira_severity = "P2"
                elif sev == "MEDIUM":
                    jira_severity = "P3"
                    if jira_auto == "high_only":
                        should_ticket = False
                elif sev == "LOW":
                    jira_severity = "P4"
                    if jira_auto in ("high_only", "medium_plus"):
                        should_ticket = False
            sum_match = re.search(r"SUMMARY:\s*(.+)", analysis_text, re.IGNORECASE)
            if sum_match:
                jira_summary = sum_match.group(1).strip()

        if should_ticket:
            try:
                result = await _create_jira_ticket(
                    summary=jira_summary,
                    description=f"Schedule: {sched['name']}\nStatus: {status}\n\n{summary}\n\n{analysis_text or diff_text}",
                    priority=jira_severity,
                    labels=["gladius", "scheduled-diff", "auto-generated"],
                )
                log.info("Jira ticket created for schedule '%s': %s", sched["name"], result["key"])
            except Exception as e:
                log.error("Jira auto-ticket failed for schedule '%s': %s", sched["name"], e)

    await _complete_task(sched_task_id)
    log.info("Schedule '%s' completed: %s", sched["name"], summary)


def _build_schedule_email_html(sched: dict, status: str, summary: str, diff_text: str, analysis: str = "") -> str:
    """Build an HTML email body for schedule results."""
    import re as _re
    status_color = "#00cc66" if status == "success" else "#ffaa00" if status == "partial" else "#ff4444"

    # AI Analysis section (primary content when available)
    analysis_html = ""
    if analysis:
        sev_m = _re.search(r"SEVERITY:\s*(LOW|MEDIUM|HIGH)", analysis, _re.IGNORECASE)
        sum_m = _re.search(r"SUMMARY:\s*(.+)", analysis, _re.IGNORECASE)
        sev = sev_m.group(1).upper() if sev_m else None
        sev_summary = sum_m.group(1).strip() if sum_m else ""
        sev_colors = {"LOW": "#00cc66", "MEDIUM": "#ffaa00", "HIGH": "#ff4444"}
        sev_bg = {"LOW": "rgba(0,204,102,0.12)", "MEDIUM": "rgba(255,170,0,0.12)", "HIGH": "rgba(255,68,68,0.12)"}
        sev_color = sev_colors.get(sev, "#888")
        sev_bgcolor = sev_bg.get(sev, "transparent")

        # Severity banner
        if sev:
            sev_icon = "&#9888;" if sev == "HIGH" else "&#9670;" if sev == "MEDIUM" else "&#10003;"
            analysis_html += f"""
            <div style="margin:16px 0 12px;padding:10px 14px;border-radius:6px;background:{sev_bgcolor};border-left:4px solid {sev_color}">
                <span style="font-size:14px;font-weight:700;color:{sev_color}">{sev_icon} {sev} SEVERITY</span>
                {'<div style="font-size:12px;color:#ccc;margin-top:4px">' + sev_summary + '</div>' if sev_summary else ''}
            </div>"""

        # Format analysis body — strip SEVERITY/SUMMARY lines
        body = analysis
        body = _re.sub(r"^SEVERITY:\s*.+$", "", body, flags=_re.MULTILINE | _re.IGNORECASE)
        body = _re.sub(r"^SUMMARY:\s*.+$", "", body, flags=_re.MULTILINE | _re.IGNORECASE)
        body = body.strip()

        # Convert numbered items and section headers
        formatted_lines = []
        for line in body.split("\n"):
            stripped = line.strip()
            if not stripped:
                formatted_lines.append("<br>")
            elif _re.match(r"^ANALYSIS:?$", stripped, _re.IGNORECASE):
                formatted_lines.append(
                    '<h3 style="color:#00d4ff;font-size:13px;margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid #333">ANALYSIS</h3>'
                )
            elif _re.match(r"^\d+\.", stripped):
                num_m = _re.match(r"^(\d+)\.\s*(.+)", stripped)
                if num_m:
                    formatted_lines.append(
                        f'<div style="display:flex;gap:8px;margin:4px 0;padding:8px 10px;background:#111;border-radius:4px;border-left:2px solid #00d4ff">'
                        f'<span style="color:#00d4ff;font-weight:700;min-width:18px">{num_m.group(1)}.</span>'
                        f'<span style="color:#ccc">{num_m.group(2)}</span></div>'
                    )
                else:
                    formatted_lines.append(f'<div style="color:#ccc;margin:2px 0">{stripped}</div>')
            elif stripped.startswith("-") or stripped.startswith("•"):
                formatted_lines.append(
                    f'<div style="margin:2px 0 2px 16px;color:#aaa">&#8226; {stripped.lstrip("-•").strip()}</div>'
                )
            else:
                formatted_lines.append(f'<div style="color:#ccc;margin:2px 0">{stripped}</div>')

        analysis_html += f"""
        <div style="margin-top:12px;font-size:12px;line-height:1.7">
            {"".join(formatted_lines)}
        </div>"""

    # Raw diff (collapsed if analysis present, shown if not)
    diff_html = ""
    if diff_text:
        lines = diff_text.split("\n")
        diff_lines = []
        for line in lines:
            if line.startswith("+"):
                diff_lines.append(f'<span style="color:#00cc66">{line}</span>')
            elif line.startswith("-"):
                diff_lines.append(f'<span style="color:#ff4444">{line}</span>')
            elif line.startswith("==="):
                diff_lines.append(f'<br><strong style="color:#00d4ff">{line}</strong>')
            else:
                diff_lines.append(line)
        label = "RAW DIFF" if analysis else "DIFF RESULTS"
        diff_html = f"""
        <div style="margin-top:16px">
            <h3 style="color:#00d4ff;font-family:monospace;font-size:13px;margin-bottom:8px">{label}</h3>
            <pre style="background:#111;color:#ccc;padding:12px;border-radius:6px;font-size:11px;overflow-x:auto;border:1px solid #222">{"<br>".join(diff_lines)}</pre>
        </div>"""

    return f"""
    <div style="background:#0a0a0a;color:#ccc;padding:24px;font-family:monospace;border-radius:8px;max-width:700px">
        <h2 style="color:#00d4ff;margin:0 0 8px 0;font-size:16px">GLADIUS AUTOMATION — SCHEDULED JOB</h2>
        <div style="margin-bottom:12px">
            <span style="font-size:12px;color:#888">Schedule:</span>
            <strong style="color:#fff"> {sched['name']}</strong>
        </div>
        <div style="margin-bottom:12px">
            <span style="font-size:12px;color:#888">Status:</span>
            <strong style="color:{status_color}"> {status.upper()}</strong>
        </div>
        <div style="margin-bottom:4px;font-size:12px;color:#aaa">{summary}</div>
        {analysis_html}
        {diff_html}
        <div style="margin-top:20px;font-size:10px;color:#555">Gladius Automation Factory · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
    </div>"""


async def _scheduler_loop():
    """Background loop that checks schedules every 60 seconds."""
    log.info("Scheduler loop started")
    last_check_minute = -1
    while True:
        await asyncio.sleep(30)
        now = datetime.now(timezone.utc)
        current_minute = now.hour * 60 + now.minute
        if current_minute == last_check_minute:
            continue
        last_check_minute = current_minute

        try:
            with get_db() as conn:
                rows = conn.execute("SELECT * FROM schedules WHERE enabled=1").fetchall()
            for row in rows:
                sched = dict(row)
                if _cron_matches(sched["cron_expr"], now):
                    asyncio.create_task(_execute_schedule(sched))
        except Exception as e:
            log.error("Scheduler loop error: %s", e)


@app.on_event("startup")
async def start_scheduler():
    asyncio.create_task(_scheduler_loop())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
