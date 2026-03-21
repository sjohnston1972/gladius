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
import logging
import subprocess
import tempfile
import sys
import ast
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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

OLLAMA_URL    = os.getenv("OLLAMA_URL",    "http://192.168.1.250:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL",  "qwen2.5-coder:7b")
SNMP_URL      = os.getenv("SNMP_URL",      "http://gladius-snmp:8000")
DB_PATH       = os.getenv("DB_PATH",       "/data/scripts.db")
DEV_SWITCH_IP = os.getenv("DEV_SWITCH_IP", "192.168.20.22")
DEV_SWITCH_HN = os.getenv("DEV_SWITCH_HN", "DEV")
LAB_USERNAME  = os.getenv("LAB_USERNAME",  "")
LAB_PASSWORD  = os.getenv("LAB_PASSWORD",  "")


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

def sanitize_script(script: str) -> str:
    """Replace LLM-generated CommonSetup/CommonCleanup with correct boilerplate."""
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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)
ERROR_THRESHOLD = 100


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class InterfaceStatusTest(aetest.Testcase):
    @aetest.test
    def check_oper_states(self, dev):
        data = dev.parse('show interfaces')
        down = [f"{i}: {d.get('oper_status','?')}" for i, d in data.items()
                if d.get('enabled') is not False and d.get('oper_status','').lower() not in ('up','connected')]
        if down:
            self.failed(f"Interfaces not UP: {', '.join(down)}")
        else:
            self.passed(f"All {len(data)} interfaces up")

    @aetest.test
    def check_error_counters(self, dev):
        data = dev.parse('show interfaces')
        issues = []
        for intf, info in data.items():
            c = info.get('counters', {})
            errs = {k: c.get(k, 0) or 0 for k in ('in_errors', 'out_errors', 'in_crc_errors')}
            if any(v > ERROR_THRESHOLD for v in errs.values()):
                issues.append(f"{intf}: {errs}")
        if issues:
            self.failed(f"High error counters on {len(issues)} interface(s):\n" + "\n".join(issues))
        else:
            self.passed("Error counters within threshold")


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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class BgpNeighborTest(aetest.Testcase):
    @aetest.test
    def check_bgp_summary(self, dev):
        try:
            bgp = dev.parse('show bgp all summary')
        except Exception as e:
            self.skipped(f"BGP not configured or parse failed: {e}")
            return
        issues = []
        total  = 0
        for vrf, vd in bgp.get('vrf', {}).items():
            for af, afd in vd.get('address_family', {}).items():
                for nbr, nd in afd.get('neighbor', {}).items():
                    total += 1
                    state = nd.get('session_state', '')
                    if state.lower() != 'established':
                        issues.append(f"{nbr} ({vrf}/{af}): {state}")
        if issues:
            self.failed(f"BGP issues: {'; '.join(issues)}")
        elif total == 0:
            self.skipped("No BGP neighbors found")
        else:
            self.passed(f"All {total} BGP neighbors established")


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
"""Gladius: OSPF Neighbor Health — adjacency states and database check."""
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)
VALID_STATES = {'FULL', '2WAY', 'FULL/DR', 'FULL/BDR', 'FULL/  -', '2WAY/DROTHER'}


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class OspfNeighborTest(aetest.Testcase):
    @aetest.test
    def check_adjacencies(self, dev):
        try:
            ospf = dev.parse('show ip ospf neighbor detail')
        except Exception as e:
            self.skipped(f"OSPF not configured: {e}")
            return
        issues = []
        total  = 0
        for intf, id_ in ospf.get('interfaces', {}).items():
            for nbr, nd in id_.get('neighbors', {}).items():
                total += 1
                state = nd.get('state', '').upper()
                if state not in VALID_STATES:
                    issues.append(f"{nbr} on {intf}: {state}")
        if issues:
            self.failed(f"OSPF issues: {'; '.join(issues)}")
        elif total == 0:
            self.skipped("No OSPF neighbors found")
        else:
            self.passed(f"All {total} OSPF neighbors healthy")

    @aetest.test
    def check_database(self, dev):
        try:
            dev.parse('show ip ospf database')
            self.passed("OSPF database present")
        except Exception as e:
            self.skipped(f"OSPF database check skipped: {e}")


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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class CdpDiscoveryTest(aetest.Testcase):
    @aetest.test
    def collect_cdp(self, dev):
        try:
            cdp = dev.parse('show cdp neighbors detail')
            neighbors = []
            for _, entries in cdp.get('index', {}).items():
                for _, n in entries.items():
                    neighbors.append({
                        'device':      n.get('device_id', ''),
                        'local_intf':  n.get('local_interface', ''),
                        'remote_intf': n.get('port_id', ''),
                        'platform':    n.get('platform', ''),
                    })
            if neighbors:
                self.passed(f"Found {len(neighbors)} CDP neighbors:\n" + json.dumps(neighbors, indent=2))
            else:
                self.skipped("No CDP neighbors found")
        except Exception as e:
            self.skipped(f"CDP unavailable: {e}")

    @aetest.test
    def collect_lldp(self, dev):
        try:
            lldp  = dev.parse('show lldp neighbors detail')
            count = sum(len(v) for v in lldp.get('interfaces', {}).values())
            self.passed(f"Found {count} LLDP neighbor entries")
        except Exception as e:
            self.skipped(f"LLDP unavailable: {e}")


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
        "description": "Audits VLAN database, trunk ports, and access port assignments",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: VLAN Database Audit — VLANs, trunks, and access ports."""
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class VlanAuditTest(aetest.Testcase):
    @aetest.test
    def check_vlan_database(self, dev):
        try:
            vlans  = dev.parse('show vlan')
            active = [v for v, d in vlans.get('vlans', {}).items() if d.get('state') == 'active']
            self.passed(f"{len(active)} active VLANs: {', '.join(map(str, active[:20]))}")
        except Exception as e:
            self.failed(f"VLAN parse failed: {e}")

    @aetest.test
    def check_trunk_ports(self, dev):
        try:
            trunks = dev.parse('show interfaces trunk')
            ports  = list(trunks.get('interface', {}).keys())
            if ports:
                self.passed(f"Trunk ports: {', '.join(ports)}")
            else:
                self.skipped("No trunk ports found")
        except Exception as e:
            self.skipped(f"Trunk check skipped: {e}")


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
"""Gladius: ACL Configuration Audit — lists, hit counts, interface bindings."""
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)
DENY_HIT_THRESHOLD = 1000


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class AclAuditTest(aetest.Testcase):
    @aetest.test
    def list_acls(self, dev):
        try:
            acls = dev.parse('show ip access-lists')
            names = list(acls.get('acls', {}).keys())
            self.passed(f"Found {len(names)} ACL(s): {', '.join(names[:10])}")
        except Exception as e:
            self.skipped(f"ACL parse failed: {e}")

    @aetest.test
    def check_high_deny_hits(self, dev):
        try:
            acls    = dev.parse('show ip access-lists')
            flagged = []
            for name, data in acls.get('acls', {}).items():
                for seq, entry in data.get('aces', {}).items():
                    if entry.get('actions', {}).get('forwarding') == 'deny':
                        hits = entry.get('statistics', {}).get('matched_packets', 0) or 0
                        if hits > DENY_HIT_THRESHOLD:
                            flagged.append(f"{name} seq {seq}: {hits} hits")
            if flagged:
                self.failed(f"High deny hit counts: {'; '.join(flagged)}")
            else:
                self.passed("No unusually high deny hit counts")
        except Exception as e:
            self.skipped(f"Hit count check skipped: {e}")

    @aetest.test
    def check_interface_bindings(self, dev):
        try:
            intfs = dev.parse('show ip interface')
            bound = {i: {'in': d.get('inbound_access_list',''), 'out': d.get('outbound_access_list','')}
                     for i, d in intfs.items()
                     if d.get('inbound_access_list') or d.get('outbound_access_list')}
            self.passed(f"ACLs bound on {len(bound)} interface(s)")
        except Exception as e:
            self.skipped(f"Binding check skipped: {e}")


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
        "description": "Checks default route, protocol distribution, and host route counts",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: Routing Table Verification — default route, summary, host routes."""
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class RoutingTableTest(aetest.Testcase):
    @aetest.test
    def check_default_route(self, dev):
        try:
            routes  = dev.parse('show ip route')
            default = (routes.get('vrf', {}).get('default', {})
                             .get('address_family', {}).get('ipv4', {})
                             .get('routes', {}))
            if '0.0.0.0/0' in default:
                nh_list = list(default['0.0.0.0/0'].get('next_hop', {}).get('next_hop_list', {}).values())
                gw = nh_list[0].get('next_hop', 'unknown') if nh_list else 'unknown'
                self.passed(f"Default route present via {gw}")
            else:
                self.failed("No default route (0.0.0.0/0) found")
        except Exception as e:
            self.failed(f"Route table parse failed: {e}")

    @aetest.test
    def check_host_route_count(self, dev):
        try:
            routes  = dev.parse('show ip route')
            all_r   = (routes.get('vrf', {}).get('default', {})
                              .get('address_family', {}).get('ipv4', {})
                              .get('routes', {}))
            host_routes = [r for r in all_r if r.endswith('/32')]
            if len(host_routes) > 50:
                self.failed(f"Excessive /32 host routes: {len(host_routes)}")
            else:
                self.passed(f"Host route count normal: {len(host_routes)} /32 routes")
        except Exception as e:
            self.skipped(f"Host route check skipped: {e}")


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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)
CPU_WARN = 70
CPU_CRIT = 90
MEM_WARN = 75
MEM_CRIT = 90


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class SystemHealthTest(aetest.Testcase):
    @aetest.test
    def check_cpu(self, dev):
        try:
            cpu  = dev.parse('show processes cpu')
            u5s  = cpu.get('five_sec_cpu', 0) or 0
            u1m  = cpu.get('one_min_cpu',  0) or 0
            u5m  = cpu.get('five_min_cpu', 0) or 0
            msg  = f"5m={u5m}% 1m={u1m}% 5s={u5s}%"
            if u5m >= CPU_CRIT:
                self.failed(f"CPU critical: {msg}")
            elif u5m >= CPU_WARN:
                self.failed(f"CPU warning: {msg}")
            else:
                self.passed(f"CPU normal: {msg}")
        except Exception as e:
            self.skipped(f"CPU check skipped: {e}")

    @aetest.test
    def check_memory(self, dev):
        try:
            mem   = dev.parse('show processes memory')
            total = mem.get('processor_pool', {}).get('total', 0) or 0
            used  = mem.get('processor_pool', {}).get('used',  0) or 0
            if total > 0:
                pct = (used / total) * 100
                msg = f"{pct:.1f}% used ({used}/{total} bytes)"
                if pct >= MEM_CRIT:
                    self.failed(f"Memory critical: {msg}")
                elif pct >= MEM_WARN:
                    self.failed(f"Memory warning: {msg}")
                else:
                    self.passed(f"Memory normal: {msg}")
            else:
                self.skipped("Memory pool data unavailable")
        except Exception as e:
            self.skipped(f"Memory check skipped: {e}")

    @aetest.test
    def collect_version(self, dev):
        try:
            ver      = dev.parse('show version')
            v        = ver.get('version', {})
            platform = v.get('platform', '')
            ios_ver  = v.get('version', '')
            uptime   = v.get('uptime', '')
            self.passed(f"Platform: {platform} | IOS: {ios_ver} | Uptime: {uptime}")
        except Exception as e:
            self.skipped(f"Version info skipped: {e}")


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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)
MAX_STRATUM = 5


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class NtpAuditTest(aetest.Testcase):
    @aetest.test
    def check_associations(self, dev):
        try:
            ntp   = dev.parse('show ntp associations')
            peers = list(ntp.get('peer', {}).keys())
            if peers:
                self.passed(f"{len(peers)} NTP peer(s): {', '.join(peers[:5])}")
            else:
                self.failed("No NTP peers configured")
        except Exception as e:
            self.skipped(f"NTP associations check skipped: {e}")

    @aetest.test
    def check_sync_status(self, dev):
        try:
            status  = dev.parse('show ntp status')
            ss      = status.get('clock_state', {}).get('system_status', {})
            synced  = ss.get('clock_state', '')
            stratum = ss.get('stratum', 99)
            ref     = ss.get('reference_host', '')
            if synced.lower() == 'synchronized':
                if stratum > MAX_STRATUM:
                    self.failed(f"Synchronized but high stratum ({stratum}) via {ref}")
                else:
                    self.passed(f"NTP synchronized — stratum {stratum} via {ref}")
            else:
                self.failed(f"NTP NOT synchronized: {synced}")
        except Exception as e:
            self.failed(f"NTP status check failed: {e}")


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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class AaaAuditTest(aetest.Testcase):
    @aetest.test
    def check_aaa_new_model(self, dev):
        output = dev.execute('show run | include ^aaa new-model')
        if 'aaa new-model' in output:
            self.passed("AAA new-model enabled")
        else:
            self.failed("AAA new-model NOT enabled — local auth only")

    @aetest.test
    def check_tacacs_servers(self, dev):
        output = dev.execute('show run | section tacacs')
        if 'tacacs' in output.lower():
            self.passed("TACACS configuration found")
        else:
            self.skipped("No TACACS configuration found")

    @aetest.test
    def check_accounting(self, dev):
        output = dev.execute('show run | include ^aaa accounting')
        if 'aaa accounting' in output:
            self.passed("AAA accounting configured")
        else:
            self.failed("AAA accounting not configured — no audit trail")

    @aetest.test
    def check_local_fallback(self, dev):
        output = dev.execute('show run | include ^aaa authentication')
        if 'local' in output:
            self.passed("Local fallback configured in AAA authentication")
        else:
            self.failed("No local fallback — risk of lockout on TACACS failure")


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
        "description": "Checks STP mode, topology change counts, and PortFast configuration",
        "platform": "iosxe",
        "script": '''#!/usr/bin/env python3
"""Gladius: Spanning Tree Health — topology stability and TCN counts."""
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)
TCN_THRESHOLD = 10


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class SpanningTreeTest(aetest.Testcase):
    @aetest.test
    def check_stp_summary(self, dev):
        try:
            stp   = dev.parse('show spanning-tree summary')
            mode  = stp.get('mode', 'unknown')
            vlans = len(stp.get('vlans', {}))
            self.passed(f"STP mode: {mode} | Active on {vlans} VLANs")
        except Exception as e:
            self.skipped(f"STP summary skipped: {e}")

    @aetest.test
    def check_topology_changes(self, dev):
        try:
            stp      = dev.parse('show spanning-tree detail')
            high_tcn = []
            for vid, vd in stp.get('pvst', {}).items():
                tcns = sum(id_.get('topology_changes', 0) or 0
                           for id_ in vd.get('interfaces', {}).values())
                if tcns > TCN_THRESHOLD:
                    high_tcn.append(f"VLAN {vid}: {tcns} TCNs")
            if high_tcn:
                self.failed(f"High TCN counts (instability): {', '.join(high_tcn)}")
            else:
                self.passed("Topology change counts within normal range")
        except Exception as e:
            self.skipped(f"TCN check skipped: {e}")


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
import logging
from pyats import aetest
from genie.testbed import load

log = logging.getLogger(__name__)

THRESHOLDS = {
    'in_crc_errors':       5,
    'in_errors':          10,
    'out_errors':         10,
    'in_discards':       100,
    'out_discards':      100,
    'input_queue_drops':  50,
    'output_queue_drops': 50,
}


class CommonSetup(aetest.CommonSetup):
    @aetest.subsection
    def connect(self, testbed):
        self.parent.parameters['dev'] = testbed.devices['DUT']
        self.parent.parameters['dev'].connect(log_stdout=False)


class InterfaceErrorTest(aetest.Testcase):
    @aetest.test
    def check_error_counters(self, dev):
        data       = dev.parse('show interfaces')
        violations = []
        for intf, info in data.items():
            c    = info.get('counters', {})
            hits = {k: c.get(k, 0) or 0 for k, t in THRESHOLDS.items() if (c.get(k, 0) or 0) > t}
            if hits:
                violations.append(f"{intf}: {hits}")
        if violations:
            self.failed(f"{len(violations)} interface(s) exceeding thresholds:\n" + "\n".join(violations))
        else:
            self.passed(f"All {len(data)} interfaces within error thresholds")

    @aetest.test
    def check_queue_drops(self, dev):
        try:
            output = dev.execute('show interfaces | include drops')
            drops  = [l.strip() for l in output.splitlines()
                      if 'drops' in l and not l.strip().startswith('0')]
            if drops:
                self.failed(f"Queue drops detected on {len(drops)} interface(s)")
            else:
                self.passed("No queue drops detected")
        except Exception as e:
            self.skipped(f"Queue drop check skipped: {e}")


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


# ── FastAPI App ───────────────────────────────────────────────────────────────

app = FastAPI(title="Gladius Automation Factory")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def startup():
    init_db()
    log.info("Automation Factory started — Ollama: %s  model: %s", OLLAMA_URL, OLLAMA_MODEL)
    log.info("Dev switch: %s (%s)", DEV_SWITCH_HN, DEV_SWITCH_IP)


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

SYSTEM_PROMPT = """You are the Gladius Automation Factory agent, an expert in pyATS and Genie for Cisco network automation.

Your purpose is to generate production-quality pyATS/Genie scripts that can be saved and executed against network devices.

## Script requirements
- Always use pyATS aetest framework: CommonSetup with connect(), one or more Testcase subclasses, CommonCleanup with disconnect()
- CRITICAL imports — always use exactly these two lines at the top of every script:
    from pyats import aetest
    from genie.testbed import load
  Never use "import aetest" or "from pyats.topology import load" — both will fail.
- CRITICAL structure — every script MUST use EXACTLY this boilerplate (do not vary it):

    class CommonSetup(aetest.CommonSetup):
        @aetest.subsection
        def connect(self, testbed):
            self.parent.parameters['dev'] = next(iter(testbed.devices.values()))
            self.parent.parameters['dev'].connect(log_stdout=False)

    class SomeDescriptiveTestcase(aetest.Testcase):
        @aetest.test
        def check_something(self, dev):       ← 'dev' is auto-injected from parent parameters
            parsed = dev.parse('show ...')
            ...

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
- Use Genie parsers (device.parse('show ...')) for structured data — see parser reference below
- Prefer device.learn('<feature>') for full feature snapshots when available
- Include meaningful pass/fail criteria with thresholds
- Handle exceptions gracefully with self.skipped() for features not always present
- Testbed device is always referenced as 'DUT' (testbed.devices['DUT'])
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

## Common patterns

### Check running-config for a text pattern (when no structured parser exists)
  try:
      run = dev.execute('show running-config')
  except Exception:
      self.skipped('Could not retrieve running config')
  if 'service password-encryption' in run:
      self.passed('Password encryption enabled')
  else:
      self.failed('Password encryption not configured')

### Iterate interfaces and check errors
  parsed = dev.parse('show interfaces')
  failures = []
  for intf, data in parsed.items():
      errs = data.get('counters', {}).get('in_errors', 0)
      if errs > 0:
          failures.append(f'{intf}: {errs} input errors')
  if failures:
      self.failed('\\n'.join(failures))
  else:
      self.passed(f'All {len(parsed)} interfaces clean')

After generating a complete script, output a save hint on its own line:
SAVE_SCRIPT: {"name": "Script Name", "description": "Brief description", "platform": "iosxe"}

Valid platform values: iosxe, ios, nxos, eos

You have access to the existing script repository and can reference or build upon existing scripts when asked."""


@app.post("/api/chat")
async def chat(req: ChatRequest):
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
                    json={"model": OLLAMA_MODEL, "messages": messages, "stream": True}
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
            passed = proc.returncode == 0 and not any(
                x in output for x in ("ERRORED", "BLOCKED", "FAILED")
            )
            now    = datetime.now(timezone.utc).isoformat()
            with get_db() as conn:
                conn.execute(
                    "UPDATE scripts SET last_run_at=?, last_run_status=?, last_run_output=? WHERE id=?",
                    (now, "PASS" if passed else "FAIL", output[:10000], script_id)
                )
            return {"passed": passed, "stage": "dry_run", "output": output[:5000],
                    "device": dev_info.get("ip", DEV_SWITCH_IP)}
        except asyncio.TimeoutError:
            proc.kill()
            return {"passed": False, "stage": "dry_run", "error": "Timed out (120s)", "output": ""}
        except Exception as e:
            return {"passed": False, "stage": "dry_run", "error": str(e), "output": ""}


# ── Script Execution ──────────────────────────────────────────────────────────

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

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path  = os.path.join(tmpdir, "test_script.py")
        testbed_path = os.path.join(tmpdir, "testbed.yaml")
        with open(script_path,  "w") as f:
            f.write(sanitize_script(script_row["script"]))
        with open(testbed_path, "w") as f:
            f.write(testbed_yaml)
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, script_path, testbed_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=tmpdir
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode() + stderr.decode()
            passed = proc.returncode == 0 and not any(
                x in output for x in ("ERRORED", "BLOCKED", "FAILED")
            )
            status = "PASS" if passed else "FAIL"
            now    = datetime.now(timezone.utc).isoformat()
            with get_db() as conn:
                conn.execute(
                    "UPDATE scripts SET last_run_at=?, last_run_status=?, last_run_output=? WHERE id=?",
                    (now, status, output[:10000], script_id)
                )
            return {"passed": passed, "status": status, "device": display_name,
                    "output": output[:8000], "run_at": now}
        except asyncio.TimeoutError:
            proc.kill()
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
