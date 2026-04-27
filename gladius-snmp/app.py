#!/usr/bin/env python3
"""Gladius SNMP Monitor — persistent device registry with background polling."""

import os
import uuid
import json
import time
import asyncio
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pysnmp.hlapi import (
    getCmd, SnmpEngine, CommunityData, UsmUserData,
    UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,
    OctetString, TimeTicks,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("gladius-snmp")

DEVICES_FILE    = Path(os.getenv("DEVICES_FILE", "/data/devices.json"))
POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "60"))   # seconds between polls
GLADIUS_API_URL = os.getenv("GLADIUS_API_URL", "http://gladius-api:8080")
JIRA_AUTO_EVENTS = os.getenv("JIRA_AUTO_EVENTS", "true").lower() in ("true", "1", "yes")

# Event types that should auto-create Jira tickets
_JIRA_EVENT_TYPES = {"interface_down", "bgp_down", "ospf_down", "device_down"}
_JIRA_PRIORITY_MAP = {
    "device_down": "P2", "bgp_down": "P2", "ospf_down": "P2",
    "interface_down": "P3", "bgp_change": "P3", "ospf_change": "P3",
}

# ── OIDs polled for every device ───────────────────────────────────────────────
SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.2.1.0": "ifNumber",
    "1.3.6.1.2.1.47.1.1.1.1.11.1": "serialNum",
}

# ── In-memory stores ───────────────────────────────────────────────────────────
_devices:          dict[str, dict] = {}   # id → device config
_status:           dict[str, dict] = {}   # id → latest poll result
_last_alerted:     dict[str, str] = {}   # id → last status we alerted on (to avoid repeat alerts)
_iface_miss_count: dict[str, int] = {}   # "devid::iface::miss" → consecutive miss count

# ── Device persistence ─────────────────────────────────────────────────────────
def _load_devices():
    global _devices
    DEVICES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DEVICES_FILE.exists():
        try:
            _devices = json.loads(DEVICES_FILE.read_text())
            log.info("Loaded %d device(s) from %s", len(_devices), DEVICES_FILE)
        except Exception as e:
            log.warning("Failed to load devices: %s", e)
            _devices = {}
    else:
        _devices = {}


def _save_devices():
    try:
        DEVICES_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEVICES_FILE.write_text(json.dumps(_devices, indent=2))
    except Exception as e:
        log.error("Failed to save devices: %s", e)


# ── SNMP helpers ───────────────────────────────────────────────────────────────
def _auth_data(dev: dict):
    v = dev.get("version", "2c")
    if v in ("1", "2c"):
        return CommunityData(dev.get("community", "public"), mpModel=0 if v == "1" else 1)
    auth_proto = usmHMACSHAAuthProtocol if dev.get("auth_protocol", "SHA").upper() == "SHA" else usmHMACMD5AuthProtocol
    priv_proto  = usmAesCfb128Protocol  if dev.get("priv_protocol", "AES").upper() == "AES" else usmDESPrivProtocol
    ak, pk = dev.get("auth_key", ""), dev.get("priv_key", "")
    if ak and pk:
        return UsmUserData(dev["username"], ak, pk, authProtocol=auth_proto, privProtocol=priv_proto)
    if ak:
        return UsmUserData(dev["username"], ak, authProtocol=auth_proto)
    return UsmUserData(dev.get("username", ""))


def _fmt_timeticks(val) -> str:
    t = int(val)
    s = t // 100
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d}d {h:02d}:{m:02d}:{s:02d}"


def _poll_device_sync(dev: dict) -> dict:
    """Run a system SNMP GET for one device. Returns status dict. Blocking — run in thread."""
    host = dev["host"]
    port = dev.get("port", 161)
    t0   = time.monotonic()
    try:
        transport = UdpTransportTarget((host, port), timeout=5, retries=1)
        objects   = [ObjectType(ObjectIdentity(oid)) for oid in SYSTEM_OIDS]
        ei, es, _, varBinds = next(
            getCmd(SnmpEngine(), _auth_data(dev), transport, ContextData(), *objects)
        )
        if ei:
            raise RuntimeError(str(ei))
        if es:
            raise RuntimeError(es.prettyPrint())

        result = {}
        for var in varBinds:
            oid_str = str(var[0])
            label   = SYSTEM_OIDS.get(oid_str, oid_str)
            val     = var[1]
            if isinstance(val, TimeTicks):
                result[label] = _fmt_timeticks(val)
            else:
                try:
                    result[label] = val.prettyPrint()
                except Exception:
                    result[label] = str(val)

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return {
            "status":       "ok",
            "last_poll":    datetime.now(timezone.utc).isoformat(),
            "last_success": datetime.now(timezone.utc).isoformat(),
            "response_ms":  elapsed_ms,
            "error":        None,
            **result,
        }
    except Exception as e:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        log.warning("Poll failed for %s: %s", host, e)
        return {
            "status":      "error",
            "last_poll":   datetime.now(timezone.utc).isoformat(),
            "last_success": _status.get(dev["id"], {}).get("last_success"),
            "response_ms": elapsed_ms,
            "error":       str(e),
        }


# ── Protocol state tracking ───────────────────────────────────────────────────
_proto_state: dict[str, dict] = {}   # dev_id → {"interfaces": {...}, "bgp": {...}, "ospf": {...}}
_events: list[dict] = []             # recent events (capped at 200)
_MAX_EVENTS = 200

# BGP state codes → names (RFC 4271)
_BGP_STATES = {"1": "idle", "2": "connect", "3": "active", "4": "opensent", "5": "openconfirm", "6": "established"}
# OSPF neighbor states (RFC 2328)
_OSPF_STATES = {"1": "down", "2": "attempt", "3": "init", "4": "twoway", "5": "exchangestart",
                "6": "exchange", "7": "loading", "8": "full"}

def _add_event(dev: dict, event_type: str, severity: str, detail: str, extra: dict = None):
    """Append a protocol event and cap the list. Skip if device is muted."""
    if dev.get("muted"):
        log.debug("MUTED — skipping event [%s] %s %s: %s", severity, dev.get("name", dev["host"]), event_type, detail)
        return None
    evt = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": dev["id"],
        "device":    dev.get("sysName") or dev.get("name", dev["host"]),
        "host":      dev["host"],
        "group":     dev.get("group", ""),
        "type":      event_type,    # interface_down, interface_up, bgp_down, bgp_up, ospf_down, ospf_up, device_down, device_up
        "severity":  severity,      # critical, warning, info
        "detail":    detail,
        **(extra or {}),
    }
    _events.append(evt)
    if len(_events) > _MAX_EVENTS:
        _events[:] = _events[-_MAX_EVENTS:]
    log.info("EVENT [%s] %s %s: %s", severity.upper(), dev.get("name", dev["host"]), event_type, detail)

    # Auto-create Jira ticket for critical/warning events
    if JIRA_AUTO_EVENTS and event_type in _JIRA_EVENT_TYPES:
        try:
            _create_jira_for_event_sync(evt)
        except Exception as e:
            log.warning("Jira auto-ticket failed for %s: %s", event_type, e)

    # Auto-tshoot for interface_down events that have a Jira ticket
    if event_type == "interface_down" and evt.get("jira_key"):
        try:
            _trigger_auto_tshoot(evt)
        except Exception as e:
            log.warning("Auto-tshoot trigger failed for %s: %s", event_type, e)

    return evt


def _create_jira_for_event_sync(evt: dict):
    """POST to gladius-pyats Jira endpoint (via gladius-api proxy) to create a ticket."""
    device = evt.get("device") or evt.get("host", "Unknown")
    detail = evt.get("detail", "")
    evt_type = evt.get("type", "")
    label = evt_type.replace("_", " ").upper()
    priority = _JIRA_PRIORITY_MAP.get(evt_type, "P3")
    group = evt.get("group", "")

    summary = f"[{label}] {device} — {detail}"
    description = (
        f"SNMP Protocol Event (auto-generated)\n\n"
        f"Event: {label}\n"
        f"Device: {device}\n"
        f"Host: {evt.get('host', '')}\n"
        f"Detail: {detail}\n"
        f"Severity: {evt.get('severity', '')}\n"
        f"Timestamp: {evt.get('timestamp', '')}\n"
        + (f"Group: {group}\n" if group else "")
        + "\nAuto-generated by Gladius SNMP Monitor"
    )

    r = requests.post(
        f"{GLADIUS_API_URL}/api/automation/jira/create",
        json={"summary": summary, "description": description, "priority": priority,
              "labels": ["gladius", "snmp-event", "auto-generated"]},
        timeout=15,
    )
    data = r.json()
    if data.get("ok") and data.get("key"):
        evt["jira_key"] = data["key"]
        evt["jira_url"] = data.get("url", "")
        log.info("Jira ticket %s created for %s on %s", data["key"], evt_type, device)
    else:
        log.warning("Jira create returned: %s", data)


def _trigger_auto_tshoot(evt: dict):
    """Fire off auto-tshoot diagnostic request to gladius-api."""
    payload = {
        "device": evt.get("device") or evt.get("host", "Unknown"),
        "host": evt.get("host", ""),
        "detail": evt.get("detail", ""),
        "event_type": evt.get("type", ""),
        "jira_key": evt.get("jira_key", ""),
        "severity": evt.get("severity", ""),
        "group": evt.get("group", ""),
    }
    r = requests.post(
        f"{GLADIUS_API_URL}/api/tshoot/auto",
        json=payload,
        timeout=10,
    )
    data = r.json()
    if data.get("ok"):
        log.info("Auto-tshoot triggered for %s (%s), task_id=%s",
                 payload["device"], payload["event_type"], data.get("task_id"))
    else:
        log.warning("Auto-tshoot trigger returned: %s", data)


def _poll_protocol_state_sync(dev: dict) -> dict:
    """Walk interface oper status, BGP peer state, OSPF neighbor state. Returns parsed state dict."""
    host = dev["host"]
    port = dev.get("port", 161)
    state = {"interfaces": {}, "bgp": {}, "ospf": {}}
    try:
        from pysnmp.hlapi import nextCmd
        auth = _auth_data(dev)
        transport = UdpTransportTarget((host, port), timeout=3, retries=0)

        # Interface oper status: walk ifDescr + ifOperStatus + ifAdminStatus
        if_descr = {}
        if_oper = {}
        if_admin = {}
        for oid_base, store, max_rows in [
            ("1.3.6.1.2.1.2.2.1.2", if_descr, 200),   # ifDescr
            ("1.3.6.1.2.1.2.2.1.7", if_admin, 200),    # ifAdminStatus
            ("1.3.6.1.2.1.2.2.1.8", if_oper, 200),     # ifOperStatus
        ]:
            count = 0
            for ei, es, _, varBinds in nextCmd(SnmpEngine(), auth,
                UdpTransportTarget((host, port), timeout=3, retries=0),
                ContextData(), ObjectType(ObjectIdentity(oid_base)), lexicographicMode=False):
                if ei or es:
                    break
                for var in varBinds:
                    idx = str(var[0]).split(".")[-1]
                    store[idx] = var[1].prettyPrint()
                count += 1
                if count >= max_rows:
                    break

        for idx, descr in if_descr.items():
            admin = if_admin.get(idx, "1")
            oper = if_oper.get(idx, "1")
            # Track all interfaces (including admin-down) so we detect recovery
            # when admin-down → admin-up transitions occur
            state["interfaces"][descr] = {"oper": oper, "admin": admin, "idx": idx}

        # BGP peer state
        for ei, es, _, varBinds in nextCmd(SnmpEngine(), auth,
            UdpTransportTarget((host, port), timeout=3, retries=0),
            ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.15.3.1.2")), lexicographicMode=False):
            if ei or es:
                break
            for var in varBinds:
                peer_ip = ".".join(str(var[0]).split(".")[-4:])
                bgp_state = var[1].prettyPrint()
                state["bgp"][peer_ip] = bgp_state
            if len(state["bgp"]) >= 50:
                break

        # OSPF neighbor state
        for ei, es, _, varBinds in nextCmd(SnmpEngine(), auth,
            UdpTransportTarget((host, port), timeout=3, retries=0),
            ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.14.10.1.6")), lexicographicMode=False):
            if ei or es:
                break
            for var in varBinds:
                nbr_ip = ".".join(str(var[0]).split(".")[-4:])
                ospf_state = var[1].prettyPrint()
                state["ospf"][nbr_ip] = ospf_state
            if len(state["ospf"]) >= 50:
                break

    except Exception as e:
        log.debug("Protocol poll failed for %s: %s", host, e)
    return state


def _detect_events(dev: dict, old_state: dict, new_state: dict) -> list[dict]:
    """Compare old and new protocol state, return list of events."""
    events = []
    dev_id = dev["id"]

    # Interface changes
    # Track ALL interfaces (including admin-down) so we detect recovery when
    # an interface transitions admin-down → admin-up → oper-up.
    old_ifs = old_state.get("interfaces", {})
    new_ifs = new_state.get("interfaces", {})
    for iface, info in new_ifs.items():
        old_info = old_ifs.get(iface)
        if old_info:
            old_oper = old_info["oper"]
            new_oper = info["oper"]
            if old_oper != new_oper:
                if new_oper == "2":  # went down
                    events.append(_add_event(dev, "interface_down", "critical",
                        f"{iface} went DOWN", {"interface": iface}))
                elif new_oper == "1" and old_oper == "2":  # came up
                    events.append(_add_event(dev, "interface_up", "info",
                        f"{iface} came UP", {"interface": iface}))
            # Admin status changed (admin-down → admin-up with oper up = recovery)
            old_admin = old_info.get("admin", "1")
            new_admin = info.get("admin", "1")
            if old_admin == "2" and new_admin == "1" and new_oper == "1" and old_oper != "1":
                events.append(_add_event(dev, "interface_up", "info",
                    f"{iface} came UP", {"interface": iface}))
        else:
            # Interface appeared (wasn't tracked before)
            # Only alert for admin-up interfaces that are oper-down — skip if admin-down
            # (admin-down interfaces being oper-down is expected, not an event)
            if info["oper"] == "2" and info.get("admin") == "1":
                events.append(_add_event(dev, "interface_down", "critical",
                    f"{iface} went DOWN", {"interface": iface}))

    # Interfaces that disappeared (were in old, not in new)
    # SKIP virtual/internal interfaces — SNMP walks are inconsistent for these
    _IGNORE_DISAPPEAR = {"Null", "Loopback", "SR", "NVI", "VoIP-", "Vlan", "ucse", "BVI", "LISP"}
    for iface in old_ifs:
        if iface not in new_ifs and old_ifs[iface]["oper"] == "1":
            if any(iface.startswith(pfx) for pfx in _IGNORE_DISAPPEAR):
                continue
            # Track disappearance count — only alert after 2 consecutive misses
            miss_key = f"{dev_id}::{iface}::miss"
            _iface_miss_count[miss_key] = _iface_miss_count.get(miss_key, 0) + 1
            if _iface_miss_count[miss_key] < 2:
                continue
            events.append(_add_event(dev, "interface_down", "warning",
                f"{iface} no longer present", {"interface": iface}))

    # Clear miss counters for interfaces that are present
    for iface in new_ifs:
        miss_key = f"{dev_id}::{iface}::miss"
        _iface_miss_count.pop(miss_key, None)

    # BGP peer changes
    old_bgp = old_state.get("bgp", {})
    new_bgp = new_state.get("bgp", {})
    for peer, state_val in new_bgp.items():
        old_val = old_bgp.get(peer)
        if old_val and old_val != state_val:
            state_name = _BGP_STATES.get(state_val, state_val)
            old_name = _BGP_STATES.get(old_val, old_val)
            if state_val == "6":  # established
                events.append(_add_event(dev, "bgp_up", "info",
                    f"BGP peer {peer} → established (was {old_name})", {"peer": peer, "state": state_name}))
            elif old_val == "6":  # was established, now isn't
                events.append(_add_event(dev, "bgp_down", "critical",
                    f"BGP peer {peer} → {state_name} (was established)", {"peer": peer, "state": state_name}))
            else:
                # Suppress noise from non-established state transitions (idle↔active↔connect etc.)
                # These are just the BGP FSM negotiating — only log if neither state is established
                # and the transition is to a meaningfully worse state (idle=1 or down)
                # Suppress all non-established state transitions entirely
                # idle↔active↔connect cycling is normal BGP FSM negotiation noise
                pass
    # BGP peers that vanished
    for peer in old_bgp:
        if peer not in new_bgp and old_bgp[peer] == "6":
            events.append(_add_event(dev, "bgp_down", "critical",
                f"BGP peer {peer} disappeared (was established)", {"peer": peer}))
    # New BGP peers
    for peer in new_bgp:
        if peer not in old_bgp and new_bgp[peer] == "6":
            events.append(_add_event(dev, "bgp_up", "info",
                f"BGP peer {peer} newly established", {"peer": peer, "state": "established"}))

    # OSPF neighbor changes
    old_ospf = old_state.get("ospf", {})
    new_ospf = new_state.get("ospf", {})
    for nbr, state_val in new_ospf.items():
        old_val = old_ospf.get(nbr)
        if old_val and old_val != state_val:
            state_name = _OSPF_STATES.get(state_val, state_val)
            old_name = _OSPF_STATES.get(old_val, old_val)
            if state_val == "8":  # full
                events.append(_add_event(dev, "ospf_up", "info",
                    f"OSPF neighbor {nbr} → full (was {old_name})", {"neighbor": nbr, "state": state_name}))
            elif old_val == "8":  # was full
                events.append(_add_event(dev, "ospf_down", "critical",
                    f"OSPF neighbor {nbr} → {state_name} (was full)", {"neighbor": nbr, "state": state_name}))
            else:
                # Suppress all non-full state transitions entirely
                # OSPF FSM negotiation noise (init↔twoway↔exchange etc.)
                pass
    # OSPF neighbors that vanished
    for nbr in old_ospf:
        if nbr not in new_ospf and old_ospf[nbr] == "8":
            events.append(_add_event(dev, "ospf_down", "critical",
                f"OSPF neighbor {nbr} disappeared (was full)", {"neighbor": nbr}))
    # New OSPF neighbors
    for nbr in new_ospf:
        if nbr not in old_ospf and new_ospf[nbr] == "8":
            events.append(_add_event(dev, "ospf_up", "info",
                f"OSPF neighbor {nbr} newly full", {"neighbor": nbr, "state": "full"}))

    return [e for e in events if e is not None]


# ── Alert helpers ──────────────────────────────────────────────────────────────
_STATUS_SEVERITY = {"ok": 0, "unknown": 0, "warn": 1, "error": 2}

def _should_alert(dev_id: str, new_status: str) -> bool:
    """Return True if the status has degraded since our last alert."""
    prev = _last_alerted.get(dev_id, "ok")
    return _STATUS_SEVERITY.get(new_status, 0) > _STATUS_SEVERITY.get(prev, 0)


def _send_alert_sync(dev: dict, old_status: str, new_status: str, snmp_data: dict) -> None:
    """POST an alert to gladius-api. Runs in a thread."""
    payload = {
        "device_id":  dev["id"],
        "name":       dev.get("name", dev["host"]),
        "host":       dev["host"],
        "old_status": old_status,
        "new_status": new_status,
        "snmp_data":  snmp_data,
    }
    try:
        r = requests.post(f"{GLADIUS_API_URL}/api/snmp/alert", json=payload, timeout=10)
        log.info("Alert POSTed for %s: %s→%s (HTTP %d)", dev.get("name"), old_status, new_status, r.status_code)
    except Exception as e:
        log.warning("Failed to send alert for %s: %s", dev.get("name"), e)


# ── Background polling loop ────────────────────────────────────────────────────
async def _poll_all():
    while True:
        ids = list(_devices.keys())
        for dev_id in ids:
            dev = _devices.get(dev_id)
            if not dev:
                continue
            result = await asyncio.to_thread(_poll_device_sync, dev)
            old_status = _staleness(_status.get(dev_id, {})) if dev_id in _status else "unknown"
            _status[dev_id] = result
            new_status = _staleness(result)
            log.info("Polled %s (%s) → %s %dms",
                     dev.get("name", dev["host"]), dev["host"],
                     new_status, result["response_ms"])

            # Fire alert on status degradation
            if _should_alert(dev_id, new_status):
                _last_alerted[dev_id] = new_status
                asyncio.create_task(
                    asyncio.to_thread(_send_alert_sync, dev, old_status, new_status, dict(result))
                )
                # Device went down — generate event
                if new_status == "error":
                    _add_event(dev, "device_down", "critical", f"Device unreachable ({result.get('error', 'no response')})")
            elif new_status == "ok" and _last_alerted.get(dev_id, "ok") != "ok":
                _last_alerted[dev_id] = "ok"
                _add_event(dev, "device_up", "info", "Device recovered")
                log.info("Device %s recovered → alert state reset", dev.get("name", dev["host"]))

            # Protocol state polling (only if device is reachable)
            if new_status == "ok":
                try:
                    # Enrich dev with sysName for event labels
                    enriched = {**dev, "sysName": result.get("sysName", "")}
                    proto_state = await asyncio.to_thread(_poll_protocol_state_sync, enriched)
                    old_proto = _proto_state.get(dev_id)
                    if old_proto:
                        _detect_events(enriched, old_proto, proto_state)
                    _proto_state[dev_id] = proto_state
                except Exception as e:
                    log.debug("Protocol poll error for %s: %s", dev["host"], e)

        await asyncio.sleep(POLL_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_devices()
    # Kick off an immediate poll before the regular loop
    asyncio.create_task(_poll_all())
    yield


app = FastAPI(title="Gladius SNMP Monitor", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Request models ─────────────────────────────────────────────────────────────
class DeviceIn(BaseModel):
    name:          str = ""
    host:          str
    port:          int = 161
    version:       str = "2c"
    community:     str = "public"
    username:      str = ""
    auth_key:      str = ""
    priv_key:      str = ""
    auth_protocol: str = "SHA"
    priv_protocol: str = "AES"
    group:         str = ""
    muted:         bool = False


class DevicePatch(BaseModel):
    name:          str | None = None
    group:         str | None = None
    port:          int | None = None
    version:       str | None = None
    community:     str | None = None
    username:      str | None = None
    auth_key:      str | None = None
    priv_key:      str | None = None
    auth_protocol: str | None = None
    priv_protocol: str | None = None
    muted:         bool | None = None


# ── Helpers ────────────────────────────────────────────────────────────────────
def _device_with_status(dev_id: str) -> dict:
    dev = _devices[dev_id]
    st  = _status.get(dev_id, {"status": "unknown", "last_poll": None, "response_ms": None, "error": None})
    return {**dev, **st}


def _staleness(st: dict) -> str:
    """Downgrade ok→warn if last_poll is stale."""
    if st.get("status") != "ok":
        return st.get("status", "unknown")
    lp = st.get("last_poll")
    if not lp:
        return "unknown"
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(lp)).total_seconds()
        if age > POLL_INTERVAL * 3:
            return "warn"
    except Exception:
        pass
    return "ok"


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "gladius-snmp", "devices": len(_devices)}


@app.get("/devices")
def list_devices():
    result = []
    for dev_id in _devices:
        d = _device_with_status(dev_id)
        d["status"] = _staleness(_status.get(dev_id, {}))
        result.append(d)
    return {"devices": result}


@app.post("/devices", status_code=201)
async def add_device(body: DeviceIn):
    dev_id = str(uuid.uuid4())
    dev = {
        "id":            dev_id,
        "name":          body.name or body.host,
        "host":          body.host,
        "port":          body.port,
        "version":       body.version,
        "community":     body.community,
        "username":      body.username,
        "auth_key":      body.auth_key,
        "priv_key":      body.priv_key,
        "auth_protocol": body.auth_protocol,
        "priv_protocol": body.priv_protocol,
        "group":         body.group,
        "muted":         body.muted,
        "added":         datetime.now(timezone.utc).isoformat(),
    }
    _devices[dev_id] = dev
    _save_devices()
    # Immediate poll in background
    asyncio.create_task(asyncio.to_thread(_poll_device_sync, dev))
    return _device_with_status(dev_id)


@app.delete("/devices/{dev_id}", status_code=204)
def delete_device(dev_id: str):
    if dev_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    _devices.pop(dev_id)
    _status.pop(dev_id, None)
    _save_devices()


@app.post("/devices/mute-all")
async def mute_all_devices(request: Request):
    body = await request.json()
    muted = body.get("muted", True)
    for dev_id in _devices:
        _devices[dev_id]["muted"] = muted
    _save_devices()
    return {"ok": True, "muted": muted, "count": len(_devices)}


@app.patch("/devices/{dev_id}")
def patch_device(dev_id: str, body: DevicePatch):
    if dev_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    updates = body.model_dump(exclude_none=True)
    _devices[dev_id].update(updates)
    _save_devices()
    return _device_with_status(dev_id)


@app.post("/devices/{dev_id}/poll")
async def poll_device(dev_id: str):
    if dev_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    result = await asyncio.to_thread(_poll_device_sync, _devices[dev_id])
    _status[dev_id] = result
    d = _device_with_status(dev_id)
    d["status"] = _staleness(result)
    return d


# ── Ad-hoc poll (no registry required) ────────────────────────────────────────
PROFILES = {
    "system":         {"mode": "get",  "oids": list(SYSTEM_OIDS.keys())},
    "interfaces":     {"mode": "walk", "oids": ["1.3.6.1.2.1.2.2"]},
    "if_counters":    {"mode": "walk", "oids": ["1.3.6.1.2.1.2.2.1.10", "1.3.6.1.2.1.2.2.1.16"]},
    "ip_addresses":   {"mode": "walk", "oids": ["1.3.6.1.2.1.4.20"]},
    "arp":            {"mode": "walk", "oids": ["1.3.6.1.2.1.4.22"]},
    "bgp":            {"mode": "walk", "oids": ["1.3.6.1.2.1.15.3"]},
    "ospf_neighbors": {"mode": "walk", "oids": ["1.3.6.1.2.1.14.10.1"]},
    "cisco_cpu":      {"mode": "get",  "oids": ["1.3.6.1.4.1.9.2.1.57.0", "1.3.6.1.4.1.9.2.1.58.0"]},
    "cisco_memory":   {"mode": "walk", "oids": ["1.3.6.1.4.1.9.9.48.1.1.1"]},
}

OID_LABELS = {
    "1.3.6.1.2.1.1.1":  "sysDescr",      "1.3.6.1.2.1.1.3":  "sysUpTime",
    "1.3.6.1.2.1.1.4":  "sysContact",    "1.3.6.1.2.1.1.5":  "sysName",
    "1.3.6.1.2.1.1.6":  "sysLocation",   "1.3.6.1.2.1.1.7":  "sysServices",
    "1.3.6.1.2.1.2.2.1.1":  "ifIndex",   "1.3.6.1.2.1.2.2.1.2":  "ifDescr",
    "1.3.6.1.2.1.2.2.1.5":  "ifSpeed",   "1.3.6.1.2.1.2.2.1.7":  "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8":  "ifOperStatus", "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.4.20.1.1": "ipAdEntAddr",  "1.3.6.1.2.1.4.20.1.3": "ipAdEntNetMask",
    "1.3.6.1.2.1.4.22.1.2": "arpPhysAddr",  "1.3.6.1.2.1.4.22.1.3": "arpNetAddr",
    "1.3.6.1.2.1.15.3.1.2": "bgpPeerState", "1.3.6.1.2.1.15.3.1.9": "bgpPeerRemoteAs",
    "1.3.6.1.2.1.14.10.1.3": "ospfNbrRtrId", "1.3.6.1.2.1.14.10.1.6": "ospfNbrState",
    "1.3.6.1.4.1.9.2.1.57": "ciscoCpu1min", "1.3.6.1.4.1.9.2.1.58": "ciscoCpu5min",
    "1.3.6.1.4.1.9.9.48.1.1.1.2": "ciscoMemName",
    "1.3.6.1.4.1.9.9.48.1.1.1.5": "ciscoMemUsed",
    "1.3.6.1.4.1.9.9.48.1.1.1.6": "ciscoMemFree",
}

def _label(oid_str: str) -> str:
    for base, name in OID_LABELS.items():
        if oid_str == base + ".0" or oid_str.startswith(base + "."):
            suffix = oid_str[len(base):]
            return name + (suffix if suffix != ".0" else "")
    return oid_str

def _adhoc_poll_sync(host: str, port: int, version: str, community: str,
                     username: str, auth_key: str, priv_key: str,
                     auth_protocol: str, priv_protocol: str,
                     profile: str, max_rows: int) -> dict:
    dev = {"host": host, "port": port, "version": version, "community": community,
           "username": username, "auth_key": auth_key, "priv_key": priv_key,
           "auth_protocol": auth_protocol, "priv_protocol": priv_protocol}
    p = PROFILES.get(profile)
    if not p:
        return {"error": f"Unknown profile: {profile}"}
    t0 = time.monotonic()
    results = []
    try:
        if p["mode"] == "get":
            transport = UdpTransportTarget((host, port), timeout=5, retries=1)
            objects = [ObjectType(ObjectIdentity(o)) for o in p["oids"]]
            ei, es, _, varBinds = next(getCmd(SnmpEngine(), _auth_data(dev), transport, ContextData(), *objects))
            if ei: raise RuntimeError(str(ei))
            for var in varBinds:
                oid_str = str(var[0])
                val = var[1]
                results.append({"oid": oid_str, "label": _label(oid_str),
                                 "value": _fmt_timeticks(val) if isinstance(val, TimeTicks) else val.prettyPrint()})
        else:
            from pysnmp.hlapi import nextCmd
            for oid in p["oids"]:
                transport = UdpTransportTarget((host, port), timeout=5, retries=1)
                for ei, es, _, varBinds in nextCmd(SnmpEngine(), _auth_data(dev), transport,
                                                    ContextData(), ObjectType(ObjectIdentity(oid)),
                                                    lexicographicMode=False):
                    if ei or es: break
                    for var in varBinds:
                        oid_str = str(var[0])
                        val = var[1]
                        results.append({"oid": oid_str, "label": _label(oid_str),
                                         "value": _fmt_timeticks(val) if isinstance(val, TimeTicks) else val.prettyPrint()})
                    if len(results) >= max_rows: break
    except Exception as e:
        return {"error": str(e), "elapsed_ms": int((time.monotonic() - t0) * 1000)}
    return {"host": host, "profile": profile, "results": results,
            "count": len(results), "elapsed_ms": int((time.monotonic() - t0) * 1000)}


class AdHocPollRequest(BaseModel):
    host:          str
    port:          int    = 161
    version:       str    = "2c"
    community:     str    = "public"
    username:      str    = ""
    auth_key:      str    = ""
    priv_key:      str    = ""
    auth_protocol: str    = "SHA"
    priv_protocol: str    = "AES"
    profile:       str    = "system"
    max_rows:      int    = 200


@app.get("/events")
def get_events(
    limit: int = 100,
    event_type: str | None = None,
    severity: str | None = None,
    device_id: str | None = None,
):
    """Return recent protocol / device events, newest first."""
    filtered = _events
    if event_type:
        filtered = [e for e in filtered if e["type"] == event_type]
    if severity:
        filtered = [e for e in filtered if e["severity"] == severity]
    if device_id:
        filtered = [e for e in filtered if e["device_id"] == device_id]
    return {"events": list(reversed(filtered[-limit:]))}


@app.delete("/events", status_code=204)
def clear_events():
    """Clear all stored events."""
    _events.clear()
    return


@app.get("/proto_state")
def get_proto_state(device_id: str | None = None):
    """Return current protocol state (interfaces, BGP, OSPF) per device."""
    if device_id:
        state = _proto_state.get(device_id)
        if state is None:
            raise HTTPException(status_code=404, detail="No protocol state for device")
        return {device_id: state}
    return _proto_state


@app.post("/poll")
async def adhoc_poll(req: AdHocPollRequest):
    result = await asyncio.to_thread(
        _adhoc_poll_sync,
        req.host, req.port, req.version, req.community,
        req.username, req.auth_key, req.priv_key,
        req.auth_protocol, req.priv_protocol,
        req.profile, req.max_rows,
    )
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result
