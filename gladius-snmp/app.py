#!/usr/bin/env python3
"""Gladius SNMP Monitor — persistent device registry with background polling."""

import os
import uuid
import json
import time
import hmac
import shutil
import hashlib
import asyncio
import logging
import tempfile
import threading
import requests
from pathlib import Path
from urllib.parse import quote
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pysnmp.hlapi import (
    getCmd, nextCmd, bulkCmd, SnmpEngine, CommunityData, UsmUserData,
    UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,
    OctetString, TimeTicks,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("gladius-snmp")

DEVICES_FILE      = Path(os.getenv("DEVICES_FILE", "/data/devices.json"))
POLL_INTERVAL     = int(os.getenv("POLL_INTERVAL", "60"))   # seconds between polls
GLADIUS_API_URL   = os.getenv("GLADIUS_API_URL", "http://gladius-api:8080")
GLADIUS_API_TOKEN = os.getenv("GLADIUS_API_TOKEN")
JIRA_AUTO_EVENTS = os.getenv("JIRA_AUTO_EVENTS", "true").lower() in ("true", "1", "yes")
ALERT_STATE_FILE  = Path(os.getenv("ALERT_STATE_FILE", str(DEVICES_FILE.parent / "alert_state.json")))
JIRA_DEDUPE_SECS  = float(os.getenv("JIRA_DEDUPE_HOURS", "24")) * 3600   # reuse an open auto-ticket this long
AUTO_TSHOOT_COOLDOWN = int(os.getenv("AUTO_TSHOOT_COOLDOWN", "1800"))     # min seconds between auto-tshoots per device

_GLADIUS_API_HEADERS = {"Authorization": f"Bearer {GLADIUS_API_TOKEN}"} if GLADIUS_API_TOKEN else {}

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

# ── Device persistence ─────────────────────────────────────────────────────────
# Set when devices.json exists but neither it nor its .bak could be parsed.
# While set, every save is refused so the unreadable (possibly recoverable)
# file is never overwritten with an empty registry.
_registry_error: str | None = None


def _atomic_write_text(path: Path, text: str) -> None:
    """Write via a temp file in the same directory + os.replace, so a crash
    mid-write never leaves a truncated file. The file is created 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _devices_backup_path() -> Path:
    return DEVICES_FILE.with_name(DEVICES_FILE.name + ".bak")


def _read_devices_file(path: Path) -> dict:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object of id → device")
    return data


def _load_devices():
    global _devices, _registry_error
    DEVICES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _registry_error = None
    if not DEVICES_FILE.exists():
        _devices = {}
        return
    try:
        _devices = _read_devices_file(DEVICES_FILE)
        log.info("Loaded %d device(s) from %s", len(_devices), DEVICES_FILE)
        return
    except Exception as e:
        load_err = e

    # Keep a copy of the unreadable file for the operator before anything else
    corrupt = DEVICES_FILE.with_name(f"{DEVICES_FILE.name}.corrupt-{int(time.time())}")
    try:
        shutil.copy2(DEVICES_FILE, corrupt)
    except Exception as e:
        log.error("Could not copy unreadable %s aside: %s", DEVICES_FILE, e)
        corrupt = None

    bak = _devices_backup_path()
    try:
        _devices = _read_devices_file(bak)
        log.error("Failed to load %s (%s) — copy kept at %s; restored %d device(s) from %s",
                  DEVICES_FILE, load_err, corrupt, len(_devices), bak)
    except Exception as e:
        _devices = {}
        _registry_error = (f"{DEVICES_FILE} is unreadable ({load_err}) and no usable backup "
                           f"({e}); registry is read-only until the file is repaired")
        log.error("%s — copy kept at %s", _registry_error, corrupt)


def _save_devices():
    if _registry_error:
        log.error("Refusing to save devices: %s", _registry_error)
        return
    try:
        # Keep the previous version as .bak, but only if it is itself valid
        if DEVICES_FILE.exists():
            try:
                prev = DEVICES_FILE.read_text()
                if not isinstance(json.loads(prev), dict):
                    raise ValueError("not a JSON object")
                _atomic_write_text(_devices_backup_path(), prev)
            except Exception as e:
                log.warning("Not backing up %s: %s", DEVICES_FILE, e)
        _atomic_write_text(DEVICES_FILE, json.dumps(_devices, indent=2))
    except Exception as e:
        log.error("Failed to save devices: %s", e)


def _require_writable_registry():
    """Endpoint guard: refuse registry changes while devices.json is unreadable."""
    if _registry_error:
        raise HTTPException(status_code=503, detail="Device registry is read-only: devices.json could not be loaded")


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


# SnmpEngine is not thread-safe, so engines are reused per worker thread rather
# than built for every request. pysnmp's hlapi caches SNMPv3 users in an engine
# by user name, so each distinct v3 credential set gets its own engine —
# otherwise a changed key, or two devices sharing a user name with different
# keys, would silently keep using the first keys seen. v1/v2c communities are
# keyed by community already and share one engine.
_engine_tls = threading.local()
_MAX_ENGINES_PER_THREAD = 32
_BULK_REPETITIONS = 25


def _engine_key(dev: dict) -> str:
    if dev.get("version", "2c") in ("1", "2c"):
        return "community"
    creds = [dev.get(k, "") for k in ("username", "auth_key", "priv_key", "auth_protocol", "priv_protocol")]
    return hashlib.sha256(json.dumps(creds).encode()).hexdigest()


def _snmp_engine(dev: dict) -> SnmpEngine:
    engines = getattr(_engine_tls, "engines", None)
    if engines is None:
        engines = _engine_tls.engines = {}
    key = _engine_key(dev)
    engine = engines.get(key)
    if engine is None:
        if len(engines) >= _MAX_ENGINES_PER_THREAD:
            for old in engines.values():
                try:
                    if old.transportDispatcher:
                        old.transportDispatcher.closeDispatcher()
                except Exception:
                    pass
            engines.clear()
        engine = engines[key] = SnmpEngine()
    return engine


def _snmp_walk(dev: dict, oid_base: str, max_rows: int, timeout: int, retries: int, errors: list | None = None):
    """Walk one subtree (GETBULK for v2c/v3, GETNEXT for v1). Blocking.
    Returns [(oid_str, value), ...] or None if the walk failed."""
    target = UdpTransportTarget((dev["host"], dev.get("port", 161)), timeout=timeout, retries=retries)
    obj = ObjectType(ObjectIdentity(oid_base))
    if dev.get("version", "2c") == "1":
        responses = nextCmd(_snmp_engine(dev), _auth_data(dev), target, ContextData(), obj,
                            lexicographicMode=False)
    else:
        responses = bulkCmd(_snmp_engine(dev), _auth_data(dev), target, ContextData(),
                            0, min(_BULK_REPETITIONS, max_rows), obj, lexicographicMode=False)
    return _collect_walk(oid_base, responses, max_rows, errors)


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
            getCmd(_snmp_engine(dev), _auth_data(dev), transport, ContextData(), *objects)
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
_proto_state: dict[str, dict] = {}   # dev_id → confirmed {"interfaces": {...}, "bgp": {...}, "ospf": {...}} (None = never walked)
_events: list[dict] = []             # recent events (capped at 200)
_MAX_EVENTS = 200

# BGP state codes → names (RFC 4271)
_BGP_STATES = {"1": "idle", "2": "connect", "3": "active", "4": "opensent", "5": "openconfirm", "6": "established"}
# OSPF neighbor states (RFC 2328)
_OSPF_STATES = {"1": "down", "2": "attempt", "3": "init", "4": "twoway", "5": "exchangestart",
                "6": "exchange", "7": "loading", "8": "full"}

def _add_event(dev: dict, event_type: str, severity: str, detail: str, extra: dict = None):
    """Append a protocol event and cap the list. Skip if device is muted.

    Must be called on the event loop. Never blocks: Jira / auto-tshoot HTTP
    calls are queued for _side_effect_worker, which fills in jira_key/jira_url
    on the stored event once the ticket exists.
    """
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

    # Auto-create Jira ticket (and auto-tshoot for interface_down) off the event loop
    if JIRA_AUTO_EVENTS and event_type in _JIRA_EVENT_TYPES:
        _enqueue_side_effects(evt)

    return evt


# ── Event side effects (Jira / auto-tshoot) ───────────────────────────────────
_side_effects: asyncio.Queue | None = None   # created in lifespan
_SIDE_EFFECT_QUEUE_MAX = 500


def _enqueue_side_effects(evt: dict) -> None:
    if _side_effects is None:
        log.debug("Side-effect worker not running — skipping Jira for %s", evt["type"])
        return
    try:
        _side_effects.put_nowait(evt)
    except asyncio.QueueFull:
        log.warning("Side-effect queue full — dropping Jira/tshoot for %s %s", evt["type"], evt["detail"])


async def _side_effect_worker():
    """Single consumer: runs the blocking HTTP calls for each event in a thread,
    one event at a time, so an event storm can never stall the event loop."""
    while True:
        evt = await _side_effects.get()
        try:
            await asyncio.to_thread(_process_event_side_effects, evt)
        except Exception as e:
            log.warning("Side effects failed for %s: %s", evt.get("type"), e)
        finally:
            _side_effects.task_done()


def _process_event_side_effects(evt: dict) -> None:
    """Blocking — runs in a worker thread."""
    try:
        _create_jira_for_event_sync(evt)
    except Exception as e:
        log.warning("Jira auto-ticket failed for %s: %s", evt["type"], e)

    # Auto-tshoot for interface_down events that opened a new Jira ticket,
    # at most once per device per AUTO_TSHOOT_COOLDOWN
    if evt["type"] == "interface_down" and evt.get("jira_key") and not evt.get("jira_deduped") \
            and _tshoot_allowed(evt["device_id"]):
        try:
            _trigger_auto_tshoot(evt)
        except Exception as e:
            log.warning("Auto-tshoot trigger failed for %s: %s", evt["type"], e)


# ── Persistent alert state (survives restarts) ────────────────────────────────
# _last_alerted, open auto-tickets and auto-tshoot times are kept in
# ALERT_STATE_FILE so a restart neither re-alerts on devices that were already
# down nor opens duplicate Jira tickets / LLM investigations.
_alert_lock = threading.RLock()
_open_tickets: dict[str, dict] = {}   # "dev_id|event_type|subject" → {"key", "url", "created"}
_tshoot_last:  dict[str, float] = {}  # dev_id → epoch of last auto-tshoot
_JIRA_DONE_STATUSES = {"done", "closed", "resolved", "cancelled", "canceled", "won't do", "won't fix"}


def _load_alert_state():
    try:
        data = json.loads(ALERT_STATE_FILE.read_text())
        with _alert_lock:
            _last_alerted.update({k: v for k, v in data.get("last_alerted", {}).items() if isinstance(v, str)})
            _open_tickets.update({k: v for k, v in data.get("open_tickets", {}).items()
                                  if isinstance(v, dict) and v.get("key")})
            _tshoot_last.update({k: float(v) for k, v in data.get("tshoot_last", {}).items()})
        log.info("Loaded alert state: %d device(s), %d open ticket(s)", len(_last_alerted), len(_open_tickets))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("Ignoring unreadable %s (%s) — first poll of each device will be a baseline",
                    ALERT_STATE_FILE, e)


def _save_alert_state():
    with _alert_lock:
        now = time.time()
        for k in [k for k, t in _open_tickets.items() if now - t.get("created", 0) > JIRA_DEDUPE_SECS]:
            _open_tickets.pop(k)
        snapshot = json.dumps({"last_alerted": _last_alerted, "open_tickets": _open_tickets,
                               "tshoot_last": _tshoot_last}, indent=2)
        try:
            _atomic_write_text(ALERT_STATE_FILE, snapshot)
        except Exception as e:
            log.error("Failed to save alert state: %s", e)


def _ticket_subject(evt: dict) -> str:
    """Dedupe key: one open auto-ticket per (device, event type, interface/peer/neighbour)."""
    sub = evt.get("interface") or evt.get("peer") or evt.get("neighbor") or ""
    return f"{evt['device_id']}|{evt['type']}|{sub}"


def _jira_ticket_is_open(key: str) -> bool:
    """Ask Jira (via gladius-api) whether an issue is still open. Unknown → open,
    so a Jira hiccup errs on the side of commenting rather than duplicating."""
    try:
        r = requests.get(f"{GLADIUS_API_URL}/api/automation/jira/issue/{quote(key, safe='')}",
                         headers=_GLADIUS_API_HEADERS, timeout=10)
    except Exception as e:
        log.warning("Jira status check for %s failed: %s", key, e)
        return True
    if r.status_code == 404:
        return False
    data = _response_json(r, f"Jira status {key}")
    return data is None or str(data.get("status", "")).lower() not in _JIRA_DONE_STATUSES


def _open_ticket_for(subject: str) -> dict | None:
    with _alert_lock:
        t = _open_tickets.get(subject)
    if not t:
        return None
    if time.time() - t.get("created", 0) > JIRA_DEDUPE_SECS or not _jira_ticket_is_open(t["key"]):
        with _alert_lock:
            _open_tickets.pop(subject, None)
        _save_alert_state()
        return None
    return t


def _tshoot_allowed(dev_id: str) -> bool:
    now = time.time()
    with _alert_lock:
        if now - _tshoot_last.get(dev_id, 0) < AUTO_TSHOOT_COOLDOWN:
            log.info("Auto-tshoot for device %s suppressed (cooldown %ds)", dev_id, AUTO_TSHOOT_COOLDOWN)
            return False
        _tshoot_last[dev_id] = now
    _save_alert_state()
    return True


def _response_json(r, what: str) -> dict | None:
    """Return the JSON body of a successful response, else log and return None."""
    if not r.ok:
        log.warning("%s returned HTTP %d: %s", what, r.status_code, r.text[:200])
        return None
    try:
        data = r.json()
    except ValueError:
        log.warning("%s returned non-JSON (%s): %s", what, r.headers.get("content-type"), r.text[:200])
        return None
    return data if isinstance(data, dict) else None


def _create_jira_for_event_sync(evt: dict):
    """POST to gladius-pyats Jira endpoint (via gladius-api proxy) to create a ticket.
    If an auto-ticket for the same subject is still open, comment on it instead."""
    device = evt.get("device") or evt.get("host", "Unknown")
    detail = evt.get("detail", "")
    evt_type = evt.get("type", "")

    subject = _ticket_subject(evt)
    existing = _open_ticket_for(subject)
    if existing:
        evt["jira_key"] = existing["key"]
        evt["jira_url"] = existing.get("url", "")
        evt["jira_deduped"] = True
        r = requests.post(
            f"{GLADIUS_API_URL}/api/automation/jira/comment",
            json={"issue_key": existing["key"],
                  "comment": f"Event recurred at {evt.get('timestamp', '')}: {detail}\n"
                             f"(Gladius SNMP Monitor — no new ticket raised while this one is open)"},
            headers=_GLADIUS_API_HEADERS,
            timeout=15,
        )
        if _response_json(r, "Jira comment") is not None:
            log.info("Jira ticket %s still open — commented recurrence of %s on %s", existing["key"], evt_type, device)
        return

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
        headers=_GLADIUS_API_HEADERS,
        timeout=15,
    )
    data = _response_json(r, "Jira create")
    if data and data.get("ok") and data.get("key"):
        evt["jira_key"] = data["key"]
        evt["jira_url"] = data.get("url", "")
        with _alert_lock:
            _open_tickets[subject] = {"key": data["key"], "url": evt["jira_url"], "created": time.time()}
        _save_alert_state()
        log.info("Jira ticket %s created for %s on %s", data["key"], evt_type, device)
    elif data is not None:
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
        headers=_GLADIUS_API_HEADERS,
        timeout=10,
    )
    data = _response_json(r, "Auto-tshoot")
    if data and data.get("ok"):
        log.info("Auto-tshoot triggered for %s (%s), task_id=%s",
                 payload["device"], payload["event_type"], data.get("task_id"))
    elif data is not None:
        log.warning("Auto-tshoot trigger returned: %s", data)


def _ospf_nbr_key(oid_str: str) -> str:
    """Neighbour key from an ospfNbrTable OID.

    Rows are indexed by ospfNbrIpAddr (4 sub-ids) followed by
    ospfNbrAddressLessIndex (1 sub-id, 0 for numbered neighbours), so the IP
    is sub-ids [-5:-1]. Address-less neighbours all share 0.0.0.0, so their
    interface index is appended to keep them distinct.
    """
    parts = oid_str.split(".")
    ip = ".".join(parts[-5:-1])
    return ip if parts[-1] == "0" else f"{ip}/{parts[-1]}"


# Value types an agent returns in place of data (end of a v1 walk, endOfMibView
# padding at the end of a GETBULK, missing objects). Matched by class name so
# this works across pysnmp versions.
_SNMP_NON_VALUES = {"Null", "NoSuchObject", "NoSuchInstance", "EndOfMibView"}


def _collect_walk(base: str, responses, max_rows: int, errors: list | None = None):
    """Consume an hlapi walk iterator of (errInd, errStatus, errIdx, varBinds).

    Returns [(oid_str, value), ...] for rows inside `base`, or None if the walk
    hit an error — a failed walk must never look like an empty table. The
    error text is appended to `errors` if given.
    """
    rows = []
    prefix = base + "."
    for ei, es, _, var_binds in responses:
        if ei or es:
            if errors is not None:
                errors.append(str(ei) if ei else es.prettyPrint())
            return None
        for name, val in var_binds:
            oid_str = str(name)
            if not oid_str.startswith(prefix) or type(val).__name__ in _SNMP_NON_VALUES:
                continue
            rows.append((oid_str, val))
        if len(rows) >= max_rows:
            break
    return rows


_IF_DESCR, _IF_ADMIN, _IF_OPER = "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.7", "1.3.6.1.2.1.2.2.1.8"
_BGP_PEER_STATE = "1.3.6.1.2.1.15.3.1.2"
_OSPF_NBR_STATE = "1.3.6.1.2.1.14.10.1.6"


def _build_interfaces(descr_rows, admin_rows, oper_rows) -> dict:
    """ifDescr/ifAdminStatus/ifOperStatus walk rows → {descr: {oper, admin, idx}}."""
    def by_idx(rows):
        return {oid.split(".")[-1]: val.prettyPrint() for oid, val in rows}
    if_admin, if_oper = by_idx(admin_rows), by_idx(oper_rows)
    # Track all interfaces (including admin-down) so we detect recovery
    # when admin-down → admin-up transitions occur
    return {descr: {"oper": if_oper.get(idx, "1"), "admin": if_admin.get(idx, "1"), "idx": idx}
            for idx, descr in by_idx(descr_rows).items()}


def _poll_protocol_state_sync(dev: dict) -> dict:
    """Walk interface oper status, BGP peer state, OSPF neighbor state. Returns parsed state dict.

    A table whose walk failed is None (state unknown), never an empty dict, so
    a dropped packet is not mistaken for "every peer disappeared".
    """
    host = dev["host"]
    state = {"interfaces": None, "bgp": None, "ospf": None}
    try:
        def walk(oid_base: str, max_rows: int):
            return _snmp_walk(dev, oid_base, max_rows, timeout=3, retries=1)

        # Interface oper status: walk ifDescr + ifAdminStatus + ifOperStatus.
        # Stop at the first failed walk — the device has stopped answering.
        cols = []
        for oid_base in (_IF_DESCR, _IF_ADMIN, _IF_OPER):
            rows = walk(oid_base, 200)
            if rows is None:
                return state
            cols.append(rows)
        state["interfaces"] = _build_interfaces(*cols)

        # BGP peer state
        rows = walk(_BGP_PEER_STATE, 50)
        if rows is None:
            return state
        state["bgp"] = {".".join(oid.split(".")[-4:]): val.prettyPrint() for oid, val in rows}

        # OSPF neighbor state
        rows = walk(_OSPF_NBR_STATE, 50)
        if rows is None:
            return state
        state["ospf"] = {_ospf_nbr_key(oid): val.prettyPrint() for oid, val in rows}

    except Exception as e:
        log.debug("Protocol poll failed for %s: %s", host, e)
    return state


# ── Protocol state diffing ────────────────────────────────────────────────────
# A down transition must be seen on this many consecutive polls before it is
# reported (and ticketed). Recoveries are reported immediately.
HOLD_DOWN_POLLS = max(1, int(os.getenv("SNMP_HOLD_DOWN_POLLS", "2")))

# ifOperStatus (RFC 2863). Any of these with admin up counts as down.
_IF_OPER_STATES = {"1": "up", "2": "down", "3": "testing", "4": "unknown",
                   "5": "dormant", "6": "notPresent", "7": "lowerLayerDown"}
_IF_OPER_DOWN = {"2", "5", "6", "7"}

# SKIP virtual/internal interfaces when they vanish — SNMP walks are inconsistent for these
_IGNORE_DISAPPEAR = ("Null", "Loopback", "SR", "NVI", "VoIP-", "Vlan", "ucse", "BVI", "LISP")

_hold_counts: dict[str, dict[str, int]] = {}   # dev_id → {"table|key": consecutive down observations}


def _iface_health(info: dict | None) -> str:
    """Classify an interface row: up / down / other (admin-down, testing, unknown) / gone."""
    if info is None:
        return "gone"
    oper = info.get("oper")
    if oper == "1":
        return "up"
    if info.get("admin", "1") == "1" and oper in _IF_OPER_DOWN:
        return "down"
    return "other"


def _peer_health(val: str | None, up_value: str) -> str:
    if val is None:
        return "gone"
    return "up" if val == up_value else "down"


def _iface_transition(name: str, o: dict | None, n: dict | None, ho: str, hn: str):
    """→ (is_down_transition, event_spec | None) for one interface."""
    if (ho in ("up", "gone") and hn == "down") or \
       (ho == "up" and hn == "gone" and not name.startswith(_IGNORE_DISAPPEAR)):
        if hn == "gone":
            return True, ("interface_down", "warning", f"{name} no longer present", {"interface": name})
        oper = n["oper"]
        suffix = "" if oper == "2" else f" ({_IF_OPER_STATES.get(oper, oper)})"
        return True, ("interface_down", "critical", f"{name} went DOWN{suffix}", {"interface": name})
    # Recovery: from any down state, or from admin-down (admin-down → admin-up with oper up)
    if hn == "up" and (ho == "down" or (ho == "other" and o.get("admin") == "2")):
        return False, ("interface_up", "info", f"{name} came UP", {"interface": name})
    return False, None


def _bgp_transition(peer: str, o: str | None, n: str | None, ho: str, hn: str):
    if ho == "up" and hn == "down":
        state_name = _BGP_STATES.get(n, n)
        return True, ("bgp_down", "critical", f"BGP peer {peer} → {state_name} (was established)",
                      {"peer": peer, "state": state_name})
    if ho == "up" and hn == "gone":
        return True, ("bgp_down", "critical", f"BGP peer {peer} disappeared (was established)", {"peer": peer})
    if ho == "down" and hn == "up":
        return False, ("bgp_up", "info", f"BGP peer {peer} → established (was {_BGP_STATES.get(o, o)})",
                       {"peer": peer, "state": "established"})
    if ho == "gone" and hn == "up":
        return False, ("bgp_up", "info", f"BGP peer {peer} newly established", {"peer": peer, "state": "established"})
    # Non-established transitions (idle↔active↔connect etc.) are normal BGP FSM
    # negotiation noise and are suppressed entirely
    return False, None


def _ospf_transition(nbr: str, o: str | None, n: str | None, ho: str, hn: str):
    if ho == "up" and hn == "down":
        state_name = _OSPF_STATES.get(n, n)
        return True, ("ospf_down", "critical", f"OSPF neighbor {nbr} → {state_name} (was full)",
                      {"neighbor": nbr, "state": state_name})
    if ho == "up" and hn == "gone":
        return True, ("ospf_down", "critical", f"OSPF neighbor {nbr} disappeared (was full)", {"neighbor": nbr})
    if ho == "down" and hn == "up":
        return False, ("ospf_up", "info", f"OSPF neighbor {nbr} → full (was {_OSPF_STATES.get(o, o)})",
                       {"neighbor": nbr, "state": "full"})
    if ho == "gone" and hn == "up":
        return False, ("ospf_up", "info", f"OSPF neighbor {nbr} newly full", {"neighbor": nbr, "state": "full"})
    # Non-full transitions (init↔twoway↔exchange etc.) are FSM noise — suppressed
    return False, None


_PROTO_TABLES = {
    "interfaces": (_iface_health, _iface_transition),
    "bgp":        (lambda v: _peer_health(v, "6"), _bgp_transition),
    "ospf":       (lambda v: _peer_health(v, "8"), _ospf_transition),
}


def _diff_protocol_state(old: dict | None, new: dict, pending: dict[str, int],
                         hold: int = HOLD_DOWN_POLLS) -> tuple[dict, list[tuple]]:
    """Pure diff of confirmed protocol state against a new observation.

    `old` is the last *confirmed* state (what events have been reported
    against), `new` the latest walk (a table may be None if its walk failed),
    `pending` the per-device hold-down counters (mutated in place).

    Returns (new confirmed state, [(event_type, severity, detail, extra), ...]).
    - A table whose walk failed keeps its confirmed state and raises nothing.
    - A table seen for the first time is a baseline and raises nothing.
    - A down transition is only reported after `hold` consecutive polls;
      until then the entry keeps its last confirmed value.
    """
    old = old or {}
    confirmed, specs = {}, []
    for table, (health, transition) in _PROTO_TABLES.items():
        old_t, new_t = old.get(table), new.get(table)
        if new_t is None:                 # walk failed — no information
            confirmed[table] = old_t
            continue
        prefix = f"{table}|"
        if old_t is None:                 # first successful walk — baseline
            for k in [k for k in pending if k.startswith(prefix)]:
                pending.pop(k)
            confirmed[table] = dict(new_t)
            continue
        out = {}
        for key in sorted(set(old_t) | set(new_t)):
            o, n = old_t.get(key), new_t.get(key)
            is_down, spec = transition(key, o, n, health(o), health(n))
            pkey = prefix + key
            if is_down:
                count = pending.get(pkey, 0) + 1
                if count < hold:
                    pending[pkey] = count
                    if o is not None:
                        out[key] = o      # not confirmed yet — keep last confirmed value
                    continue
            pending.pop(pkey, None)
            if spec:
                specs.append(spec)
            if n is not None:
                out[key] = n
        seen = set(old_t) | set(new_t)
        for k in [k for k in pending if k.startswith(prefix) and k[len(prefix):] not in seen]:
            pending.pop(k)
        confirmed[table] = out
    return confirmed, specs


def _detect_events(dev: dict, old_state: dict | None, new_state: dict) -> tuple[dict, list[dict]]:
    """Diff protocol state for one device and emit the resulting events.
    Returns (new confirmed state, emitted events)."""
    pending = _hold_counts.setdefault(dev["id"], {})
    confirmed, specs = _diff_protocol_state(old_state, new_state, pending)
    events = [_add_event(dev, *spec) for spec in specs]
    return confirmed, [e for e in events if e is not None]


# ── Alert helpers ──────────────────────────────────────────────────────────────
_STATUS_SEVERITY = {"ok": 0, "unknown": 0, "warn": 1, "error": 2}

def _alert_transition(prev: str | None, new_status: str) -> str | None:
    """What a device status means for alerting, given the last status we acted on.

    prev is None when we have no record of the device (new device, or first run
    without persisted alert state): that poll is a baseline and never alerts,
    so a restart can't re-raise alerts for devices that were already down.
    Returns "baseline", "degraded", "recovered" or None (no change).
    """
    if prev is None:
        return "baseline"
    if _STATUS_SEVERITY.get(new_status, 0) > _STATUS_SEVERITY.get(prev, 0):
        return "degraded"
    if new_status == "ok" and prev != "ok":
        return "recovered"
    return None


def _set_last_alerted(dev_id: str, status: str) -> None:
    with _alert_lock:
        _last_alerted[dev_id] = status
    _save_alert_state()


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
        r = requests.post(f"{GLADIUS_API_URL}/api/snmp/alert", json=payload, headers=_GLADIUS_API_HEADERS, timeout=10)
        log.log(logging.INFO if r.ok else logging.WARNING, "Alert POSTed for %s: %s→%s (HTTP %d)",
                dev.get("name"), old_status, new_status, r.status_code)
    except Exception as e:
        log.warning("Failed to send alert for %s: %s", dev.get("name"), e)


# ── Background polling loop ────────────────────────────────────────────────────
async def _poll_one(dev_id: str):
    """Poll one registered device: system GET, alerting, protocol state."""
    dev = _devices.get(dev_id)
    if not dev:
        return
    result = await asyncio.to_thread(_poll_device_sync, dev)
    old_status = _staleness(_status.get(dev_id, {})) if dev_id in _status else "unknown"
    _status[dev_id] = result
    new_status = _staleness(result)
    log.info("Polled %s (%s) → %s %dms",
             dev.get("name", dev["host"]), dev["host"],
             new_status, result["response_ms"])

    transition = _alert_transition(_last_alerted.get(dev_id), new_status)
    if transition == "baseline":
        _set_last_alerted(dev_id, new_status)
        if new_status != "ok":
            log.info("First poll of %s is %s — recorded as baseline, not alerted",
                     dev.get("name", dev["host"]), new_status)
    # Fire alert on status degradation (suppressed for muted devices)
    elif transition == "degraded":
        _set_last_alerted(dev_id, new_status)
        if dev.get("muted"):
            log.debug("MUTED — skipping alert POST for %s (%s) %s→%s",
                      dev.get("name", dev["host"]), dev["host"], old_status, new_status)
        else:
            _spawn(asyncio.to_thread(_send_alert_sync, dev, old_status, new_status, dict(result)))
        # Device went down — generate event (also gated by mute inside _add_event)
        if new_status == "error":
            _add_event(dev, "device_down", "critical", f"Device unreachable ({result.get('error', 'no response')})")
    elif transition == "recovered":
        _set_last_alerted(dev_id, "ok")
        _add_event(dev, "device_up", "info", "Device recovered")
        log.info("Device %s recovered → alert state reset", dev.get("name", dev["host"]))

    # Protocol state polling (only if device is reachable)
    if new_status == "ok":
        try:
            # Enrich dev with sysName for event labels
            enriched = {**dev, "sysName": result.get("sysName", "")}
            proto_state = await asyncio.to_thread(_poll_protocol_state_sync, enriched)
            confirmed, _ = _detect_events(enriched, _proto_state.get(dev_id), proto_state)
            _proto_state[dev_id] = confirmed
        except Exception as e:
            log.debug("Protocol poll error for %s: %s", dev["host"], e)


POLL_CONCURRENCY = max(1, int(os.getenv("SNMP_POLL_CONCURRENCY", "10")))   # devices polled in parallel
_RESTART_DELAY = 5                     # seconds before a crashed background loop is restarted
_started_at = time.monotonic()
_last_cycle_completed: float | None = None   # monotonic time the last full poll cycle finished


async def _poll_one_guarded(dev_id: str, sem: asyncio.Semaphore):
    async with sem:
        try:
            await _poll_one(dev_id)
        except Exception:
            log.exception("Poll of device %s failed", dev_id)


async def _poll_cycle():
    """Poll every registered device, POLL_CONCURRENCY at a time. One device
    failing (or timing out) never holds up or aborts the others."""
    sem = asyncio.Semaphore(POLL_CONCURRENCY)
    await asyncio.gather(*(_poll_one_guarded(dev_id, sem) for dev_id in list(_devices.keys())))


async def _poll_all():
    """Run poll cycles on a fixed cadence (start-to-start POLL_INTERVAL)."""
    global _last_cycle_completed
    loop = asyncio.get_running_loop()
    next_run = loop.time()
    while True:
        try:
            await _poll_cycle()
            _last_cycle_completed = time.monotonic()
        except Exception:
            log.exception("Poll cycle failed")
        next_run += POLL_INTERVAL
        delay = next_run - loop.time()
        if delay < 0:
            log.warning("Poll cycle overran POLL_INTERVAL (%ds) by %.0fs", POLL_INTERVAL, -delay)
            next_run, delay = loop.time(), 0
        await asyncio.sleep(delay)


async def _supervise(name: str, factory):
    """Keep a long-running background coroutine alive: log and restart it if it
    ever raises or returns, instead of letting monitoring silently stop."""
    while True:
        try:
            await factory()
            log.error("%s exited unexpectedly — restarting", name)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("%s crashed — restarting in %ds", name, _RESTART_DELAY)
        await asyncio.sleep(_RESTART_DELAY)


def _poller_health() -> tuple[bool, float | None]:
    """→ (healthy, seconds since last completed cycle). Unhealthy once no cycle
    has completed for 3× POLL_INTERVAL (counting from startup)."""
    now = time.monotonic()
    age = None if _last_cycle_completed is None else now - _last_cycle_completed
    ref = age if age is not None else now - _started_at
    return ref <= POLL_INTERVAL * 3, age


_bg_tasks: set[asyncio.Task] = set()   # strong refs so background tasks aren't garbage-collected


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _side_effects, _started_at
    _started_at = time.monotonic()
    _load_devices()
    _load_alert_state()
    _side_effects = asyncio.Queue(maxsize=_SIDE_EFFECT_QUEUE_MAX)
    _spawn(_supervise("Side-effect worker", _side_effect_worker))
    # Kick off an immediate poll before the regular loop
    _spawn(_supervise("Poll loop", _poll_all))
    yield


ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "https://gladius.clydeford.net").split(",")
    if origin.strip()
]


async def require_token(authorization: str = Header(default="")) -> None:
    """FastAPI dependency: requires 'Authorization: Bearer <GLADIUS_API_TOKEN>'."""
    if not GLADIUS_API_TOKEN:
        raise HTTPException(status_code=401, detail="Server auth not configured")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, GLADIUS_API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI(title="Gladius SNMP Monitor", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


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
# Fields that must never leave this process in an API response — they are the
# SNMP secrets used to authenticate to the device.
_SECRET_DEVICE_FIELDS = ("community", "auth_key", "priv_key")


def _redact_device(dev: dict) -> dict:
    """Strip SNMP secrets from a device dict before it goes out over the API."""
    return {k: v for k, v in dev.items() if k not in _SECRET_DEVICE_FIELDS}


def _device_with_status(dev_id: str) -> dict:
    dev = _redact_device(_devices[dev_id])
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
    healthy, age = _poller_health()
    body = {
        "status":          "ok" if healthy and not _registry_error else "error",
        "service":         "gladius-snmp",
        "devices":         len(_devices),
        "poll_interval":   POLL_INTERVAL,
        "last_cycle_age_s": None if age is None else round(age, 1),
    }
    if not healthy:
        body["detail"] = f"no poll cycle completed in over {POLL_INTERVAL * 3}s"
    if _registry_error:
        body["detail"] = "device registry could not be loaded (devices.json unreadable)"
    return JSONResponse(body, status_code=200 if body["status"] == "ok" else 503)


@app.get("/devices", dependencies=[Depends(require_token)])
def list_devices():
    result = []
    for dev_id in _devices:
        d = _device_with_status(dev_id)
        d["status"] = _staleness(_status.get(dev_id, {}))
        result.append(d)
    return {"devices": result}


@app.post("/devices", status_code=201, dependencies=[Depends(require_token)])
async def add_device(body: DeviceIn):
    _require_writable_registry()
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


@app.delete("/devices/{dev_id}", status_code=204, dependencies=[Depends(require_token)])
def delete_device(dev_id: str):
    _require_writable_registry()
    if dev_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    _devices.pop(dev_id)
    _status.pop(dev_id, None)
    _save_devices()


@app.post("/devices/mute-all", dependencies=[Depends(require_token)])
async def mute_all_devices(request: Request):
    _require_writable_registry()
    body = await request.json()
    muted = body.get("muted", True)
    for dev_id in _devices:
        _devices[dev_id]["muted"] = muted
    _save_devices()
    return {"ok": True, "muted": muted, "count": len(_devices)}


@app.patch("/devices/{dev_id}", dependencies=[Depends(require_token)])
def patch_device(dev_id: str, body: DevicePatch):
    _require_writable_registry()
    if dev_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    updates = body.model_dump(exclude_none=True)
    _devices[dev_id].update(updates)
    _save_devices()
    return _device_with_status(dev_id)


@app.post("/devices/{dev_id}/poll", dependencies=[Depends(require_token)])
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
            ei, es, _, varBinds = next(getCmd(_snmp_engine(dev), _auth_data(dev), transport, ContextData(), *objects))
            if ei: raise RuntimeError(str(ei))
            for var in varBinds:
                oid_str = str(var[0])
                val = var[1]
                results.append({"oid": oid_str, "label": _label(oid_str),
                                 "value": _fmt_timeticks(val) if isinstance(val, TimeTicks) else val.prettyPrint()})
        else:
            errors = []
            for oid in p["oids"]:
                remaining = max_rows - len(results)
                if remaining <= 0:
                    break
                rows = _snmp_walk(dev, oid, remaining, timeout=5, retries=1, errors=errors)
                if rows is None:
                    # Keep what earlier walks returned; a failure with nothing at all is an error
                    if not results:
                        raise RuntimeError(errors[-1] if errors else "SNMP walk failed")
                    break
                for oid_str, val in rows:
                    results.append({"oid": oid_str, "label": _label(oid_str),
                                     "value": _fmt_timeticks(val) if isinstance(val, TimeTicks) else val.prettyPrint()})
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


@app.get("/events", dependencies=[Depends(require_token)])
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


@app.delete("/events", status_code=204, dependencies=[Depends(require_token)])
def clear_events():
    """Clear all stored events."""
    _events.clear()
    return


@app.get("/proto_state", dependencies=[Depends(require_token)])
def get_proto_state(device_id: str | None = None):
    """Return current protocol state (interfaces, BGP, OSPF) per device."""
    if device_id:
        state = _proto_state.get(device_id)
        if state is None:
            raise HTTPException(status_code=404, detail="No protocol state for device")
        return {device_id: state}
    return _proto_state


@app.post("/poll", dependencies=[Depends(require_token)])
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


class DeviceProfilePollRequest(BaseModel):
    profile:  str = "system"
    max_rows: int = 200


@app.post("/devices/{dev_id}/poll_profile", dependencies=[Depends(require_token)])
async def poll_device_profile(dev_id: str, req: DeviceProfilePollRequest):
    """Ad-hoc profile poll (cisco_cpu, interfaces, ...) using a registered
    device's own stored credentials — the caller never sees the secret.
    Use this instead of round-tripping community/auth_key/priv_key through
    the browser via GET /devices + POST /poll."""
    if dev_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    dev = _devices[dev_id]
    result = await asyncio.to_thread(
        _adhoc_poll_sync,
        dev["host"], dev.get("port", 161), dev.get("version", "2c"), dev.get("community", "public"),
        dev.get("username", ""), dev.get("auth_key", ""), dev.get("priv_key", ""),
        dev.get("auth_protocol", "SHA"), dev.get("priv_protocol", "AES"),
        req.profile, req.max_rows,
    )
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result
