#!/usr/bin/env python3
"""Gladius SNMP Monitor — persistent device registry with background polling."""

import os
import uuid
import json
import time
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
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

DEVICES_FILE  = Path(os.getenv("DEVICES_FILE", "/data/devices.json"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))   # seconds between polls

# ── OIDs polled for every device ───────────────────────────────────────────────
SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.2.1.0": "ifNumber",
}

# ── In-memory stores ───────────────────────────────────────────────────────────
_devices: dict[str, dict] = {}   # id → device config
_status:  dict[str, dict] = {}   # id → latest poll result

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


# ── Background polling loop ────────────────────────────────────────────────────
async def _poll_all():
    while True:
        ids = list(_devices.keys())
        for dev_id in ids:
            dev = _devices.get(dev_id)
            if not dev:
                continue
            result = await asyncio.to_thread(_poll_device_sync, dev)
            _status[dev_id] = result
            log.info("Polled %s (%s) → %s %dms",
                     dev.get("name", dev["host"]), dev["host"],
                     result["status"], result["response_ms"])
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
    "ip_addresses":   {"mode": "walk", "oids": ["1.3.6.1.2.1.4.20"]},
    "arp":            {"mode": "walk", "oids": ["1.3.6.1.2.1.4.22"]},
    "bgp":            {"mode": "walk", "oids": ["1.3.6.1.2.1.15.3"]},
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
