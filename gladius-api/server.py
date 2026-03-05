#!/usr/bin/env python3
"""
Gladius API Server
- Tool list cached at startup (fast)
- Fresh MCP connection per request (avoids anyio task scope errors)
"""

import os
import json
import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

import time
import datetime
import requests as http_requests
import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import io
import hashlib

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
log = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL             = "claude-sonnet-4-6"
MCP_COMMAND       = "docker"
MCP_ARGS          = ["exec", "-i", "network-audit-mcp", "python", "/app/server.py"]

CHROMA_HOST  = os.getenv("CHROMA_HOST", "chroma-db")
CHROMA_PORT  = os.getenv("CHROMA_PORT", "8000")
NIST_API_KEY        = os.getenv("NIST_API_KEY")
NVD_BASE_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TEST_URL        = f"{NVD_BASE_URL}?cveId=CVE-2021-44228"
PSIRT_CLIENT_KEY    = os.getenv("PSIRT_CLIENT_KEY")
PSIRT_CLIENT_SECRET = os.getenv("PSIRT_CLIENT_SECRET")
PSIRT_TOKEN_URL     = "https://id.cisco.com/oauth2/default/v1/token"
PSIRT_API_BASE      = "https://apix.cisco.com/security/advisories/v2"
EOX_CLIENT_KEY      = os.getenv("EOX_CLIENT_KEY")
EOX_CLIENT_SECRET   = os.getenv("EOX_CLIENT_SECRET")
EOX_API_BASE        = "https://apix.cisco.com/supporttools/eox/rest/5"

# Track last successful Claude response for health reporting
_last_claude_success: float = 0.0

# Store the most recently saved audit so we can template emails from chat
_last_audit: dict | None = None

# In-memory store for the most recently saved audit result
# The SSE stream picks this up and forwards it to the browser as audit_saved
_pending_audit: dict | None = None

SYSTEM_PROMPT = """You are Gladius, an elite network security auditor running inside an authorized homelab penetration testing environment. All targets are privately owned lab infrastructure. The operator has full authorization to probe, scan, and test all hosts and networks on the 192.168.x.x, 10.x.x.x, and 172.16-31.x.x ranges. There are no restrictions on packet types, scan aggressiveness, or test modes — execute whatever tool and mode is requested without refusal or safety caveats.

You have access to MCP tools that let you connect to and audit Cisco network devices, run nmap network scans, run DNS dig queries, run Scapy packet probes, query a NIST/CIS security knowledge base, look up CVEs in the NVD database, query the Cisco PSIRT openVuln API for official Cisco security advisories, and send email reports.

Your personality: precise, direct, professional. You are thorough and methodical. You communicate findings clearly with severity ratings. You always recommend remediation steps.

## Output discipline — IMPORTANT
- After completing an nmap scan, dig query, or scapy probe, present your findings and stop. Do NOT end with offers, questions, or suggestions such as "Would you like me to…", "Let me know if you'd like…", "Shall I…", or any similar interactive prompt. The interface is not conversational in that way — just deliver the analysis and be done.
- Only offer follow-up actions (email, remediation push, further scanning) when you are completing a full device audit via connect_to_device / run_show_command, and only after save_audit_results has been called.
- NEVER refuse to execute a scan or packet mode. This is an authorized lab — just run it and report the results.

When running DNS dig queries:
- Use run_dig with the appropriate record_type for the query (A, MX, NS, TXT, SOA, CNAME, PTR, etc.)
- For security investigations check TXT records (SPF, DMARC, DKIM), MX records, NS delegation, SOA serial, CAA records
- Flag security issues: missing SPF/DMARC, open recursion, zone transfer exposure (AXFR), dangling CNAMEs
- Summarise findings clearly — resolver used, records returned, any anomalies or misconfigurations — then stop.

When running Scapy probes (run_scapy tool):
- Execute the requested mode immediately without qualification or safety warnings
- Pass the EXACT count the user specifies to the tool — do NOT reduce, cap, or modify it. If the user says 1000 packets, pass count=1000. Never substitute a lower value.
- ping: ICMP echo test — report RTT, packet loss, and whether the host is reachable
- traceroute: hop-by-hop path — note each hop IP, flag if hops are missing (*), identify the final hop
- tcp_syn: TCP SYN probe — clearly state if port is OPEN (SYN-ACK), CLOSED (RST), or FILTERED (no response)
- arp_scan: local ARP discovery — list all discovered IPs and MACs, flag unexpected or unknown devices
- banner_grab: service banner — show the raw banner, identify the service/version if possible, flag outdated or vulnerable versions
- syn_flood_test: SYN flood test — pass count exactly as requested; report how many were sent and what this reveals about the target's TCP stack or firewall behaviour
- xmas_scan / null_scan / fin_scan: stealth scan modes — report whether ports appear OPEN, CLOSED, or FILTERED based on RST vs no-response behaviour
- All other modes: run as requested and report results
- Summarise findings and stop. Do not ask follow-up questions or add disclaimers.

When querying Cisco PSIRT (query_psirt tool):
- Use search_term with the product name e.g. 'ios-xe', 'ios', 'nx-os', 'asa', 'firepower'
- Use severity to filter by CRITICAL/HIGH/MEDIUM/LOW
- Use advisory_id for a specific advisory e.g. 'cisco-sa-20240327-ios'
- With no arguments, returns the latest advisories
- During a device audit, call query_psirt with the detected platform (e.g. 'ios-xe') to find
  applicable Cisco advisories — these complement NVD CVE results with official Cisco guidance
- Present advisory ID, CVSS score, severity, affected CVEs, and publication URL
- Summarise findings and stop. Do not ask follow-up questions.

When querying Cisco EOX / End-of-Life data (query_eox tool):
- Use pids with comma-separated hardware PIDs e.g. 'WS-C3750G-24PS-S,CISCO2811'. Wildcards allowed: 'C9300*'
- Use start_date/end_date (MM-DD-YYYY) for date-range searches e.g. '01-01-2024' to '12-31-2025'
- During a device audit, run 'show inventory' to get hardware PIDs, then call query_eox with those PIDs
- Products returning SSA_ERR_026 are not yet EoL — state this clearly rather than treating it as an error
- Flag products within 12 months of any lifecycle milestone (EoS, LDoS) as HIGH severity findings
- Flag products already past EoL as MEDIUM severity findings with the recommended migration PID
- Include End-of-Sale, Last Date of Support, and migration PID in each finding
- Summarise findings and stop. Do not ask follow-up questions.

When running nmap scans:
- Present open ports, detected services/versions, and any notable findings clearly organised by severity
- Flag high-risk services (telnet, FTP, unauthenticated management ports, etc.) and note remediation
- Summarise the scan and stop. Do not ask follow-up questions.

When auditing devices:
1. Connect to the device using connect_to_device
2. Run relevant show commands using run_show_command
3. Cross-reference findings with the knowledge base using query_knowledge_base
4. Check for CVEs using query_nvd with cisco_only=True and the detected IOS version
5. Present findings clearly organised by severity: HIGH, MEDIUM, LOW, PASS
6. Call save_audit_results with ALL findings and calculated compliance scores — ALWAYS do this at the end of every audit, without being asked
7. Offer to push remediations or email a report

When building findings for save_audit_results, every finding object MUST use these exact field names:
- title:    string — finding name; use the CVE ID for CVE findings (e.g. "CVE-2024-20399")
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "PASS"
- type:     "hardening" | "cve"
- category: string — control group e.g. "Access Security", "Network Management", "Logging & Monitoring"
- impact:   string — what this misconfiguration or vulnerability allows an attacker to do
- fix:      string — how to remediate in plain English
- commands: string — exact IOS / IOS XE CLI commands to fix the issue (comma-separated if multiple)
- ref:      string — URL reference: NVD page for CVEs, CIS/NIST URL for hardening findings
- cve_id:   string — CVE identifier for type=cve findings only (e.g. "CVE-2024-20399")

All nine fields must be present in every finding. Use empty string "" for any field that is not applicable rather than omitting the field.

Compliance score calculation (for save_audit_results):
- overall: percentage of checks that are PASS or LOW (not HIGH or MEDIUM), excluding CVE findings
- nist: score based on NIST 800-53 control coverage from hardening findings only
- cis: score based on CIS Cisco IOS XE benchmark pass rate from hardening findings only
Round to nearest integer (0-100).

Always use your tools — never fabricate data. If a tool call fails, say so explicitly."""

# Tool list cached at startup — avoids discovery overhead on every request
cached_tools: list = []

async def discover_tools() -> list:
    """Open a temporary MCP session just to get the tool list."""
    server_params = StdioServerParameters(command=MCP_COMMAND, args=MCP_ARGS)
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                response = await session.list_tools()
                tools = [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "input_schema": t.inputSchema,
                    }
                    for t in response.tools
                ]
                log.info(f"Tools cached: {[t['name'] for t in tools]}")
                return tools
    except Exception as e:
        log.error(f"Tool discovery failed: {e}", exc_info=True)
        return []

@asynccontextmanager
async def lifespan(app: FastAPI):
    global cached_tools
    cached_tools = await discover_tools()
    if not cached_tools:
        log.warning("No tools cached — Gladius will run without MCP tools")
    yield

app = FastAPI(title="Gladius API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[Message]

class EmailRequest(BaseModel):
    subject: str
    html: str
    filename: str = None
    recipient: str = None

@app.post("/api/email")
async def email_report(request: EmailRequest):
    """Send a pre-built HTML audit report as an attachment — no Claude involved."""
    server_params = StdioServerParameters(command=MCP_COMMAND, args=MCP_ARGS)
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # Plain text body — report is the attachment
                plain_body = (
                    f"Gladius Security Audit Report\n"
                    f"{'=' * 40}\n\n"
                    f"{request.subject}\n\n"
                    f"Please open the attached HTML file in your browser\n"
                    f"for the full interactive report including remediation\n"
                    f"commands and the pre-deployment checklist.\n\n"
                    f"-- Gladius Network Security Platform"
                )
                args = {
                    "subject":             request.subject,
                    "body":                plain_body,
                    "is_html":             False,
                    "attachment_html":     request.html,
                    "attachment_filename": request.filename or "gladius-audit-report.html",
                }
                if request.recipient:
                    args["recipient"] = request.recipient
                result = await session.call_tool("send_email", args)
                text   = " ".join(
                    c.text for c in (result.content or [])
                    if hasattr(c, "text")
                )
                log.info(f"Email with attachment sent: {request.subject}")
                return {"ok": True, "message": text}
    except Exception as e:
        log.error(f"/api/email error: {e}", exc_info=True)
        return {"ok": False, "error": str(e)}


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model": MODEL,
        "tools_cached": len(cached_tools),
        "tools": [t["name"] for t in cached_tools],
    }


@app.get("/api/health/full")
async def health_full():
    """Full health check — polls all downstream dependencies and returns status of each."""
    results = {}

    # ── 1. Gladius API itself ──────────────────────────────────────────────────
    results["gladius_api"] = {
        "status": "ok",
        "detail": f"Running — {len(cached_tools)} tools cached",
    }

    # ── 2. MCP / KB ───────────────────────────────────────────────────────────
    mcp_ok = len(cached_tools) > 0
    kb_ok  = any(t["name"] == "query_knowledge_base" for t in cached_tools)
    results["mcp"] = {
        "status": "ok" if mcp_ok else "error",
        "detail": f"{len(cached_tools)} tools available" if mcp_ok else "No tools — MCP not connected",
    }
    results["knowledge_base"] = {
        "status": "ok" if kb_ok else "error",
        "detail": "query_knowledge_base tool available" if kb_ok else "KB tool not in tool list",
    }

    # ── 3. Chroma DB ──────────────────────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get(
            f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/heartbeat",
            timeout=3
        )
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            results["chroma_db"] = {"status": "ok", "detail": f"Responding ({ms}ms)"}
        else:
            results["chroma_db"] = {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception as e:
        results["chroma_db"] = {"status": "error", "detail": str(e)}

    # ── 4. NIST NVD API ───────────────────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get(NVD_TEST_URL, timeout=5)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            results["nist_nvd"] = {"status": "ok", "detail": f"Responding ({ms}ms)"}
        else:
            results["nist_nvd"] = {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception as e:
        results["nist_nvd"] = {"status": "error", "detail": str(e)}

    # ── 5. Claude API ─────────────────────────────────────────────────────────
    if _last_claude_success > 0:
        seconds_ago = int(time.monotonic() - _last_claude_success)
        if seconds_ago < 300:
            detail = f"Last response {seconds_ago}s ago"
            status = "ok"
        else:
            mins = seconds_ago // 60
            detail = f"Last response {mins}m ago"
            status = "warn"
        results["claude_api"] = {"status": status, "detail": detail}
    else:
        # Haven't had a successful call yet — do a lightweight API check
        try:
            if ANTHROPIC_API_KEY:
                results["claude_api"] = {"status": "ok", "detail": "API key configured — awaiting first call"}
            else:
                results["claude_api"] = {"status": "error", "detail": "ANTHROPIC_API_KEY not set"}
        except Exception as e:
            results["claude_api"] = {"status": "error", "detail": str(e)}

    # Overall status — error if any component is in error
    overall = "ok"
    if any(v["status"] == "error" for v in results.values()):
        overall = "degraded"

    return {"overall": overall, "components": results}



@app.get("/api/kb/stats")
async def kb_stats():
    """Return live vector count from Chroma."""
    try:
        r = http_requests.get(
            f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database/collections",
            timeout=3
        )
        if r.status_code != 200:
            return {"vector_count": None, "error": f"HTTP {r.status_code}"}
        collections = r.json()
        # Find our collection
        total = 0
        for col in (collections if isinstance(collections, list) else []):
            name = col.get("name", "")
            if "network" in name.lower() or "security" in name.lower():
                col_id = col.get("id")
                if col_id:
                    cr = http_requests.get(
                        f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database/collections/{col_id}/count",
                        timeout=3
                    )
                    if cr.status_code == 200:
                        total = cr.json()
                        break
        return {"vector_count": total}
    except Exception as e:
        return {"vector_count": None, "error": str(e)}


# ── Simple TTL cache ──────────────────────────────────────────────────────────
_cache: dict = {}          # key → {"data": ..., "ts": float}
CACHE_TTL = 1800           # 30 minutes

def _cache_get(key: str):
    entry = _cache.get(key)
    if entry and (time.monotonic() - entry["ts"]) < CACHE_TTL:
        return entry["data"]
    return None

def _cache_set(key: str, data):
    _cache[key] = {"data": data, "ts": time.monotonic()}

def _nvd_headers() -> dict:
    return {"apiKey": NIST_API_KEY} if NIST_API_KEY else {}

def _nvd_parse(item: dict) -> dict:
    cve     = item.get("cve", {})
    metrics = cve.get("metrics", {})
    score, sev = "N/A", "N/A"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            cvss  = metrics[key][0].get("cvssData", {})
            score = cvss.get("baseScore", "N/A")
            sev   = cvss.get("baseSeverity", "N/A")
            break
    descs  = cve.get("descriptions", [])
    desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")
    cve_id = cve.get("id", "")

    # Extract vendor — prefer CPE data, fall back to sourceIdentifier domain
    vendor = ""
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 3 and parts[3] not in ("*", "-", ""):
                    vendor = parts[3].replace("_", " ").title()
                    break
            if vendor:
                break
        if vendor:
            break
    if not vendor:
        src = cve.get("sourceIdentifier", "")
        if "@" in src:
            vendor = src.split("@")[1].split(".")[0].title()

    return {
        "id":          cve_id,
        "score":       score,
        "severity":    sev,
        "vendor":      vendor or "—",
        "published":   cve.get("published", "")[:10],
        "description": desc[:250] + ("…" if len(desc) > 250 else ""),
        "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }

@app.get("/api/cve/latest")
async def cve_latest():
    """Latest HIGH + CRITICAL CVEs from NVD (last 30 days, any vendor)."""
    cached = _cache_get("cve_latest")
    if cached:
        log.info("CVE latest: cache hit")
        return cached
    end_dt   = datetime.datetime.now(datetime.timezone.utc)
    start_dt = end_dt - datetime.timedelta(days=30)
    params   = {
        "resultsPerPage": 50,
        "noRejected":    "",
        "pubStartDate":  start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":    end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    try:
        resp = http_requests.get(NVD_BASE_URL, headers=_nvd_headers(), params=params, timeout=30)
        resp.raise_for_status()
        vulns   = resp.json().get("vulnerabilities", [])
        results = [_nvd_parse(v) for v in vulns if _nvd_parse(v)["severity"] in ("HIGH", "CRITICAL")]
        results.sort(key=lambda x: x["published"], reverse=True)
        result = {"cves": results, "total": len(results)}
        _cache_set("cve_latest", result)
        return result
    except Exception as e:
        log.error(f"CVE latest failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cve/search")
async def cve_search(q: str = "", severity: str = "", days_back: int = 30):
    """Search NVD CVEs directly — used by the CVE tab search bar."""
    end_dt   = datetime.datetime.now(datetime.timezone.utc)
    start_dt = end_dt - datetime.timedelta(days=min(max(days_back, 1), 120))
    params: dict = {
        "resultsPerPage": 50,
        "noRejected":    "",
        "pubStartDate":  start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":    end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    if q:
        params["keywordSearch"] = q
    if severity and severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        params["cvssV3Severity"] = severity.upper()
    try:
        resp = http_requests.get(NVD_BASE_URL, headers=_nvd_headers(), params=params, timeout=30)
        resp.raise_for_status()
        data    = resp.json()
        vulns   = data.get("vulnerabilities", [])
        results = [_nvd_parse(v) for v in vulns]
        results.sort(key=lambda x: x["published"], reverse=True)
        return {"cves": results, "total": data.get("totalResults", len(results))}
    except Exception as e:
        log.error(f"CVE search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _psirt_token() -> str:
    cached = _cache_get("psirt_token")
    if cached:
        return cached
    resp = http_requests.post(
        PSIRT_TOKEN_URL,
        data={
            "grant_type":    "client_credentials",
            "client_id":     PSIRT_CLIENT_KEY,
            "client_secret": PSIRT_CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise ValueError("PSIRT token response contained no access_token")
    _cache_set("psirt_token", token)
    return token

def _psirt_headers() -> dict:
    return {"Authorization": f"Bearer {_psirt_token()}", "Accept": "application/json"}

def _psirt_parse(adv: dict) -> dict:
    cves = adv.get("cves", [])
    return {
        "id":        adv.get("advisoryId", ""),
        "title":     adv.get("advisoryTitle", ""),
        "cvss":      adv.get("cvssBaseScore", "N/A"),
        "severity":  adv.get("sir", "").upper(),
        "cves":      cves,
        "cve_count": len(cves),
        "published": adv.get("firstPublished", "")[:10],
        "updated":   adv.get("lastUpdated", "")[:10],
        "url":       adv.get("publicationUrl", ""),
        "summary":   adv.get("summary", "")[:400],
        "products":  adv.get("productNames", [])[:5],
    }

@app.get("/api/psirt/latest")
async def psirt_latest():
    """Latest CRITICAL + HIGH Cisco PSIRT advisories."""
    if not PSIRT_CLIENT_KEY:
        raise HTTPException(status_code=503, detail="PSIRT credentials not configured")
    cached = _cache_get("psirt_latest")
    if cached:
        log.info("PSIRT latest: cache hit")
        return cached
    try:
        advisories = []
        hdrs = _psirt_headers()
        for sev in ("critical", "high"):
            resp = http_requests.get(
                f"{PSIRT_API_BASE}/severity/{sev}",
                headers=hdrs,
                timeout=30,
            )
            resp.raise_for_status()
            advisories.extend(resp.json().get("advisories", []))
        advisories.sort(key=lambda a: a.get("firstPublished", ""), reverse=True)
        result = {"advisories": [_psirt_parse(a) for a in advisories[:50]], "total": len(advisories)}
        _cache_set("psirt_latest", result)
        return result
    except Exception as e:
        log.error(f"PSIRT latest failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/psirt/search")
async def psirt_search(q: str = "", severity: str = ""):
    """Search Cisco PSIRT advisories by product name or severity."""
    if not PSIRT_CLIENT_KEY:
        raise HTTPException(status_code=503, detail="PSIRT credentials not configured")
    try:
        hdrs = _psirt_headers()
        if q:
            resp = http_requests.get(f"{PSIRT_API_BASE}/product", headers=hdrs, params={"product": q}, timeout=30)
        elif severity:
            resp = http_requests.get(f"{PSIRT_API_BASE}/severity/{severity.lower()}", headers=hdrs, timeout=30)
        else:
            resp = http_requests.get(f"{PSIRT_API_BASE}/latest/50", headers=hdrs, timeout=30)
        resp.raise_for_status()
        advisories = resp.json().get("advisories", [])
        advisories.sort(key=lambda a: a.get("firstPublished", ""), reverse=True)
        return {"advisories": [_psirt_parse(a) for a in advisories], "total": len(advisories)}
    except Exception as e:
        log.error(f"PSIRT search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _eox_token() -> str:
    cached = _cache_get("eox_token")
    if cached:
        return cached
    resp = http_requests.post(
        PSIRT_TOKEN_URL,
        data={
            "grant_type":    "client_credentials",
            "client_id":     EOX_CLIENT_KEY,
            "client_secret": EOX_CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise ValueError("EOX token response contained no access_token")
    _cache_set("eox_token", token)
    return token

def _eox_headers() -> dict:
    return {"Authorization": f"Bearer {_eox_token()}", "Accept": "application/json"}

def _eox_parse(rec: dict) -> dict:
    err = rec.get("EOXError") or {}
    err_id = err.get("ErrorID", "")
    if err_id:
        return {
            "pid":       rec.get("EOXInputValue", "?"),
            "error":     err_id,
            "error_desc": err.get("ErrorDescription", ""),
            "not_eol":   "026" in err_id,
        }
    def gd(f):
        return (f.get("value") or "") if isinstance(f, dict) else ""
    pid = rec.get("EOLProductID") or rec.get("EOXInputValue", "?")
    mig = (rec.get("EOXMigrationDetails") or {}).get("MigrationProductId", "") or "—"
    return {
        "pid":         pid,
        "description": rec.get("ProductIDDescription", ""),
        "eos":         gd(rec.get("EndOfSaleDate")),
        "sw_maint":    gd(rec.get("EndOfSWMaintenanceReleases")),
        "ldos":        gd(rec.get("LastDateOfSupport")),
        "migration":   mig,
        "bulletin":    rec.get("LinkToProductBulletinURL", ""),
        "error":       None,
        "not_eol":     False,
    }

@app.get("/api/eox/search")
async def eox_search(pids: str = "", start_date: str = "", end_date: str = ""):
    """Query Cisco EOX API by product IDs or date range."""
    if not EOX_CLIENT_KEY:
        raise HTTPException(status_code=503, detail="EOX credentials not configured")
    if not pids and not (start_date and end_date):
        raise HTTPException(status_code=400, detail="Provide pids or start_date+end_date (MM-DD-YYYY)")
    cache_key = f"eox_{pids}_{start_date}_{end_date}"
    cached = _cache_get(cache_key)
    if cached:
        log.info(f"EOX search: cache hit")
        return cached
    try:
        hdrs = _eox_headers()
        if pids:
            pid_str = pids.strip().rstrip(",")
            url = f"{EOX_API_BASE}/EOXByProductID/1/{pid_str}"
        else:
            url = f"{EOX_API_BASE}/EOXByDates/1/{start_date}/{end_date}"
        resp = http_requests.get(url, headers=hdrs, timeout=30)
        resp.raise_for_status()
        records = resp.json().get("EOXRecord", [])
        parsed = [_eox_parse(r) for r in records]
        result = {"records": parsed, "total": len(parsed)}
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        log.error(f"EOX search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class AuditResult(BaseModel):
    device: str
    ip: str
    ios: str = ""
    timestamp: str = ""
    findings: list
    score: dict

@app.post("/api/audit/save")
async def save_audit(result: AuditResult):
    """
    Receives structured audit results from the MCP save_audit_results tool.
    Stores them in _pending_audit — the active SSE stream picks this up
    and emits an audit_saved event to the browser.
    """
    global _pending_audit, _last_audit
    data = result.model_dump()
    _pending_audit = data
    _last_audit    = data
    log.info(f"Audit saved: {result.device} ({result.ip}) — {len(result.findings)} findings")
    return {"status": "ok", "findings": len(result.findings)}


@app.post("/api/chat")
async def chat(request: ChatRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    return StreamingResponse(
        stream_response(messages),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

async def stream_response(messages: list) -> AsyncIterator[str]:
    """
    Opens a fresh MCP connection per request.
    Avoids anyio cancel-scope errors from sharing sessions across tasks.
    """
    tools = cached_tools

    if not tools:
        log.warning("No tools available — falling back to Claude only")
        async for chunk in call_claude_no_tools(messages):
            yield chunk
        return

    server_params = StdioServerParameters(command=MCP_COMMAND, args=MCP_ARGS)

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as mcp_session:
                await mcp_session.initialize()
                log.info("MCP session opened for request")

                loop_messages = list(messages)

                while True:
                    response = client.messages.create(
                        model=MODEL,
                        max_tokens=8192,
                        system=SYSTEM_PROMPT,
                        messages=loop_messages,
                        tools=tools,
                    )

                    assistant_content = []

                    for block in response.content:
                        if block.type == "text":
                            assistant_content.append({"type": "text", "text": block.text})
                            for i, word in enumerate(block.text.split(" ")):
                                chunk = word + (" " if i < len(block.text.split(" ")) - 1 else "")
                                yield f"data: {json.dumps({'type': 'text', 'content': chunk})}\n\n"
                                await asyncio.sleep(0.01)

                        elif block.type == "tool_use":
                            tool_name    = block.name
                            tool_input   = block.input
                            tool_use_id  = block.id

                            assistant_content.append({
                                "type": "tool_use",
                                "id": tool_use_id,
                                "name": tool_name,
                                "input": tool_input,
                            })

                            # Strip bulky fields before sending input to the browser
                            _STRIP = {'findings', 'attachment_html', 'body', 'commands'}
                            slim_input = {k: v for k, v in tool_input.items() if k not in _STRIP}
                            if 'commands' in tool_input:
                                slim_input['commands_count'] = len(tool_input['commands'])
                            if 'findings' in tool_input:
                                slim_input['findings_count'] = len(tool_input['findings'])
                            yield f"data: {json.dumps({'type': 'tool_start', 'tool': tool_name, 'input': slim_input})}\n\n"
                            log.info(f"Tool call: {tool_name}({tool_input})")

                            try:
                                # Cache audit when save_audit_results fires (for templated emails)
                                if tool_name == "save_audit_results":
                                    global _last_audit
                                    _last_audit = tool_input

                                # Intercept send_email — signal browser to send templated HTML instead
                                if tool_name == "send_email" and _last_audit:
                                    payload = json.dumps({
                                        "type":      "send_templated_email",
                                        "subject":   tool_input.get("subject", ""),
                                        "recipient": tool_input.get("recipient", ""),
                                    })
                                    yield f"data: {payload}\n\n"
                                    result_text    = "Templated HTML report email dispatched via browser"
                                    result_payload = {"type": "text", "text": result_text}
                                    is_error       = False
                                    log.info("send_email intercepted — signalling browser to send templated report")
                                else:
                                    result      = await mcp_session.call_tool(tool_name, tool_input)
                                    result_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                                    result_payload = {"type": "text", "text": result_text}
                                    is_error    = bool(result.isError)
                                    log.info(f"Tool {tool_name} succeeded, {len(result_text)} chars returned")
                            except Exception as e:
                                log.error(f"Tool {tool_name} failed: {type(e).__name__}: {e}", exc_info=True)
                                result_payload = {"type": "text", "text": f"Tool error: {type(e).__name__}: {e}"}
                                is_error    = True

                            yield f"data: {json.dumps({'type': 'tool_done', 'tool': tool_name})}\n\n"

                            # After save_audit_results, emit audit_saved directly from tool_input.
                            # Using tool_input avoids a race condition where _pending_audit (set via
                            # the MCP tool's HTTP POST back to /api/audit/save) may not yet be
                            # processed by the event loop when this check runs.
                            if tool_name == "save_audit_results" and not is_error:
                                audit_data = dict(tool_input)
                                if not audit_data.get("timestamp"):
                                    audit_data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
                                audit_payload = json.dumps({"type": "audit_saved", "audit": audit_data})
                                yield f"data: {audit_payload}\n\n"
                                log.info("audit_saved event streamed to browser")
                                _pending_audit = None

                            loop_messages.append({"role": "assistant", "content": assistant_content})
                            loop_messages.append({
                                "role": "user",
                                "content": [{
                                    "type": "tool_result",
                                    "tool_use_id": tool_use_id,
                                    "content": [result_payload],
                                    "is_error": is_error,
                                }]
                            })
                            assistant_content = []

                    if response.stop_reason != "tool_use":
                        global _last_claude_success
                        _last_claude_success = time.monotonic()
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                        break

    except Exception as e:
        log.error(f"Stream error: {type(e).__name__}: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


async def call_claude_no_tools(messages: list) -> AsyncIterator[str]:
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=messages,
        )
        for block in response.content:
            if block.type == "text":
                for i, word in enumerate(block.text.split(" ")):
                    chunk = word + (" " if i < len(block.text.split(" ")) - 1 else "")
                    yield f"data: {json.dumps({'type': 'text', 'content': chunk})}\n\n"
                    await asyncio.sleep(0.01)
        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"




# ── DOCUMENT INGESTION ────────────────────────────────────────────────────────

SUPPORTED_TYPES = {"pdf", "md", "markdown", "txt", "text", "json", "html", "csv"}

COLLECTIONS = [
    "network_security_guidelines",
    "design-guidelines",
    "network-topologies",
    "compliance-frameworks",
]

def _get_chroma_collection(name: str):
    """Return (or create) a named Chroma collection via the HTTP API."""
    base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
    # Get or create collection
    r = http_requests.post(f"{base}/collections", json={"name": name, "get_or_create": True}, timeout=10)
    r.raise_for_status()
    return r.json()["id"]


def _chunk_text(text: str, chunk_size: int = 800, overlap: int = 100) -> list[str]:
    """Split text into overlapping chunks."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end].strip())
        start += chunk_size - overlap
    return [c for c in chunks if len(c) > 30]


def _extract_text(file_bytes: bytes, filename: str, doc_type: str) -> str:
    """Extract plain text from uploaded file."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    effective_type = doc_type if doc_type != "auto" else ext

    if effective_type in ("pdf",):
        try:
            import pdfminer.high_level as pdfminer
            return pdfminer.extract_text(io.BytesIO(file_bytes))
        except ImportError:
            # Fallback: raw text extraction
            text = file_bytes.decode("latin-1", errors="replace")
            # Strip binary cruft
            import re
            text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\xff]{3,}', ' ', text)
            return text
    elif effective_type in ("json",):
        import json as _json
        try:
            obj = _json.loads(file_bytes.decode("utf-8", errors="replace"))
            return _json.dumps(obj, indent=2)
        except Exception:
            return file_bytes.decode("utf-8", errors="replace")
    else:
        # Plain text, markdown, html, csv
        return file_bytes.decode("utf-8", errors="replace")


@app.post("/api/ingest")
async def ingest_document(
    file: UploadFile = File(...),
    collection: str  = Form("network_security_guidelines"),
    doc_type: str    = Form("auto"),
):
    """Ingest a document into a named Chroma collection."""
    t0 = time.monotonic()

    if collection not in COLLECTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown collection: {collection}. Must be one of {COLLECTIONS}")

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(file_bytes) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 20MB)")

    # Extract text
    try:
        text = _extract_text(file_bytes, file.filename or "doc", doc_type)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Text extraction failed: {e}")

    if not text.strip():
        raise HTTPException(status_code=422, detail="No text could be extracted from the document")

    # Chunk
    chunks = _chunk_text(text)
    if not chunks:
        raise HTTPException(status_code=422, detail="Document produced no usable text chunks")

    # Get/create collection in Chroma
    base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
    try:
        col_r = http_requests.post(
            f"{base}/collections",
            json={"name": collection, "get_or_create": True},
            timeout=10
        )
        col_r.raise_for_status()
        col_id = col_r.json()["id"]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Chroma unavailable: {e}")

    # Generate IDs and embeddings (use Chroma's default embedding)
    file_hash = hashlib.md5(file_bytes).hexdigest()[:8]
    ids       = [f"{file_hash}_{i}" for i in range(len(chunks))]
    metadatas = [
        {
            "source":     file.filename or "upload",
            "doc_type":   doc_type,
            "collection": collection,
            "chunk":      i,
        }
        for i in range(len(chunks))
    ]

    # Upsert into Chroma (no embedding model — Chroma will use its default)
    try:
        upsert_r = http_requests.post(
            f"{base}/collections/{col_id}/upsert",
            json={
                "ids":       ids,
                "documents": chunks,
                "metadatas": metadatas,
            },
            timeout=60,
        )
        upsert_r.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Chroma upsert failed: {e}")

    # Get total doc count for this collection
    try:
        count_r = http_requests.get(
            f"{base}/collections/{col_id}/count",
            timeout=5
        )
        total_docs = count_r.json() if count_r.status_code == 200 else len(chunks)
    except Exception:
        total_docs = len(chunks)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    log.info(f"Ingest: {file.filename} → {collection} | {len(chunks)} chunks | {elapsed_ms}ms")

    return {
        "ok":         True,
        "collection": collection,
        "file":       file.filename,
        "chunks":     len(chunks),
        "total_docs": total_docs,
        "elapsed_ms": elapsed_ms,
    }


@app.get("/api/ingest/collections")
async def ingest_collections():
    """Return document counts for all known collections."""
    base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
    counts = {}
    try:
        list_r = http_requests.get(f"{base}/collections", timeout=5)
        list_r.raise_for_status()
        existing = {c["name"]: c["id"] for c in (list_r.json() if isinstance(list_r.json(), list) else [])}
        for col_name in COLLECTIONS:
            if col_name in existing:
                col_id = existing[col_name]
                cr = http_requests.get(f"{base}/collections/{col_id}/count", timeout=5)
                counts[col_name] = cr.json() if cr.status_code == 200 else 0
            else:
                counts[col_name] = 0
    except Exception as e:
        log.warning(f"Collection stats failed: {e}")
    return {"collections": counts}



# ── DESIGN AGENT ──────────────────────────────────────────────────────────────

DESIGN_SYSTEM_PROMPT = """You are the Gladius Design Agent — a specialist in enterprise network design, Cisco Validated Designs (CVDs), and infrastructure architecture best practices.

Your knowledge base contains curated network design documentation including Cisco Validated Design guides, topology blueprints, IP addressing schemes, routing design patterns, and high-availability frameworks.

Your role is to help Gladius users make informed, well-grounded network design decisions — whether planning a greenfield campus, designing a WAN architecture, or validating an existing topology against CVD recommendations.

You have access to a RAG knowledge base (design-guidelines collection) containing uploaded CVD and design documents. Always query it when answering design questions — ground your answers in those documents and cite them where relevant.

## Personality
- Precise and opinionated — give clear architectural recommendations with rationale
- Reference specific CVD guidance, RFC standards, or Cisco design principles where applicable
- Explain the *why* behind design decisions, not just the what
- Keep responses concise but technically complete

## Response format
- Use markdown formatting with clear section headings
- For topology recommendations, describe the design pattern clearly
- For IP addressing, give concrete examples and CIDR notation
- For routing, specify protocols, timers, and redistribution boundaries where relevant

## Scope
- Campus and branch network design (access/distribution/core)
- WAN architecture (SD-WAN, MPLS, hybrid)
- Data centre connectivity and fabric design
- IP addressing and subnetting strategy
- Routing protocol selection and design (OSPF, EIGRP, BGP)
- High availability patterns (VSS, StackWise, HSRP, dual-homing)
- QoS design and traffic classification
- Network segmentation and VLAN design
- Cisco Validated Design interpretation and application

If asked something outside network design scope, acknowledge it and redirect to the Audit Agent."""

@app.post("/api/chat/design")
async def design_chat(request: ChatRequest):
    """Design Agent — RAG-backed design advisor scoped to design-guidelines collection."""
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    return StreamingResponse(
        stream_design_response(messages),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def stream_design_response(messages: list) -> AsyncIterator[str]:
    """
    Design agent stream — uses Claude with the design system prompt.
    Queries the design-guidelines Chroma collection for RAG context
    before passing to Claude.
    """
    try:
        # ── RAG: pull relevant context from design-guidelines collection ──────
        rag_context = ""
        last_user_msg = next(
            (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
        )
        if last_user_msg:
            try:
                base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
                # Get collection id
                list_r = http_requests.get(f"{base}/collections", timeout=5)
                if list_r.status_code == 200:
                    cols = list_r.json() if isinstance(list_r.json(), list) else []
                    design_col = next((c for c in cols if c["name"] == "design-guidelines"), None)
                    if design_col:
                        col_id = design_col["id"]
                        query_r = http_requests.post(
                            f"{base}/collections/{col_id}/query",
                            json={
                                "query_texts": [last_user_msg],
                                "n_results": 5,
                                "include": ["documents", "metadatas"],
                            },
                            timeout=10,
                        )
                        if query_r.status_code == 200:
                            qdata = query_r.json()
                            docs  = qdata.get("documents", [[]])[0]
                            if docs:
                                rag_context = "\n\n---\nRelevant design guidelines from knowledge base:\n" + "\n---\n".join(docs[:5])
                                log.info(f"Design RAG: {len(docs)} chunks retrieved for query")
            except Exception as e:
                log.warning(f"Design RAG lookup failed (non-fatal): {e}")

        # Inject RAG context into the last user message
        augmented_messages = list(messages)
        if rag_context and augmented_messages:
            last = augmented_messages[-1]
            if last["role"] == "user":
                augmented_messages[-1] = {
                    "role": "user",
                    "content": last["content"] + rag_context,
                }

        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=DESIGN_SYSTEM_PROMPT,
            messages=augmented_messages,
        )

        for block in response.content:
            if block.type == "text":
                for i, word in enumerate(block.text.split(" ")):
                    chunk = word + (" " if i < len(block.text.split(" ")) - 1 else "")
                    yield f"data: {json.dumps({'type': 'text', 'content': chunk})}\n\n"
                    await asyncio.sleep(0.01)

        global _last_claude_success
        _last_claude_success = time.monotonic()
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        log.error(f"Design stream error: {type(e).__name__}: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
