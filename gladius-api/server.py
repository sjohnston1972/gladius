#!/usr/bin/env python3
"""
Gladius API Server
- Persistent MCP session (no subprocess spin-up per request)
- Tool list cached at startup
"""

import os
import json

# Disable HuggingFace network calls — use local cache only.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
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
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import io
import hashlib
import httpx

load_dotenv()

# Lazy-loaded embedding model (shared across requests)
_embed_model = None
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")

def get_embed_model():
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        log.info(f"Loading embedding model: {EMBED_MODEL}")
        # When HF_HUB_OFFLINE=1, sentence_transformers can't resolve short model
        # names through the hub cache. Resolve to the snapshot path explicitly.
        try:
            import huggingface_hub
            cached = huggingface_hub.try_to_load_from_cache(
                f"sentence-transformers/{EMBED_MODEL}", "config.json"
            )
            if cached and cached is not huggingface_hub.utils.EntryNotFoundError:
                model_path = os.path.dirname(cached)
                log.info(f"Loading embed model from local snapshot: {model_path}")
                _embed_model = SentenceTransformer(model_path)
            else:
                _embed_model = SentenceTransformer(EMBED_MODEL)
        except Exception:
            _embed_model = SentenceTransformer(EMBED_MODEL)
        log.info("Embedding model loaded.")
    return _embed_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
log = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL             = "claude-sonnet-4-6"
OLLAMA_URL        = os.getenv("OLLAMA_URL", "http://192.168.1.250:11434")
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

# ── Running Tasks Tracker ─────────────────────────────────────────────────────
import uuid as _uuid
_running_tasks: dict[str, dict] = {}   # task_id → {agent, description, started, source, model}

def _task_start(agent: str, description: str, source: str = "web", model: str = "") -> str:
    """Register a running task. Returns task_id."""
    tid = str(_uuid.uuid4())[:8]
    _running_tasks[tid] = {
        "id": tid,
        "agent": agent,
        "description": description[:200],
        "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "model": model,
        "status": "running",
    }
    log.info(f"[Task {tid}] STARTED: {agent} — {description[:80]} (source={source})")
    return tid

_TASK_RETAIN_SECS = 60  # keep completed tasks visible for 60s

def _task_end(tid: str):
    """Mark a task as completed (retained for _TASK_RETAIN_SECS before removal)."""
    task = _running_tasks.get(tid)
    if task:
        task["status"] = "completed"
        task["completed"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        log.info(f"[Task {tid}] ENDED: {task['agent']} — {task['description'][:80]}")

def _prune_completed_tasks():
    """Remove completed tasks older than _TASK_RETAIN_SECS."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expired = [
        tid for tid, t in _running_tasks.items()
        if t.get("status") == "completed" and t.get("completed")
        and (now - datetime.datetime.fromisoformat(t["completed"])).total_seconds() > _TASK_RETAIN_SECS
    ]
    for tid in expired:
        del _running_tasks[tid]

_SEQUENTIAL_DEVICE_TOOLS = {"connect_to_device", "disconnect_device", "run_show_command", "push_config"}
_CONTINUATION_MSG = (
    "If there are more devices remaining in the batch, proceed to the next one now. "
    "If the task is complete, go ahead and summarise."
)

def _last_tool_in_history(msgs: list) -> str | None:
    """Return the name of the last tool_use block in the most recent assistant message, or None."""
    for msg in reversed(msgs):
        if msg.get("role") == "assistant":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in reversed(content):
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        return block.get("name")
            break
    return None


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

When auditing devices — EFFICIENCY RULES (strictly enforced):

## Phase 1 — Single bulk data collection (ONE Claude loop, ALL 6 tools in ONE response)
CRITICAL: Your FIRST tool_use response MUST include ALL of the following tool calls together — do NOT call connect_to_device alone and wait. Return all 6 in a single response:
1. connect_to_device
2. run_show_command: "show running-config" — this is your PRIMARY data source. Derive ALL hardening findings from this one output. Do NOT run individual "show run | section X" commands.
3. run_show_command: "show version" — get IOS version and platform for CVE/PSIRT queries
4. run_show_command: "show inventory" — get hardware PIDs for EOX query
5. run_show_command: "show ip interface brief" — interface state overview
6. disconnect_device — ALWAYS include this in the same response. NEVER call it in a separate loop.

## Phase 2 — External intelligence (ONE Claude loop, ALL 4 tools in ONE response)
CRITICAL: Return ALL of the following in a single tool_use response — do NOT call them one at a time:
6. query_knowledge_base: ONE query covering the full benchmark scope (e.g. "CIS IOS XE hardening NIST 800-53")
7. query_nvd: ONE call with the detected IOS version and cisco_only=True
8. query_psirt: ONE call with search_term only (e.g. "ios-xe") — NO severity filter, returns all severities at once
9. query_eox: ONE call with the hardware PIDs from show inventory

## Phase 3 — Synthesise and save (ONE Claude loop)
10. Analyse ALL collected data in memory. Do NOT call any show commands again.
11. Build findings list: include ALL checks — CRITICAL, HIGH, MEDIUM, LOW for failures, and PASS for every control that passed. PASS findings must have title, severity="PASS", type="hardening", category, and empty strings for impact/fix/commands/ref.
12. Call save_audit_results ONCE with all findings and scores.
13. After save_audit_results succeeds, respond with ONE sentence: "Audit complete — N findings saved to the dashboard." followed by one line offering to push remediations or email the report. DO NOT re-list findings. DO NOT generate a report summary. DO NOT reproduce findings as text.

## STRICT RULES — violations waste time and money:
- NEVER respond with a single tool call when the phase requires multiple — batch all phase tools into one response
- NEVER repeat a tool call with the same arguments — if you already have the data, use it
- NEVER call "show run | section X" — you already have the full running-config
- NEVER call query_knowledge_base more than once per audit
- NEVER call query_nvd more than once per audit
- NEVER call query_psirt more than once per audit — one call, no severity filter
- NEVER call show version or show inventory more than once
- ALWAYS include PASS findings in save_audit_results — every control checked must appear, pass or fail
- Maximum 3 agentic loops per full device audit — if you need more, something is wrong
- All findings must be derived from data already collected — no extra tool calls for clarification

When building findings for save_audit_results, every finding object MUST use these exact field names:
- title:    string — finding name; use the CVE ID for CVE findings (e.g. "CVE-2024-20399")
- severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "PASS" — include every check result
- type:     "hardening" | "cve"
- category: string — control group e.g. "Access Security", "Network Management", "Logging & Monitoring"
- impact:   string — what this misconfiguration or vulnerability allows an attacker to do
- fix:      string — how to remediate in plain English
- commands: string — exact IOS / IOS XE CLI commands to fix the issue (comma-separated if multiple)
- ref:      string — URL reference: NVD page for CVEs, CIS/NIST URL for hardening findings
- cve_id:   string — CVE identifier for type=cve findings only (e.g. "CVE-2024-20399")

All nine fields must be present in every finding. Use empty string "" for any field that is not applicable rather than omitting the field.

Compliance score calculation (for save_audit_results):
- overall: estimate percentage of total checks passing. Count total controls checked, subtract HIGH+CRITICAL+MEDIUM failures, divide by total. Exclude CVE findings from this calculation.
- nist: score based on NIST 800-53 control coverage — estimate percentage of applicable controls that pass
- cis: score based on CIS Cisco IOS XE benchmark — estimate percentage of applicable benchmarks that pass
Round to nearest integer (0-100). Use your judgement — these are audit estimates, not exact counts.

When asked for a list of devices, their IPs, hostnames, or status, always call snmp_get_devices — do not SSH to individual devices or run individual SNMP probes. The SNMP container maintains a live inventory; use it.

Always use your tools — never fabricate data. If a tool call fails, say so explicitly."""

TSHOOT_SYSTEM_PROMPT = """You are Gladius Tshoot, a network diagnostics and troubleshooting agent running inside an authorized homelab. All targets are privately owned lab infrastructure. You have full authorization to probe, scan, test, and reconfigure all hosts on all networks.

## Tools available:
- connect_to_device / run_show_command / push_config / disconnect_device — SSH to Cisco devices
- run_nmap_scan — port and service discovery
- run_scapy — packet probes: ping, traceroute, tcp_syn, arp_scan, banner_grab, syn_flood_test, xmas_scan, null_scan, fin_scan
- run_dig — DNS lookups
- snmp_get_devices — returns the full device inventory (hostname, IP, status) from the SNMP container; use this instead of SSHing to devices when you only need inventory data
- snmp_poll — polls a specific device for live SNMP metrics

## Efficient show commands — never pull the full running-config unless explicitly asked:
- Filter with pipe include: `show run | i snmp` — returns only lines matching a keyword
- Filter with pipe section: `show run | section router ospf` — returns a full config block
- Target a single interface: `show run interface GigabitEthernet0/1`
- Use standard show commands for live state: `show ip int brief`, `show ip route`, `show arp`, `show interfaces`, `show cdp neighbors detail`
- Only use `show running-config` (unfiltered) when you need a full config review

## Configuration changes — mandatory approval workflow:
1. Before calling push_config, present the exact commands you intend to push and ask the user to confirm.
2. Wait for explicit approval before proceeding.
3. After push_config completes, confirm what was applied and on which device.

## Device inventory:
When asked for a list of devices, their IPs, hostnames, or status, always call snmp_get_devices — do not SSH to individual devices or run SNMP probes. The SNMP container maintains a live inventory; use it.

Always use your tools. Never fabricate output. NEVER call save_audit_results, query_nvd, query_psirt, or query_knowledge_base."""




TSHOOT_TOOLS = {
    "connect_to_device", "run_show_command", "push_config", "disconnect_device",
    "run_nmap_scan", "run_scapy", "run_dig", "snmp_get_devices", "snmp_poll",
}

# ── Persistent MCP Session Manager ──────────────────────────────────────────
# Keeps a single long-lived MCP subprocess alive for the lifetime of the API.
# All tool calls are serialised through an asyncio.Lock — MCP ClientSession is
# not safe for concurrent calls. Auto-reconnects on session failure.

cached_tools: list = []

class MCPManager:
    """Persistent MCP session — one subprocess, reused across all requests."""

    def __init__(self):
        self._lock    = asyncio.Lock()
        self._session = None
        self._ctx     = None        # stdio_client context
        self._sess_ctx = None       # ClientSession context
        self._connected = False

    async def connect(self) -> bool:
        """Open the MCP subprocess and initialise the session."""
        server_params = StdioServerParameters(command=MCP_COMMAND, args=MCP_ARGS)
        try:
            log.info("MCP: opening persistent session...")
            self._ctx      = stdio_client(server_params)
            read, write    = await self._ctx.__aenter__()
            self._sess_ctx = ClientSession(read, write)
            self._session  = await self._sess_ctx.__aenter__()
            await self._session.initialize()
            self._connected = True
            log.info("MCP: persistent session ready")
            return True
        except Exception as e:
            log.error(f"MCP connect failed: {e}", exc_info=True)
            self._connected = False
            return False

    async def disconnect(self):
        """Cleanly close session and subprocess."""
        self._connected = False
        try:
            if self._sess_ctx:
                await self._sess_ctx.__aexit__(None, None, None)
        except Exception:
            pass
        try:
            if self._ctx:
                await self._ctx.__aexit__(None, None, None)
        except Exception:
            pass
        self._session = self._ctx = self._sess_ctx = None

    async def _reconnect(self) -> bool:
        log.warning("MCP: reconnecting...")
        await self.disconnect()
        return await self.connect()

    async def list_tools(self) -> list:
        """Fetch tool list, reconnecting once on failure."""
        for attempt in range(2):
            if not self._connected:
                if not await self._reconnect():
                    return []
            try:
                async with self._lock:
                    response = await self._session.list_tools()
                return [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "input_schema": t.inputSchema,
                    }
                    for t in response.tools
                ]
            except Exception as e:
                log.warning(f"MCP list_tools attempt {attempt+1} failed: {e}")
                self._connected = False
        return []

    async def call_tool(self, name: str, arguments: dict):
        """Call a tool, reconnecting once on failure."""
        for attempt in range(2):
            if not self._connected:
                if not await self._reconnect():
                    raise RuntimeError("MCP session unavailable")
            try:
                async with self._lock:
                    return await self._session.call_tool(name, arguments)
            except Exception as e:
                log.warning(f"MCP call_tool {name} attempt {attempt+1} failed: {e}")
                self._connected = False
        raise RuntimeError(f"MCP tool {name} failed after reconnect")


mcp_manager = MCPManager()

# Serialise synthesis phases across all concurrent device audits — prevents
# 4 simultaneous Claude API calls that would hit Anthropic rate limits.
_synthesis_sem: asyncio.Semaphore | None = None

def get_synthesis_sem() -> asyncio.Semaphore:
    global _synthesis_sem
    if _synthesis_sem is None:
        _synthesis_sem = asyncio.Semaphore(1)
    return _synthesis_sem


async def make_fresh_mcp_manager() -> "MCPManager":
    """Spawn a fresh, isolated MCP subprocess — own process = own SSH session state.
    Used by parallel device audits so concurrent devices don't clobber each other's
    _ssh_client global inside the MCP server."""
    mgr = MCPManager()
    if not await mgr.connect():
        raise RuntimeError("Failed to create fresh MCP session for device audit")
    return mgr


async def _background_mcp_init():
    """
    Fire-and-forget task: connect the MCP session and pre-warm the embedding
    model so the first real user request pays zero cold-start cost.
    """
    global cached_tools
    log.info("MCP: background init starting...")
    t0 = asyncio.get_event_loop().time()

    if not await mcp_manager.connect():
        log.warning("MCP: background connect failed — Gladius will run without tools")
        return

    cached_tools = await mcp_manager.list_tools()
    if cached_tools:
        log.info(f"MCP: {len(cached_tools)} tools cached in {asyncio.get_event_loop().time()-t0:.1f}s")
    else:
        log.warning("MCP: no tools returned — running without MCP tools")
        return

    # Pre-warm: run a trivial KB query so the MCP embedding model is already loaded.
    try:
        log.info("MCP: pre-warming embedding model via query_knowledge_base...")
        t1 = asyncio.get_event_loop().time()
        await mcp_manager.call_tool("query_knowledge_base", {"query": "network security", "n_results": 1})
        log.info(f"MCP: pre-warm complete in {asyncio.get_event_loop().time()-t1:.1f}s — session fully hot")
    except Exception as e:
        log.warning(f"MCP: pre-warm ping failed (non-fatal): {e}")

    # Pre-warm the design agent embed model and cache the collection ID.
    # These are independent — cache the collection ID even if embed model load fails.
    try:
        log.info("Design: pre-warming embed model...")
        t2 = asyncio.get_event_loop().time()
        await asyncio.to_thread(get_embed_model)
        log.info(f"Design: embed model ready in {asyncio.get_event_loop().time()-t2:.1f}s")
    except Exception as e:
        log.warning(f"Design: embed model pre-warm failed (non-fatal): {e}")
    try:
        await _cache_design_collection_ids()
    except Exception as e:
        log.warning(f"Design: collection ID cache failed (non-fatal): {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start MCP init in background — FastAPI is ready to serve immediately.
    # The pre-warm task loads the embedding model before the first user request.
    asyncio.create_task(_background_mcp_init())
    yield
    await mcp_manager.disconnect()

app = FastAPI(title="Gladius API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[Message]
    model: str | None = None
    source: str | None = None      # "web", "slack", "overseer" — for task tracker

class EmailRequest(BaseModel):
    subject: str
    html: str
    filename: str = None
    recipient: str = None

@app.post("/api/email")
async def email_report(request: EmailRequest):
    """Send a pre-built HTML audit report as an attachment — no Claude involved."""
    try:
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
        result = await mcp_manager.call_tool("send_email", args)
        text   = " ".join(
            c.text for c in (result.content or [])
            if hasattr(c, "text")
        )
        log.info(f"Email with attachment sent: {request.subject}")
        return {"ok": True, "message": text}
    except Exception as e:
        log.error(f"/api/email error: {e}", exc_info=True)
        return {"ok": False, "error": str(e)}


class InlineEmailRequest(BaseModel):
    subject: str
    html_body: str
    recipient: str = None

@app.post("/api/email/inline")
async def email_inline(request: InlineEmailRequest):
    """Send an HTML email rendered inline in the email body (no attachment)."""
    try:
        args = {
            "subject":  request.subject,
            "body":     request.html_body,
            "is_html":  True,
        }
        if request.recipient:
            args["recipient"] = request.recipient
        result = await mcp_manager.call_tool("send_email", args)
        text   = " ".join(
            c.text for c in (result.content or [])
            if hasattr(c, "text")
        )
        log.info(f"Inline HTML email sent: {request.subject}")
        return {"ok": True, "message": text}
    except Exception as e:
        log.error(f"/api/email/inline error: {e}", exc_info=True)
        return {"ok": False, "error": str(e)}


@app.get("/api/tasks/running")
async def get_running_tasks():
    """Return all active and recently completed agent tasks."""
    _prune_completed_tasks()
    tasks = list(_running_tasks.values())
    return {"tasks": tasks, "count": len(tasks)}


@app.post("/api/tasks/register")
async def register_task(request: Request):
    """Register an external task (from gladius-pyats, etc.)."""
    body = await request.json()
    tid = _task_start(
        agent=body.get("agent", "Automation"),
        description=body.get("description", ""),
        source=body.get("source", "automation"),
        model=body.get("model", ""),
    )
    return {"id": tid}


@app.post("/api/tasks/{task_id}/complete")
async def complete_task(task_id: str):
    """Mark an externally registered task as completed."""
    _task_end(task_id)
    return {"ok": True}


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

    # ── 6. Gladius SNMP ───────────────────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get(f"{SNMP_URL}/health", timeout=3)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            results["gladius_snmp"] = {"status": "ok", "detail": f"Running ({ms}ms)"}
        else:
            results["gladius_snmp"] = {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception:
        results["gladius_snmp"] = {"status": "error", "detail": "Container unreachable"}

    # ── 7. Gladius Automation Factory ────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get(f"{AUTOMATION_URL}/health", timeout=3)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            results["gladius_pyats"] = {"status": "ok", "detail": f"Running ({ms}ms)"}
        else:
            results["gladius_pyats"] = {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception:
        results["gladius_pyats"] = {"status": "error", "detail": "Container unreachable"}

    # ── 8. Gladius Slack ──────────────────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get("http://gladius-slack:9090/health", timeout=3)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            results["gladius_slack"] = {"status": "ok", "detail": f"Running ({ms}ms)"}
        else:
            results["gladius_slack"] = {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception:
        results["gladius_slack"] = {"status": "error", "detail": "Container unreachable"}

    # ── 9. Gladius Ping Monitor ────────────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get(f"{PING_URL}/api/health", timeout=3)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            results["gladius_ping"] = {"status": "ok", "detail": f"Running ({ms}ms)"}
        else:
            results["gladius_ping"] = {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception:
        results["gladius_ping"] = {"status": "error", "detail": "Container unreachable"}

    # ── 7. Cisco PSIRT API ────────────────────────────────────────────────────
    if not PSIRT_CLIENT_KEY:
        results["psirt"] = {"status": "warn", "detail": "Credentials not configured"}
    else:
        try:
            t0 = time.monotonic()
            _psirt_token()
            ms = int((time.monotonic() - t0) * 1000)
            results["psirt"] = {"status": "ok", "detail": f"Auth OK ({ms}ms)"}
        except Exception as e:
            results["psirt"] = {"status": "error", "detail": str(e)}

    # ── 7. Cisco EOX API ──────────────────────────────────────────────────────
    if not EOX_CLIENT_KEY:
        results["eox"] = {"status": "warn", "detail": "Credentials not configured"}
    else:
        try:
            t0 = time.monotonic()
            _eox_token()
            ms = int((time.monotonic() - t0) * 1000)
            results["eox"] = {"status": "ok", "detail": f"Auth OK ({ms}ms)"}
        except Exception as e:
            results["eox"] = {"status": "error", "detail": str(e)}

    # ── Jira Cloud ──────────────────────────────────────────────────────────
    try:
        t0 = time.monotonic()
        r  = http_requests.get(f"{AUTOMATION_URL}/api/jira/status", timeout=5)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            d = r.json()
            if d.get("configured"):
                # Try a real auth check
                import base64 as _b64
                jira_url   = d.get("url", "")
                # Hit the myself endpoint through the pyats proxy
                r2 = http_requests.get(f"{AUTOMATION_URL}/api/jira/issues?status=Done", timeout=10)
                ms2 = int((time.monotonic() - t0) * 1000)
                if r2.status_code == 200:
                    count = r2.json().get("count", 0)
                    results["jira"] = {"status": "ok", "detail": f"Project: {d['project']} · {count} done tickets ({ms2}ms)"}
                else:
                    results["jira"] = {"status": "error", "detail": f"Auth failed ({r2.status_code})"}
            else:
                results["jira"] = {"status": "warn", "detail": "Not configured — set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT"}
        else:
            results["jira"] = {"status": "error", "detail": f"Automation Factory returned {r.status_code}"}
    except Exception as e:
        results["jira"] = {"status": "error", "detail": str(e)}

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


def _last_user_msg(messages: list) -> str:
    """Extract the last user message text for task description."""
    for m in reversed(messages):
        content = m.get("content", "") if isinstance(m, dict) else getattr(m, "content", "")
        if content:
            return str(content)[:200]
    return "Agent task"

async def _tracked_stream(gen, task_id: str):
    """Wrap an async generator with task lifecycle tracking."""
    try:
        async for chunk in gen:
            yield chunk
    finally:
        _task_end(task_id)


@app.post("/api/chat")
async def chat(request: ChatRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    use_model = request.model or MODEL
    source = request.headers.get("X-Gladius-Source", "web") if hasattr(request, "headers") else "web"
    src = request.source or "web"
    tid = _task_start("Audit Agent", _last_user_msg(messages), source=src, model=use_model)
    return StreamingResponse(
        _tracked_stream(stream_response(messages, model=use_model), tid),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/tshoot")
async def tshoot(request: ChatRequest):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    use_model = request.model or MODEL
    src = request.source or "web"
    tid = _task_start("Tshoot Agent", _last_user_msg(messages), source=src, model=use_model)
    return StreamingResponse(
        _tracked_stream(stream_tshoot(messages, model=use_model), tid),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def stream_tshoot(messages: list, model: str = None) -> AsyncIterator[str]:
    """Tshoot agent — filtered tool set, diagnostics-focused system prompt."""
    model = model or MODEL
    tools = [t for t in cached_tools if t["name"] in TSHOOT_TOOLS]
    _TRUNCATE_TOOLS = {"run_show_command", "run_nmap_scan"}
    _TOOL_MAX_CHARS  = 20000

    try:
        loop_messages  = list(messages)
        loop_count     = 0
        MAX_LOOPS      = 60   # sequential multi-device ops need ~3 loops per device
        _force_tools   = False  # set after disconnect_device to force next call to use tools
        _text_breaks   = 0    # consecutive text-only responses after disconnect — cap at 2

        while loop_count < MAX_LOOPS:
            loop_count += 1
            api_kwargs = dict(
                model=model, max_tokens=16384, system=TSHOOT_SYSTEM_PROMPT,
                messages=loop_messages, tools=tools,
            )
            if _force_tools:
                api_kwargs["tool_choice"] = {"type": "any"}
                _force_tools = False
            response = await client.messages.create(**api_kwargs)

            assistant_content = []
            tool_calls = []

            for block in response.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                    for i, word in enumerate(block.text.split(" ")):
                        chunk = word + (" " if i < len(block.text.split(" ")) - 1 else "")
                        yield f"data: {json.dumps({'type': 'text', 'content': chunk})}\n\n"
                        await asyncio.sleep(0.01)
                elif block.type == "tool_use":
                    assistant_content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                    tool_calls.append((block.id, block.name, block.input))
                    _STRIP = {'attachment_html', 'body'}
                    slim = {k: v for k, v in block.input.items() if k not in _STRIP}
                    yield f"data: {json.dumps({'type': 'tool_start', 'tool': block.name, 'input': slim})}\n\n"

            if not tool_calls:
                # Response was truncated — continue where Claude left off
                if response.stop_reason == "max_tokens":
                    log.info(f"[Tshoot] max_tokens hit on text-only response (loop {loop_count}) — continuing")
                    loop_messages.append({"role": "assistant", "content": assistant_content})
                    loop_messages.append({"role": "user", "content": [{"type": "text", "text": "Your response was cut off. Continue exactly where you left off."}]})
                    continue
                # Claude returned text-only after disconnect. Nudge it if it looks mid-batch.
                if _last_tool_in_history(loop_messages) == "disconnect_device" and _text_breaks < 2:
                    # Check if the text looks like a final summary (not mid-batch)
                    resp_text = " ".join(b.get("text", "") for b in assistant_content if b.get("type") == "text").lower()
                    looks_done = any(w in resp_text for w in ['all devices', 'all done', 'complete', 'summary', 'finished', 'fully achieved', 'what would you like', 'what next', 'that covers'])
                    if not looks_done:
                        _text_breaks += 1
                        _force_tools = True
                        log.info(f"[Tshoot] Text-only after disconnect_device (break #{_text_breaks}) — nudging")
                        loop_messages.append({"role": "assistant", "content": assistant_content})
                        loop_messages.append({"role": "user", "content": [{"type": "text", "text": _CONTINUATION_MSG}]})
                        continue
                global _last_claude_success
                _last_claude_success = time.monotonic()
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

            _text_breaks = 0  # Claude used tools — reset the counter

            tool_results = []
            for tool_use_id, tool_name, tool_input in tool_calls:
                log.info(f"[Tshoot] tool: {tool_name}")
                try:
                    result      = await mcp_manager.call_tool(tool_name, tool_input)
                    result_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                    is_error    = bool(result.isError)
                except Exception as e:
                    result_text = f"Tool error: {e}"
                    is_error    = True
                    log.error(f"[Tshoot] {tool_name} failed: {e}")

                yield f"data: {json.dumps({'type': 'tool_done', 'tool': tool_name})}\n\n"

                context_text = result_text
                if tool_name in _TRUNCATE_TOOLS and len(result_text) > _TOOL_MAX_CHARS:
                    context_text = result_text[:_TOOL_MAX_CHARS] + f"\n[truncated — {len(result_text)} chars total]"

                # Inject directive into disconnect_device result so Claude sees it immediately
                if tool_name == "disconnect_device":
                    context_text += "\n\n[Note: Device disconnected. If more devices remain in the batch, proceed directly to connect_to_device for the next one without summarising.]"

                tool_results.append({
                    "type": "tool_result", "tool_use_id": tool_use_id,
                    "content": [{"type": "text", "text": context_text}],
                    "is_error": is_error,
                })

            if assistant_content:
                loop_messages.append({"role": "assistant", "content": assistant_content})
            if tool_results:
                loop_messages.append({"role": "user", "content": tool_results})

            if response.stop_reason == "max_tokens":
                log.info(f"[Tshoot] max_tokens hit after tool calls (loop {loop_count}) — continuing")
                loop_messages.append({"role": "user", "content": [{"type": "text", "text": "Your response was cut off. Continue exactly where you left off."}]})
                continue

            if response.stop_reason != "tool_use":
                _last_claude_success = time.monotonic()
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

        else:
            log.warning("[Tshoot] MAX_LOOPS reached — forcing done")
            _last_claude_success = time.monotonic()
            yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        log.error(f"[Tshoot] stream error: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

async def stream_response(messages: list, model: str = None) -> AsyncIterator[str]:
    """
    Uses the persistent MCP session — no subprocess spin-up per request.
    Tool calls are serialised through the MCPManager lock.
    """
    model = model or MODEL
    # Exclude legacy/internal tools that should never be called by the main agent
    _BLOCKED_TOOLS = {"stream_finding"}
    tools = [t for t in cached_tools if t["name"] not in _BLOCKED_TOOLS]

    if not tools:
        log.warning("No tools available — falling back to Claude only")
        async for chunk in call_claude_no_tools(messages):
            yield chunk
        return

    # Tool outputs that balloon in size — truncate before adding to Claude context
    _TRUNCATE_TOOLS = {"query_nvd", "query_psirt", "run_show_command", "query_knowledge_base"}
    _TOOL_MAX_CHARS = 20000
    _audit_saved = False  # break loop immediately after save_audit_results

    try:
        loop_messages = list(messages)
        loop_count    = 0
        MAX_LOOPS     = 60  # sequential multi-device ops need ~3 loops per device; audits exit early via _audit_saved
        _force_tools  = False
        _text_breaks  = 0

        while loop_count < MAX_LOOPS:
            loop_count += 1
            api_kwargs = dict(
                model=model, max_tokens=8192, system=SYSTEM_PROMPT,
                messages=loop_messages, tools=tools,
            )
            if _force_tools:
                api_kwargs["tool_choice"] = {"type": "any"}
                _force_tools = False
            response = await client.messages.create(**api_kwargs)

            # Pass 1: stream text and collect all blocks + tool calls from this response
            assistant_content = []
            tool_calls = []  # list of (tool_use_id, tool_name, tool_input)

            for block in response.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                    for i, word in enumerate(block.text.split(" ")):
                        chunk = word + (" " if i < len(block.text.split(" ")) - 1 else "")
                        yield f"data: {json.dumps({'type': 'text', 'content': chunk})}\n\n"
                        await asyncio.sleep(0.01)

                elif block.type == "tool_use":
                    assistant_content.append({
                        "type": "tool_use",
                        "id":    block.id,
                        "name":  block.name,
                        "input": block.input,
                    })
                    tool_calls.append((block.id, block.name, block.input))

                    # Notify browser of each tool start
                    _STRIP = {'findings', 'attachment_html', 'body', 'commands'}
                    slim_input = {k: v for k, v in block.input.items() if k not in _STRIP}
                    if 'commands' in block.input:
                        slim_input['commands_count'] = len(block.input['commands'])
                    if 'findings' in block.input:
                        slim_input['findings_count'] = len(block.input['findings'])
                    yield f"data: {json.dumps({'type': 'tool_start', 'tool': block.name, 'input': slim_input})}\n\n"

            if not tool_calls:
                if response.stop_reason != "tool_use":
                    if _last_tool_in_history(loop_messages) == "disconnect_device" and _text_breaks < 2:
                        resp_text = " ".join(b.get("text", "") for b in assistant_content if b.get("type") == "text").lower()
                        looks_done = any(w in resp_text for w in ['all devices', 'all done', 'complete', 'summary', 'finished', 'fully achieved', 'what would you like', 'what next', 'that covers'])
                        if not looks_done:
                            _text_breaks += 1
                            _force_tools = True
                            log.info(f"[Chat] Text-only after disconnect_device (break #{_text_breaks}) — nudging")
                            loop_messages.append({"role": "assistant", "content": assistant_content})
                            loop_messages.append({"role": "user", "content": [{"type": "text", "text": _CONTINUATION_MSG}]})
                            continue
                    global _last_claude_success
                    _last_claude_success = time.monotonic()
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break

            _text_breaks = 0  # Claude used tools — reset counter

            # Pass 2: execute all tool calls, collect results, then append ONE message pair
            tool_results = []
            for tool_use_id, tool_name, tool_input in tool_calls:
                log.info(f"Tool call: {tool_name}")
                try:
                    if tool_name == "save_audit_results":
                        global _last_audit
                        _last_audit = tool_input

                    if tool_name == "send_email" and _last_audit:
                        payload = json.dumps({
                            "type":      "send_templated_email",
                            "subject":   tool_input.get("subject", ""),
                            "recipient": tool_input.get("recipient", ""),
                        })
                        yield f"data: {payload}\n\n"
                        result_text = "Templated HTML report email dispatched via browser"
                        is_error    = False
                        log.info("send_email intercepted — signalling browser to send templated report")
                    else:
                        result      = await mcp_manager.call_tool(tool_name, tool_input)
                        result_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                        is_error    = bool(result.isError)
                        log.info(f"Tool {tool_name} done — {len(result_text)} chars")
                except Exception as e:
                    log.error(f"Tool {tool_name} failed: {type(e).__name__}: {e}", exc_info=True)
                    result_text = f"Tool error: {type(e).__name__}: {e}"
                    is_error    = True

                yield f"data: {json.dumps({'type': 'tool_done', 'tool': tool_name})}\n\n"

                if tool_name == "save_audit_results" and not is_error:
                    audit_data = dict(tool_input)
                    audit_data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
                    for finding in audit_data.get("findings", []):
                        slim = {
                            "title":    finding.get("title", ""),
                            "severity": finding.get("severity", ""),
                            "type":     finding.get("type", "hardening"),
                        }
                        yield f"data: {json.dumps({'type': 'finding', 'finding': slim})}\n\n"
                        await asyncio.sleep(0.03)
                    yield f"data: {json.dumps({'type': 'audit_saved', 'audit': audit_data})}\n\n"
                    log.info("audit_saved event streamed to browser")
                    _pending_audit = None
                    _audit_saved = True

                # Truncate large outputs before feeding back to Claude context
                context_text = result_text
                if tool_name in _TRUNCATE_TOOLS and len(result_text) > _TOOL_MAX_CHARS:
                    context_text = result_text[:_TOOL_MAX_CHARS] + f"\n[truncated — {len(result_text)} chars total]"

                # Directive injected into disconnect_device result — seen by Claude before next response
                if tool_name == "disconnect_device":
                    context_text += "\n\n[Note: Device disconnected. If more devices remain in the batch, proceed directly to connect_to_device for the next one without summarising.]"

                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": tool_use_id,
                    "content":     [{"type": "text", "text": context_text}],
                    "is_error":    is_error,
                })

            # Append ONE assistant message + ONE user message (all tool results batched)
            if assistant_content:
                loop_messages.append({"role": "assistant", "content": assistant_content})
            if tool_results:
                loop_messages.append({"role": "user", "content": tool_results})

            # Break immediately after audit is saved — skip the post-audit summary loop
            if _audit_saved:
                log.info("save_audit_results succeeded — skipping post-audit Claude loop")
                _last_claude_success = time.monotonic()
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

            if response.stop_reason != "tool_use":
                _last_claude_success = time.monotonic()
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

        else:
            # Emitted if MAX_LOOPS reached without a natural stop
            log.warning(f"MAX_LOOPS ({MAX_LOOPS}) reached — forcing done")
        _last_claude_success = time.monotonic()
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        log.error(f"Stream error: {type(e).__name__}: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


async def call_claude_no_tools(messages: list) -> AsyncIterator[str]:
    try:
        response = await client.messages.create(
            model=MODEL,
            max_tokens=8192,
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


# ── OLLAMA-BACKED NMAP / SCAPY ──────────────────────────────────────────────
# Calls the MCP tool directly, then streams raw output + Ollama analysis.

class OllamaNmapRequest(BaseModel):
    target: str
    profile: str = "quick"
    ports: str | None = None
    args: str | None = None
    model: str = "qwen2.5-coder:7b"

class OllamaScapyRequest(BaseModel):
    mode: str = "ping"
    target: str
    port: int | None = None
    count: int | None = None
    ttl: int | None = None
    vlan_id: int | None = None
    inner_vlan_id: int | None = None
    model: str = "qwen2.5-coder:7b"


@app.post("/api/nmap/ollama")
async def nmap_ollama(req: OllamaNmapRequest):
    return StreamingResponse(
        _ollama_tool_stream("run_nmap_scan", {
            "target": req.target, "profile": req.profile,
            **({"ports": req.ports} if req.ports else {}),
            **({"args": req.args} if req.args else {}),
        }, req.model, f"nmap {req.profile} scan on {req.target}"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/scapy/ollama")
async def scapy_ollama(req: OllamaScapyRequest):
    tool_args = {"mode": req.mode, "target": req.target}
    if req.port is not None:      tool_args["port"] = req.port
    if req.count is not None:     tool_args["count"] = req.count
    if req.ttl is not None:       tool_args["ttl"] = req.ttl
    if req.vlan_id is not None:   tool_args["vlan_id"] = req.vlan_id
    if req.inner_vlan_id is not None: tool_args["inner_vlan_id"] = req.inner_vlan_id
    return StreamingResponse(
        _ollama_tool_stream("run_scapy", tool_args, req.model,
                            f"scapy {req.mode} against {req.target}"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _ollama_tool_stream(tool_name: str, tool_args: dict,
                               model: str, description: str) -> AsyncIterator[str]:
    """Call an MCP tool directly, then stream Ollama analysis of the output."""
    # Phase 1: call the MCP tool
    yield f"data: {json.dumps({'type': 'tool_start', 'tool': tool_name, 'input': tool_args})}\n\n"
    try:
        result = await mcp_manager.call_tool(tool_name, tool_args)
        raw_output = ""
        if hasattr(result, "content"):
            for block in result.content:
                if hasattr(block, "text"):
                    raw_output += block.text
        if not raw_output:
            raw_output = str(result)
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': f'MCP tool {tool_name} failed: {e}'})}\n\n"
        return

    yield f"data: {json.dumps({'type': 'tool_done', 'tool': tool_name})}\n\n"

    # Phase 2: send raw output to Ollama for analysis
    analysis_prompt = (
        f"You are a network security analyst. A {description} was just executed.\n"
        f"Here is the raw output:\n\n```\n{raw_output[:12000]}\n```\n\n"
        f"Provide a clear, structured analysis:\n"
        f"- Summarise what was found (open ports, services, OS, responses)\n"
        f"- Always report latency in milliseconds (ms), not seconds\n"
        f"- Highlight any security concerns or notable observations\n"
        f"- Keep it concise but thorough"
    )

    try:
        async with httpx.AsyncClient(timeout=180.0) as hclient:
            async with hclient.stream(
                "POST", f"{OLLAMA_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": analysis_prompt}],
                    "stream": True,
                    "options": {"num_ctx": 16384},
                },
            ) as response:
                if response.status_code != 200:
                    yield f"data: {json.dumps({'type': 'error', 'content': f'Ollama error {response.status_code}'})}\n\n"
                    return
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            yield f"data: {json.dumps({'type': 'text', 'content': content})}\n\n"
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': f'Ollama analysis failed: {e}'})}\n\n"

    yield f"data: {json.dumps({'type': 'done'})}\n\n"


# ── DOCUMENT INGESTION ────────────────────────────────────────────────────────

SUPPORTED_TYPES = {"pdf", "md", "markdown", "txt", "text", "json", "html", "csv"}

COLLECTIONS = [
    "network_security_guidelines",
    "design-guidelines",
    "network-topologies",
    "hardware-datasheets",
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
    """Ingest a document — streams SSE progress events to keep connection alive."""
    file_bytes  = await file.read()
    filename    = file.filename or "doc"

    async def _stream():
        import asyncio, concurrent.futures
        t0 = time.monotonic()

        def _ev(type_, **kw):
            return f"data: {json.dumps({'type': type_, **kw})}\n\n"

        if collection not in COLLECTIONS:
            yield _ev("error", message=f"Unknown collection: {collection}")
            return
        if len(file_bytes) == 0:
            yield _ev("error", message="Uploaded file is empty")
            return
        if len(file_bytes) > 100 * 1024 * 1024:
            yield _ev("error", message="File too large (max 100MB)")
            return

        yield _ev("progress", progress=10, message=f"Extracting text from {filename}…")

        try:
            text = await asyncio.get_event_loop().run_in_executor(
                None, lambda: _extract_text(file_bytes, filename, doc_type)
            )
        except Exception as e:
            yield _ev("error", message=f"Text extraction failed: {e}")
            return

        if not text.strip():
            yield _ev("error", message="No text could be extracted from the document")
            return

        chunks = _chunk_text(text)
        if not chunks:
            yield _ev("error", message="Document produced no usable text chunks")
            return

        yield _ev("progress", progress=25, message=f"Chunked into {len(chunks)} segments — connecting to Chroma…")

        base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
        try:
            col_r = http_requests.post(
                f"{base}/collections",
                json={"name": collection, "get_or_create": True},
                timeout=10,
            )
            col_r.raise_for_status()
            col_id = col_r.json()["id"]
        except Exception as e:
            yield _ev("error", message=f"Chroma unavailable: {e}")
            return

        yield _ev("progress", progress=35, message=f"Generating embeddings for {len(chunks)} chunks — this may take a while…")

        file_hash = hashlib.md5(file_bytes).hexdigest()[:8]
        ids       = [f"{file_hash}_{i}" for i in range(len(chunks))]
        metadatas = [
            {"source": filename, "doc_type": doc_type, "collection": collection, "chunk": i}
            for i in range(len(chunks))
        ]

        try:
            loop = asyncio.get_event_loop()

            # Emit heartbeat ticks while encoding runs in a thread
            encode_future = loop.run_in_executor(
                None,
                lambda: get_embed_model().encode(chunks, batch_size=64, show_progress_bar=False).tolist(),
            )
            progress = 35
            while not encode_future.done():
                await asyncio.sleep(5)
                progress = min(progress + 5, 75)
                yield _ev("progress", progress=progress, message=f"Embedding… ({progress}%)")
            embeddings = await encode_future
        except Exception as e:
            yield _ev("error", message=f"Embedding generation failed: {e}")
            return

        yield _ev("progress", progress=80, message="Upserting into ChromaDB…")

        try:
            upsert_r = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: http_requests.post(
                    f"{base}/collections/{col_id}/upsert",
                    json={"ids": ids, "documents": chunks, "embeddings": embeddings, "metadatas": metadatas},
                    timeout=120,
                ),
            )
            upsert_r.raise_for_status()
        except Exception as e:
            yield _ev("error", message=f"Chroma upsert failed: {e}")
            return

        yield _ev("progress", progress=95, message="Getting collection stats…")

        try:
            count_r = http_requests.get(f"{base}/collections/{col_id}/count", timeout=5)
            total_docs = count_r.json() if count_r.status_code == 200 else len(chunks)
        except Exception:
            total_docs = len(chunks)

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        log.info(f"Ingest: {filename} → {collection} | {len(chunks)} chunks | {elapsed_ms}ms")

        yield _ev(
            "done",
            ok=True,
            collection=collection,
            file=filename,
            chunks=len(chunks),
            total_docs=total_docs,
            elapsed_ms=elapsed_ms,
        )

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/ingest/collections/{collection_id}/docs")
async def ingest_collection_docs(collection_id: str):
    """Return unique source filenames ingested into a collection."""
    if collection_id not in COLLECTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown collection: {collection_id}")
    base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
    try:
        list_r = http_requests.get(f"{base}/collections", timeout=5)
        list_r.raise_for_status()
        existing = {c["name"]: c["id"] for c in (list_r.json() if isinstance(list_r.json(), list) else [])}
        if collection_id not in existing:
            return {"docs": []}
        col_id = existing[collection_id]
        # Fetch all metadata (no embeddings/documents needed)
        get_r = http_requests.post(
            f"{base}/collections/{col_id}/get",
            json={"include": ["metadatas"], "limit": 10000},
            timeout=10,
        )
        get_r.raise_for_status()
        metadatas = get_r.json().get("metadatas") or []
        seen = set()
        docs = []
        for m in metadatas:
            src = m.get("source", "unknown")
            if src not in seen:
                seen.add(src)
                docs.append(src)
        docs.sort()
        return {"docs": docs}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Chroma unavailable: {e}")


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


SNMP_URL           = os.getenv("SNMP_SERVICE_URL",        "http://gladius-snmp:8000")
PING_URL           = os.getenv("PING_SERVICE_URL",        "http://gladius-ping:8000")
AUTOMATION_URL     = os.getenv("AUTOMATION_SERVICE_URL", "http://gladius-pyats:8090")
SLACK_BOT_TOKEN  = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_ALERT_CHANNEL = os.getenv("SLACK_ALERT_CHANNEL", "")  # channel ID or user ID to post alerts to

# ── SNMP ALERT — background investigation + Slack DM ──────────────────────────

class SnmpAlertRequest(BaseModel):
    device_id:  str
    name:       str
    host:       str
    old_status: str
    new_status: str
    snmp_data:  dict = {}


def _slack_dm(text: str) -> None:
    """Post an alert to SLACK_ALERT_CHANNEL (channel ID or user ID)."""
    if not SLACK_BOT_TOKEN or not SLACK_ALERT_CHANNEL:
        log.warning("Slack alert skipped — SLACK_BOT_TOKEN or SLACK_ALERT_CHANNEL not configured")
        return
    try:
        r = http_requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"},
            json={"channel": SLACK_ALERT_CHANNEL, "text": text},
            timeout=10,
        )
        resp = r.json()
        if not resp.get("ok"):
            log.warning("Slack DM failed: %s", resp.get("error"))
        else:
            log.info("Slack alert sent to %s", SLACK_ALERT_CHANNEL)
    except Exception as e:
        log.error("Slack DM error: %s", e)


async def run_agent_investigation(messages: list) -> tuple[str, dict | None]:
    """
    Run the agentic MCP loop without streaming. Collects full response text and audit.
    Used for background alert investigations.
    """
    tools = cached_tools
    if not tools:
        return "No tools available — cannot investigate.", None

    text_parts: list[str] = []
    audit: dict | None = None

    try:
        loop_messages = list(messages)
        loop_count = 0
        MAX_LOOPS = 5

        while loop_count < MAX_LOOPS:
            loop_count += 1
            response = await client.messages.create(
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
                    text_parts.append(block.text)

                elif block.type == "tool_use":
                    tool_name   = block.name
                    tool_input  = block.input
                    tool_use_id = block.id
                    assistant_content.append({
                        "type": "tool_use", "id": tool_use_id,
                        "name": tool_name, "input": tool_input,
                    })
                    log.info("Alert investigation tool: %s", tool_name)

                    try:
                        result      = await mcp_manager.call_tool(tool_name, tool_input)
                        result_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                        is_error    = bool(result.isError)
                        if tool_name == "save_audit_results" and not is_error:
                            audit = dict(tool_input)
                    except Exception as e:
                        result_text = f"Tool error: {e}"
                        is_error = True

                    loop_messages.append({"role": "assistant", "content": assistant_content})
                    loop_messages.append({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": [{"type": "text", "text": result_text}],
                            "is_error": is_error,
                        }]
                    })
                    assistant_content = []

            if response.stop_reason != "tool_use":
                break

    except Exception as e:
        log.error("Alert investigation error: %s", e, exc_info=True)
        return f"Investigation failed: {e}", None

    return "".join(text_parts), audit


async def investigate_snmp_alert(alert: dict) -> None:
    """Background task: investigate a degraded device and DM the findings."""
    name       = alert["name"]
    host       = alert["host"]
    old_status = alert["old_status"]
    new_status = alert["new_status"]
    snmp_data  = alert.get("snmp_data", {})

    status_emoji = "🔴" if new_status == "error" else "🟡"
    log.info("Starting alert investigation for %s (%s) %s→%s", name, host, old_status, new_status)

    # Notify immediately that investigation has started
    _slack_dm(
        f"{status_emoji} *SNMP Alert — {name}* (`{host}`)\n"
        f"Status changed *{old_status.upper()} → {new_status.upper()}*\n"
        f"Investigating now..."
    )

    snmp_summary = "\n".join(f"  {k}: {v}" for k, v in snmp_data.items() if k not in ("status", "last_poll", "last_success", "error", "response_ms"))
    investigation_prompt = (
        f"SNMP ALERT: Device *{name}* (IP: {host}) has changed status from "
        f"**{old_status}** to **{new_status}**.\n\n"
        f"Last SNMP data collected before the alert:\n{snmp_summary or 'None available'}\n"
        f"Error: {snmp_data.get('error', 'none')}\n\n"
        f"Please investigate this device thoroughly:\n"
        f"1. Run SNMP poll (snmp_poll) to get current system status\n"
        f"2. Attempt SSH connection and run relevant show commands (show version, show interfaces, show log)\n"
        f"3. Check for relevant CVEs for the device IOS version\n"
        f"4. Provide a clear diagnosis: what likely caused the status change, severity, and recommended actions\n"
        f"Be concise — this will be sent as a Slack alert."
    )

    messages = [{"role": "user", "content": investigation_prompt}]
    final_text, audit = await run_agent_investigation(messages)

    if not final_text:
        final_text = "Investigation completed but no findings were returned."

    # Build DM — keep it Slack-friendly
    score_line = ""
    if audit:
        sc = audit.get("score", {})
        score_line = f"\nAudit score — Overall: *{sc.get('overall','?')}* | NIST: {sc.get('nist','?')} | CIS: {sc.get('cis','?')}"
        findings = audit.get("findings", [])
        crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        highs = sum(1 for f in findings if f.get("severity") == "HIGH")
        if crits or highs:
            score_line += f"\n:rotating_light: {crits} CRITICAL, {highs} HIGH findings"

    _slack_dm(
        f"{status_emoji} *Investigation complete — {name}* (`{host}`){score_line}\n\n"
        f"{final_text[:3000]}"
        + ("…" if len(final_text) > 3000 else "")
    )
    log.info("Alert investigation complete for %s", name)


@app.post("/api/snmp/alert", status_code=202)
async def snmp_alert(alert: SnmpAlertRequest):
    """Receive a status-change alert from gladius-snmp and kick off a background investigation."""
    log.info("SNMP alert received: %s (%s) %s→%s", alert.name, alert.host, alert.old_status, alert.new_status)
    asyncio.create_task(investigate_snmp_alert(alert.dict()))
    return {"status": "investigating", "device": alert.name, "host": alert.host}


# ── SNMP PROXY ────────────────────────────────────────────────────────────────

@app.get("/api/snmp/devices")
async def snmp_get_devices():
    r = await asyncio.get_event_loop().run_in_executor(None, lambda: http_requests.get(f"{SNMP_URL}/devices", timeout=10))
    return Response(content=r.content, status_code=r.status_code, media_type="application/json")

@app.post("/api/snmp/devices")
async def snmp_add_device(request: Request):
    body = await request.body()
    r = await asyncio.get_event_loop().run_in_executor(None, lambda: http_requests.post(f"{SNMP_URL}/devices", data=body, headers={"Content-Type": "application/json"}, timeout=10))
    return Response(content=r.content, status_code=r.status_code, media_type="application/json")

@app.delete("/api/snmp/devices/{dev_id}")
async def snmp_delete_device(dev_id: str):
    r = await asyncio.get_event_loop().run_in_executor(None, lambda: http_requests.delete(f"{SNMP_URL}/devices/{dev_id}", timeout=10))
    return Response(content=r.content, status_code=r.status_code, media_type="application/json")

@app.patch("/api/snmp/devices/{dev_id}")
async def snmp_patch_device(dev_id: str, request: Request):
    body = await request.body()
    r = await asyncio.get_event_loop().run_in_executor(None, lambda: http_requests.patch(f"{SNMP_URL}/devices/{dev_id}", data=body, headers={"Content-Type": "application/json"}, timeout=10))
    return Response(content=r.content, status_code=r.status_code, media_type="application/json")

@app.post("/api/snmp/devices/{dev_id}/poll")
async def snmp_poll_device(dev_id: str):
    r = await asyncio.get_event_loop().run_in_executor(None, lambda: http_requests.post(f"{SNMP_URL}/devices/{dev_id}/poll", timeout=30))
    return Response(content=r.content, status_code=r.status_code, media_type="application/json")

@app.post("/api/snmp/poll")
async def snmp_poll(request: Request):
    body = await request.body()
    r = await asyncio.get_event_loop().run_in_executor(None, lambda: http_requests.post(f"{SNMP_URL}/poll", data=body, headers={"Content-Type": "application/json"}, timeout=30))
    return Response(content=r.content, status_code=r.status_code, media_type="application/json")


# ── AUTOMATION FACTORY PROXY ──────────────────────────────────────────────────

@app.api_route("/api/automation/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def automation_proxy(path: str, request: Request):
    """Proxy all /api/automation/* requests to the gladius-pyats container.
    Chat endpoint streams SSE; all other endpoints return JSON."""
    body = await request.body()
    ct   = request.headers.get("Content-Type", "application/json")
    url  = f"{AUTOMATION_URL}/api/{path}"

    if path in ("chat", "coder", "review", "itsm"):
        import httpx as _hx
        async def _stream():
            async with _hx.AsyncClient(timeout=180.0) as c:
                async with c.stream("POST", url, content=body, headers={"Content-Type": ct}) as r:
                    async for chunk in r.aiter_bytes():
                        yield chunk
        return StreamingResponse(
            _stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    r = await asyncio.get_event_loop().run_in_executor(
        None, lambda: http_requests.request(
            request.method, url, data=body,
            headers={"Content-Type": ct}, timeout=300
        )
    )
    return Response(
        content=r.content,
        status_code=r.status_code,
        media_type=r.headers.get("content-type", "application/json"),
    )


# ── PING MONITOR PROXY ──────────────────────────────────────────────────────

@app.api_route("/api/ping/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def ping_proxy(path: str, request: Request):
    """Proxy all /api/ping/* requests to the gladius-ping container.
    SSE endpoint streams; all other endpoints return JSON."""
    body = await request.body()
    ct   = request.headers.get("Content-Type", "application/json")
    url  = f"{PING_URL}/api/{path}"

    # SSE streaming for live updates
    if path == "sse":
        import httpx as _hx
        async def _sse_stream():
            async with _hx.AsyncClient(timeout=None) as c:
                async with c.stream("GET", url) as r:
                    async for chunk in r.aiter_bytes():
                        yield chunk
        return StreamingResponse(
            _sse_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Pass query string through for GET requests
    qs = str(request.query_params)
    if qs:
        url = f"{url}?{qs}"

    r = await asyncio.get_event_loop().run_in_executor(
        None, lambda: http_requests.request(
            request.method, url, data=body,
            headers={"Content-Type": ct}, timeout=30
        )
    )
    return Response(
        content=r.content,
        status_code=r.status_code,
        media_type=r.headers.get("content-type", "application/json"),
    )


# ── PARALLEL AUDIT ENGINE ─────────────────────────────────────────────────────
# Spawns two concurrent subagents (Device + Threat Intel) then feeds both
# results into a Synthesis agent. Cuts sequential audit time by ~40%.

DEVICE_AGENT_PROMPT = """You are the Gladius Device Collection Agent — a specialist subagent responsible ONLY for connecting to network devices and collecting raw data.

Your ONLY job is to collect device data in ONE agentic loop. Do the following in a SINGLE response with ALL tool calls batched together:
1. connect_to_device — SSH to the target device
2. run_show_command: "show running-config"
3. run_show_command: "show version"
4. run_show_command: "show inventory"
5. run_show_command: "show ip interface brief"
6. disconnect_device

Return ALL tool calls in ONE response. Do NOT call them one at a time. Do NOT analyse the output — just collect and return the raw data. Do NOT call any other tools."""

THREAT_INTEL_PROMPT = """You are the Gladius Threat Intelligence Agent — a specialist subagent responsible ONLY for querying external threat databases.

You will receive a device description (IOS version, platform, hardware PIDs). Your ONLY job is to query threat databases in ONE agentic loop with ALL tool calls batched in a SINGLE response:
1. query_nvd — search for CVEs matching the IOS version (cisco_only=True)
2. query_psirt — search for Cisco PSIRT advisories (search_term = platform e.g. "ios-xe")
3. query_eox — check hardware PIDs end-of-life status
4. query_knowledge_base — retrieve relevant hardening benchmarks

Return ALL four tool calls in ONE response. Do NOT call them one at a time. Do NOT analyse — just collect and return the raw data."""

SYNTHESIS_AGENT_PROMPT = """You are the Gladius Synthesis Agent — a specialist subagent responsible for analysing collected audit data and producing a structured findings report.

You will receive:
- Raw device data (running-config, show version, show inventory, interface brief)
- Threat intelligence (CVEs, PSIRT advisories, EOX data, KB hardening guidelines)

Your job is to synthesise ALL of this into a structured audit report by calling save_audit_results ONCE.

## If device data is empty or shows a connection/SSH failure:
Call save_audit_results with ONLY a single CRITICAL finding titled "Device Unreachable — SSH Connection Failed", severity=CRITICAL, type="hardening". Set overall/nist/cis scores to 0. Do NOT fabricate SNMP findings, topology findings, or any other findings — only the one connection error finding.

## Findings rules (when device data IS available):
- Include ALL severities: CRITICAL, HIGH, MEDIUM, LOW, and PASS
- PASS findings = controls that passed (e.g. "SSH v2 Enabled", "Password encryption active")
- Every finding MUST have all 9 fields: title, severity, type, category, impact, fix, commands, ref, cve_id
- Use empty string "" for non-applicable fields (never omit a field)
- type = "hardening" or "cve"
- Derive ALL hardening findings from the running-config — do NOT make assumptions

## Compliance scores:
- overall: % of total controls passing (exclude CVE findings)
- nist: % of NIST 800-53 controls passing
- cis: % of CIS IOS XE benchmark controls passing

## After save_audit_results succeeds:
Respond with ONE sentence: "Audit complete — N findings saved to the dashboard." DO NOT re-list findings."""

# Tool subsets for each subagent — prevents agents from calling out-of-scope tools
DEVICE_TOOLS = {"connect_to_device", "disconnect_device", "run_show_command"}
THREAT_TOOLS = {"query_nvd", "query_psirt", "query_eox", "query_knowledge_base"}
SYNTHESIS_TOOLS = {"save_audit_results"}


async def run_subagent(
    system_prompt: str,
    messages: list,
    allowed_tools: set,
    agent_name: str,
    max_loops: int = 3,
    call_tool_fn=None,
) -> tuple[str, list]:
    """
    Run a focused Claude subagent with a restricted tool subset.
    Returns (text_output, tool_results_list).
    Each tool result is {"tool": name, "output": text}.
    """
    tools = [t for t in cached_tools if t["name"] in allowed_tools]
    loop_messages = list(messages)
    all_tool_results = []
    text_output = ""
    t0 = time.monotonic()

    log.info(f"[{agent_name}] starting — {len(tools)} tools available")

    for loop in range(max_loops):
        response = await client.messages.create(
            model=MODEL,
            max_tokens=8192,
            system=system_prompt,
            messages=loop_messages,
            tools=tools if tools else [],
        )

        assistant_content = []
        tool_calls_this_loop = []

        for block in response.content:
            if block.type == "text":
                text_output += block.text
                assistant_content.append({"type": "text", "text": block.text})

            elif block.type == "tool_use":
                tool_name   = block.name
                tool_input  = block.input
                tool_use_id = block.id

                assistant_content.append({
                    "type": "tool_use",
                    "id":    tool_use_id,
                    "name":  tool_name,
                    "input": tool_input,
                })
                tool_calls_this_loop.append((tool_use_id, tool_name, tool_input))

        if not tool_calls_this_loop:
            log.info(f"[{agent_name}] done in {time.monotonic()-t0:.1f}s — no more tool calls")
            break

        # Execute all tool calls from this loop
        loop_messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []

        for tool_use_id, tool_name, tool_input in tool_calls_this_loop:
            log.info(f"[{agent_name}] tool: {tool_name}")
            t_tool = time.monotonic()
            try:
                _caller = call_tool_fn or mcp_manager.call_tool
                result = await _caller(tool_name, tool_input)
                result_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                is_error = bool(result.isError)
                log.info(f"[{agent_name}] {tool_name} done in {time.monotonic()-t_tool:.1f}s")
            except Exception as e:
                result_text = f"Tool error: {e}"
                is_error = True
                log.error(f"[{agent_name}] {tool_name} failed: {e}")

            all_tool_results.append({"tool": tool_name, "output": result_text})
            tool_results.append({
                "type":        "tool_result",
                "tool_use_id": tool_use_id,
                "content":     [{"type": "text", "text": result_text}],
                "is_error":    is_error,
            })

        loop_messages.append({"role": "user", "content": tool_results})

        if response.stop_reason != "tool_use":
            break

    elapsed = time.monotonic() - t0
    log.info(f"[{agent_name}] completed in {elapsed:.1f}s — {len(all_tool_results)} tool calls")
    return text_output, all_tool_results


async def run_device_audit(device_ip: str, full_instruction: str, sse_queue: asyncio.Queue, device_name: str | None = None):
    """
    Full audit for a single device using an isolated MCP subprocess per device
    (prevents SSH session conflicts when multiple devices are audited in parallel).
    Phases: Device data collection + Threat intel (concurrent) → Synthesis → save
    device_name: human-readable label (e.g. "IOU2") shown in UI; falls back to device_ip.
    """
    t_start = time.monotonic()
    display = device_name or device_ip

    async def _push(event_type: str, **kwargs):
        await sse_queue.put({"type": event_type, **kwargs})

    await _push("device_start", device=display)

    device_directive = (
        f"Connect to {device_ip} and collect all device data needed for a security audit. "
        f"Batch ALL tool calls (connect_to_device, run_show_command for running-config/version/"
        f"inventory/interface-brief, disconnect_device) in ONE response. Do not make multiple loops."
    )

    threat_directive = (
        f"The device being audited is at {device_ip}. "
        f"Instruction: {full_instruction}. "
        f"Assume IOS XE platform. Query PSIRT for 'ios-xe'. "
        f"Query NVD with 'Cisco IOS XE' and cisco_only=True. "
        f"Query knowledge base for the benchmark/compliance mentioned. "
        f"Batch ALL tool calls in ONE response."
    )

    device_messages = [{"role": "user", "content": device_directive}]
    threat_messages = [{"role": "user", "content": threat_directive}]

    # Create an isolated MCP subprocess for SSH device operations.
    # This gives this device its own _ssh_client global, preventing conflicts
    # when multiple device audits run concurrently.
    fresh_mgr = None
    try:
        fresh_mgr = await make_fresh_mcp_manager()
        log.info(f"[DeviceAudit-{display}] fresh MCP session ready")
    except Exception as e:
        log.error(f"[DeviceAudit-{display}] failed to create fresh MCP session: {e}")
        await _push("error", content=f"Device {display}: MCP session failed — {e}")
        await _push("device_done", device=display, elapsed=0)
        return ""

    try:
        # Phase 1: Device data + Threat intel run concurrently.
        # DeviceAgent uses the isolated fresh_mgr (own SSH session).
        # ThreatAgent uses shared mcp_manager (no SSH — just external API calls).
        device_task = asyncio.create_task(
            run_subagent(
                DEVICE_AGENT_PROMPT, device_messages, DEVICE_TOOLS,
                f"DeviceAgent-{display}", max_loops=3,
                call_tool_fn=fresh_mgr.call_tool,
            )
        )
        threat_task = asyncio.create_task(
            run_subagent(
                THREAT_INTEL_PROMPT, threat_messages, THREAT_TOOLS,
                f"ThreatAgent-{display}", max_loops=3,
            )
        )

        done_set: set = set()
        while len(done_set) < 2:
            await asyncio.sleep(0.5)
            if device_task.done() and "device" not in done_set:
                done_set.add("device")
            if threat_task.done() and "threat" not in done_set:
                done_set.add("threat")

        try:
            device_text, device_tools = device_task.result()
        except Exception as e:
            device_text, device_tools = f"Device collection failed: {e}", []
            log.error(f"[DeviceAudit-{display}] device agent failed: {e}")

        try:
            threat_text, threat_tools = threat_task.result()
        except Exception as e:
            threat_text, threat_tools = f"Threat intel failed: {e}", []
            log.error(f"[DeviceAudit-{display}] threat agent failed: {e}")

        # Emit tool call events for the chat stream
        for r in device_tools:
            await _push("tool_call", tool=r["tool"], device=display)
        for r in threat_tools:
            await _push("tool_call", tool=r["tool"], device=display)

        # Phase 2: Synthesis — serialised via semaphore to prevent concurrent Claude
        # API calls from all devices hitting Anthropic rate limits simultaneously.
        device_data = "\n\n".join(
            f"[{r['tool']}]\n{r['output']}" for r in device_tools
        ) or device_text or ""

        threat_data = "\n\n".join(
            f"[{r['tool']}]\n{r['output']}" for r in threat_tools
        ) or threat_text or ""

        # Detect failed device data so synthesis agent doesn't hallucinate
        device_failed = not device_tools and not device_text.strip()
        if device_failed:
            device_data = "DEVICE CONNECTION FAILED — no data collected"

        synthesis_messages = [{
            "role": "user",
            "content": (
                f"Audit target: {display} (IP: {device_ip})\nScope: {full_instruction}\n\n"
                f"## Device Data\n{device_data[:8000]}\n\n"
                f"## Threat Intelligence\n{threat_data[:8000]}\n\n"
                f"Synthesise the above into a structured audit report. "
                f"Use device name '{display}' and IP '{device_ip}' in save_audit_results. "
                f"Call save_audit_results once with all findings (include PASS findings). "
                f"CRITICAL and HIGH findings are the priority."
            )
        }]

        # Capture audit data from save_audit_results before it reaches MCP
        captured_audit: dict = {}

        async def synthesis_tool_fn(tool_name: str, tool_input: dict):
            if tool_name == "save_audit_results":
                captured_audit.update(tool_input)
            return await mcp_manager.call_tool(tool_name, tool_input)

        log.info(f"[DeviceAudit-{display}] waiting for synthesis slot")
        async with get_synthesis_sem():
            log.info(f"[DeviceAudit-{display}] synthesis started")
            synthesis_text, _ = await run_subagent(
                SYNTHESIS_AGENT_PROMPT, synthesis_messages, SYNTHESIS_TOOLS,
                f"SynthesisAgent-{display}", max_loops=2,
                call_tool_fn=synthesis_tool_fn,
            )

        # Stream findings + emit audit_saved
        if captured_audit:
            audit_data = dict(captured_audit)
            # Always set the correct device name and IP
            if display and display != device_ip:
                audit_data.setdefault("device", display)
            audit_data["ip"] = device_ip
            audit_data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
            for finding in audit_data.get("findings", []):
                slim = {
                    "title":    finding.get("title", ""),
                    "severity": finding.get("severity", ""),
                    "type":     finding.get("type", "hardening"),
                }
                await sse_queue.put({"type": "finding", "finding": slim})
                await asyncio.sleep(0.03)
            await _push("audit_saved", audit=audit_data)
            log.info(f"[DeviceAudit-{display}] audit_saved emitted — {len(captured_audit.get('findings', []))} findings")
        else:
            log.warning(f"[DeviceAudit-{display}] no audit data captured from synthesis agent")

    finally:
        # Always clean up the isolated MCP subprocess
        if fresh_mgr:
            await fresh_mgr.disconnect()
            log.info(f"[DeviceAudit-{display}] fresh MCP session closed")

    elapsed = round(time.monotonic() - t_start, 1)
    await _push("device_done", device=display, elapsed=elapsed)
    log.info(f"[DeviceAudit] {display} ({device_ip}) complete in {elapsed}s")
    return synthesis_text


async def run_parallel_audit(
    audit_target: str,
    audit_scope: str,
    sse_queue: asyncio.Queue,
):
    """
    Multi-device orchestrator: spawns one run_device_audit task per device,
    all running concurrently. Falls back to single-device audit if only one IP found.
    """
    import re as _re
    t_total = time.monotonic()

    async def _push(event_type: str, **kwargs):
        await sse_queue.put({"type": event_type, **kwargs})

    # Build the full instruction string
    if audit_scope:
        full_instruction = f"Audit {audit_target} against {audit_scope}"
    else:
        full_instruction = audit_target  # full message passed directly

    # Extract all device IPs and common lab hostnames from the instruction
    ip_pattern   = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    host_pattern = r'\b((?:IOU|SW|RTR|GW|FW|CORE|DIST|ACCESS|ASA|VPN|R|BR)[\w\-]*\d+[\w\-]*)\b'
    _exclude     = {'IOS', 'IOS-XE', 'IOSXE', 'XE', 'CVE', 'NVD', 'CIS', 'SSH', 'AAA', 'ACL', 'VPN'}
    ips   = _re.findall(ip_pattern, full_instruction)
    names = [n for n in _re.findall(host_pattern, full_instruction, _re.IGNORECASE)
             if n.upper() not in _exclude]

    # Resolve hostnames → IPs via SNMP device list (build name→ip map from sysName)
    snmp_name_map: dict[str, str] = {}
    try:
        snmp_resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: http_requests.get(f"{SNMP_URL}/devices", timeout=5)
        )
        if snmp_resp.ok:
            for dev in snmp_resp.json().get("devices", []):
                host = dev.get("host", "")
                sys_name = dev.get("sysName", "")
                # sysName is like "IOU2.clydeford.net" — map short name and fqdn
                short = sys_name.split(".")[0].upper() if sys_name else ""
                if short:
                    snmp_name_map[short] = host
                if sys_name:
                    snmp_name_map[sys_name.upper()] = host
    except Exception as e:
        log.warning(f"[Orchestrator] SNMP lookup failed (will use hostnames directly): {e}")

    # Build device list: resolve names to IPs where possible, keep IPs as-is
    # Also build a display_name map so audit cards show the device name not just IP
    device_display: dict[str, str] = {}  # ip_or_host → display_name
    resolved = []
    for name in names:
        ip = snmp_name_map.get(name.upper(), name)  # fallback: use name as host
        resolved.append(ip)
        device_display[ip] = name  # display as original name in UI
    devices = list(dict.fromkeys(ips + resolved))
    for raw_ip in ips:
        if raw_ip not in device_display:
            device_display[raw_ip] = raw_ip

    if snmp_name_map and names:
        resolved_pairs = [(n, snmp_name_map.get(n.upper(), "unresolved")) for n in names]
        log.info(f"[Orchestrator] SNMP resolved: {resolved_pairs}")

    if not devices:
        await _push("error", content="No device IPs found in audit request.")
        await _push("done")
        return

    display_names = [device_display.get(ip, ip) for ip in devices]
    log.info(f"[Orchestrator] Launching {len(devices)} device audit(s): {list(zip(display_names, devices))}")
    await _push("text", content=f"🚀 Launching **{len(devices)} parallel device audit{'s' if len(devices)>1 else ''}**: {', '.join(display_names)}\n\n")

    # Spawn one task per device — all run concurrently
    tasks = {
        ip: asyncio.create_task(
            run_device_audit(ip, full_instruction, sse_queue, device_name=device_display.get(ip, ip))
        )
        for ip in devices
    }

    results = {}
    done_devices = set()
    while len(done_devices) < len(devices):
        await asyncio.sleep(0.5)
        for ip, task in tasks.items():
            if task.done() and ip not in done_devices:
                done_devices.add(ip)
                try:
                    results[ip] = task.result()
                except Exception as e:
                    results[ip] = f"Audit failed: {e}"
                    log.error(f"[Orchestrator] Device {ip} failed: {e}")

    total_elapsed = round(time.monotonic() - t_total, 1)
    summary = "\n".join(f"- **{device_display.get(ip, ip)}**: audit complete" for ip in devices)
    await _push("text", content=f"\n\n✅ All device audits complete in **{total_elapsed}s**\n{summary}\n")
    await _push("done")
    log.info(f"[Orchestrator] All {len(devices)} audits complete in {total_elapsed}s")


class ParallelAuditRequest(BaseModel):
    # Accepts either {target, scope} directly OR {messages, conversation_id} from chat UI
    target: str | None = None
    scope: str = "NIST CIS IOS XE benchmark, open CVEs and open PSIRT advisories"
    messages: list | None = None
    conversation_id: str | None = None


@app.post("/api/audit/parallel")
async def parallel_audit(request: ParallelAuditRequest):
    """Parallel audit endpoint — one subagent per device, all concurrent."""
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")

    # Extract target and scope from messages if sent via chat UI
    audit_target = request.target
    audit_scope  = request.scope
    if not audit_target and request.messages:
        last_msg = next((m["content"] for m in reversed(request.messages) if m.get("role") == "user"), None)
        if last_msg:
            audit_target = last_msg
            audit_scope  = ""

    if not audit_target:
        raise HTTPException(status_code=422, detail="No audit target provided")

    sse_queue: asyncio.Queue = asyncio.Queue()
    asyncio.create_task(run_parallel_audit(audit_target, audit_scope, sse_queue))

    async def _stream():
        while True:
            try:
                event = await asyncio.wait_for(sse_queue.get(), timeout=180.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'error', 'content': 'Audit timed out'})}\n\n"
                break

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )



# ── DESIGN AGENT ──────────────────────────────────────────────────────────────

# Cached Chroma collection IDs for Design Agent collections — populated at startup.
_design_col_id: str | None = None
_hw_col_id:     str | None = None


async def _cache_design_collection_ids():
    """Fetch and cache collection IDs for design-guidelines and hardware-datasheets."""
    global _design_col_id, _hw_col_id
    try:
        base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
        r = await asyncio.to_thread(
            http_requests.get, f"{base}/collections", timeout=5
        )
        if r.status_code == 200:
            cols = r.json() if isinstance(r.json(), list) else []
            col_map = {c["name"]: c["id"] for c in cols}
            if "design-guidelines" in col_map:
                _design_col_id = col_map["design-guidelines"]
                log.info(f"Design: design-guidelines ID cached ({_design_col_id[:8]}...)")
            else:
                log.warning("Design: design-guidelines collection not found in Chroma")
            if "hardware-datasheets" in col_map:
                _hw_col_id = col_map["hardware-datasheets"]
                log.info(f"Design: hardware-datasheets ID cached ({_hw_col_id[:8]}...)")
            else:
                log.info("Design: hardware-datasheets collection not yet in Chroma (will query when available)")
    except Exception as e:
        log.warning(f"Design: collection ID cache failed: {e}")


def _rag_query_collections(query_text: str, col_ids: dict[str, str], n_per_col: int = 4) -> str:
    """
    Query one or more Chroma collections and return a combined context string.
    col_ids: dict of {label: collection_id}  e.g. {"Design Guidelines": "abc123", "Hardware Data Sheets": "def456"}
    """
    base = f"http://{CHROMA_HOST}:{CHROMA_PORT}/api/v2/tenants/default_tenant/databases/default_database"
    emb  = get_embed_model().encode(query_text).tolist()
    sections = []
    for label, col_id in col_ids.items():
        try:
            r = http_requests.post(
                f"{base}/collections/{col_id}/query",
                json={
                    "query_embeddings": [emb],
                    "n_results": n_per_col,
                    "include": ["documents", "metadatas"],
                },
                timeout=10,
            )
            if r.status_code == 200:
                docs = r.json().get("documents", [[]])[0]
                if docs:
                    sections.append(
                        f"\n\n---\nRelevant context from {label}:\n" + "\n---\n".join(docs)
                    )
        except Exception as e:
            log.warning(f"Design RAG: query failed for '{label}': {e}")
    return "".join(sections)


DESIGN_SYSTEM_PROMPT = """You are the Gladius Design Agent — a specialist in enterprise network design, Cisco Validated Designs (CVDs), and infrastructure architecture best practices.

Your knowledge base contains curated network design documentation including Cisco Validated Design guides, topology blueprints, IP addressing schemes, routing design patterns, and high-availability frameworks.

Your role is to help Gladius users make informed, well-grounded network design decisions — whether planning a greenfield campus, designing a WAN architecture, or validating an existing topology against CVD recommendations.

You have access to two RAG knowledge bases that are automatically queried on every request:
- **Design Guidelines** (`design-guidelines`) — CVD and solution design specifications: topology blueprints, routing design patterns, IP addressing schemes, high-availability frameworks.
- **Hardware Data Sheets** (`hardware-datasheets`) — vendor hardware specifications, datasheet extracts, device capability profiles, interface counts, performance ratings, and hardware constraints.

Always ground your answers in retrieved context from these collections and reference the source where relevant. When hardware constraints or device specifications are relevant to a design decision, draw on the Hardware Data Sheets collection.

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
- **Use Mermaid diagrams** whenever a topology, flow, or hierarchy would benefit from visual representation. Wrap diagrams in ```mermaid code blocks. Prefer `graph TD` for topologies and hierarchies, `sequenceDiagram` for traffic flows, `flowchart LR` for decision trees. Keep node labels concise.

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
    Design agent stream — RAG lookup runs in a thread (non-blocking), then
    streams Claude tokens in real-time as they arrive (no buffering).
    """
    t_req = time.monotonic()
    try:
        # ── RAG: pull context from design-guidelines collection ───────────────
        # Runs entirely in a thread pool so the event loop is never blocked.
        rag_context = ""
        last_user_msg = next(
            (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
        )
        log.info(f"Design: request received, col_id={'set' if _design_col_id else 'MISSING'}")

        if last_user_msg and (_design_col_id or _hw_col_id):
            try:
                col_ids = {}
                if _design_col_id: col_ids["Design Guidelines"]    = _design_col_id
                if _hw_col_id:     col_ids["Hardware Data Sheets"] = _hw_col_id

                t_rag = time.monotonic()
                log.info(f"Design RAG: querying {list(col_ids.keys())} (t+{(t_rag-t_req)*1000:.0f}ms)")
                rag_context = await asyncio.to_thread(_rag_query_collections, last_user_msg, col_ids)
                log.info(f"Design RAG: done in {(time.monotonic()-t_rag)*1000:.0f}ms, context={'yes' if rag_context else 'none'}")
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

        # ── Stream Claude tokens in real-time ─────────────────────────────────
        t_stream = time.monotonic()
        log.info(f"Design: starting Claude stream (t+{(t_stream-t_req)*1000:.0f}ms from request)")
        first_token = True
        try:
            async with client.messages.stream(
                model=MODEL,
                max_tokens=8192,
                system=DESIGN_SYSTEM_PROMPT,
                messages=augmented_messages,
            ) as stream:
                async for text in stream.text_stream:
                    if first_token:
                        log.info(f"Design: first token at t+{(time.monotonic()-t_req)*1000:.0f}ms from request")
                        first_token = False
                    yield f"data: {json.dumps({'type': 'text', 'content': text})}\n\n"
        except Exception as stream_err:
            # Log but emit done — partial response already sent to browser is still useful
            log.warning(f"Design stream interrupted ({type(stream_err).__name__}): {stream_err}")

        log.info(f"Design stream: finished in {(time.monotonic()-t_stream)*1000:.0f}ms total")
        global _last_claude_success
        _last_claude_success = time.monotonic()
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        log.error(f"Design stream error: {type(e).__name__}: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"



# ── Design Critique Loop ─────────────────────────────────────────────────────

# Per-intensity critic configuration — 9 levels (1 = Go Easy, 9 = Both Barrels)
_CRITIC_INTENSITY = {
    1: dict(
        name="Go Easy",
        tone=(
            "Be gentle and encouraging. Surface only showstopper flaws — issues that would cause "
            "outright failure. Overlook minor gaps and stylistic choices. Frame any issues constructively."
        ),
        count="1–2",
        threshold=(
            "Approve readily. If the design is fundamentally reasonable and would work in production, "
            "output DESIGN_APPROVED."
        ),
    ),
    2: dict(
        name="Gentle",
        tone=(
            "Be constructive and supportive. Identify significant issues that would cause operational "
            "problems, but frame them positively and focus on the most impactful ones."
        ),
        count="2–3",
        threshold=(
            "Approve if the major design decisions are correct, even if minor details could be improved."
        ),
    ),
    3: dict(
        name="Considerate",
        tone=(
            "Be balanced but lean towards encouragement. Call out issues that would cause real operational "
            "problems or violate important best practices, but acknowledge what the design does well."
        ),
        count="2–4",
        threshold="Approve when the design addresses core requirements adequately.",
    ),
    4: dict(
        name="Measured",
        tone=(
            "Provide balanced critique. Identify real issues without being harsh. Give credit for good "
            "design decisions."
        ),
        count="3–5",
        threshold="Approve when major issues are resolved and the design is solid in its key dimensions.",
    ),
    5: dict(
        name="Balanced",
        tone=(
            "Be objective and thorough. Apply standard enterprise design review criteria. Neither lenient "
            "nor harsh — call it as it is."
        ),
        count="3–6",
        threshold="Approve when the design is solid across all major dimensions with no significant gaps.",
    ),
    6: dict(
        name="Thorough",
        tone=(
            "Be rigorous. Surface issues that experienced senior engineers would flag in a formal design "
            "review. Don't overlook gaps in HA, security, or scalability."
        ),
        count="4–7",
        threshold="Approve only when the design is genuinely strong with no significant gaps.",
    ),
    7: dict(
        name="Rigorous",
        tone=(
            "Be demanding. Apply the standards of a senior network architect. Every major design decision "
            "must be justified. Identify all issues that could cause problems in a production environment."
        ),
        count="5–8",
        threshold=(
            "Approve only when the design is comprehensive, production-ready, and free of architectural debt."
        ),
    ),
    8: dict(
        name="Unsparing",
        tone=(
            "Be uncompromising. Apply the exacting standards of a Cisco Distinguished Engineer. Challenge "
            "every architectural decision. Assume the design will run in a large enterprise with zero "
            "tolerance for downtime."
        ),
        count="6–9",
        threshold=(
            "Approve only when the design is excellent across every evaluated dimension — no hand-waving, "
            "no 'good enough'."
        ),
    ),
    9: dict(
        name="Both Barrels",
        tone=(
            "Be absolutely ruthless. Leave nothing on the table. Challenge every design decision, "
            "assumption, omission, and implicit trade-off. Apply the most exacting enterprise standards "
            "imaginable. This design must survive the harshest possible scrutiny from the most demanding "
            "architect in the room."
        ),
        count="7–12",
        threshold=(
            "Approve ONLY if the design is truly exceptional — production-ready, fully resilient, "
            "secure, scalable, CVD-compliant, and operationally sound in every respect. "
            "Reject anything that falls short of outstanding."
        ),
    ),
}


def _build_critic_system_prompt(intensity: int) -> str:
    cfg = _CRITIC_INTENSITY.get(intensity, _CRITIC_INTENSITY[5])
    return f"""You are the Gladius Critic Agent — a network design reviewer operating at intensity level {intensity}/9 ({cfg['name']}).

## Your Tone
{cfg['tone']}

## Analysis Checklist
For every design proposal, evaluate these dimensions:
- **Redundancy & HA** — are failure domains isolated? Single-point-of-failure risk?
- **Scalability** — will this design handle growth? Are there architectural ceilings?
- **Security posture** — segmentation, access control, management plane protection
- **Routing correctness** — protocol selection, summarisation, convergence, redistribution risks
- **IP addressing** — subnetting correctness, room for growth, VLSM/CIDR accuracy
- **CVD alignment** — does this follow Cisco Validated Design principles?
- **Operational concerns** — manageability, monitoring hooks, change risk
- **Missing elements** — what has the design omitted that a production deployment requires?

## Output Format
List each flaw as a numbered issue:
1. **[Concise Title]** — Technical explanation of the flaw and its consequence
2. **[Concise Title]** — ...

Aim for {cfg['count']} issues per iteration.

## Approval Criterion
{cfg['threshold']}

When approving, end your response with this exact token on its own line:
`DESIGN_APPROVED`"""


class DesignCritiqueRequest(BaseModel):
    question: str
    max_iterations: int = 4
    critique_intensity: int = 5


@app.post("/api/chat/design/critique")
async def design_critique_chat(request: DesignCritiqueRequest):
    """Design critique loop — iterates between Design Agent and Critic Agent."""
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    iterations = max(1, min(request.max_iterations, 6))
    intensity  = max(1, min(request.critique_intensity, 9))
    return StreamingResponse(
        stream_design_critique(request.question, iterations, intensity),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def stream_design_critique(user_question: str, max_iterations: int, intensity: int = 5) -> AsyncIterator[str]:
    """
    Iterative design critique loop:
      1. Design Agent drafts a design.
      2. Critic Agent reviews it (at the requested intensity level).
      3. If DESIGN_APPROVED or max_iterations reached → emit approved + done.
      4. Else Design Agent revises → go to 2.
    """
    critic_system_prompt = _build_critic_system_prompt(intensity)
    log.info(f"Design critique: intensity={intensity} ({_CRITIC_INTENSITY.get(intensity, {}).get('name', '?')}), max_iter={max_iterations}")
    try:
        yield f"data: {json.dumps({'type': 'critique_start', 'max_iterations': max_iterations})}\n\n"

        # RAG lookup — run once against the original question, query all Design Agent collections
        rag_context = ""
        if (_design_col_id or _hw_col_id) and user_question:
            try:
                col_ids = {}
                if _design_col_id: col_ids["Design Guidelines"]    = _design_col_id
                if _hw_col_id:     col_ids["Hardware Data Sheets"] = _hw_col_id
                rag_context = await asyncio.to_thread(_rag_query_collections, user_question, col_ids)
                log.info(f"Design critique RAG: queried {list(col_ids.keys())}, context={'yes' if rag_context else 'none'}")
            except Exception as e:
                log.warning(f"Design critique RAG lookup failed (non-fatal): {e}")

        current_design = ""
        critique = ""

        for iteration in range(1, max_iterations + 1):
            # ── Design Agent phase ────────────────────────────────────────────
            if iteration == 1:
                label = "Drafting initial design…"
                design_prompt = user_question
                if rag_context:
                    design_prompt += rag_context
            else:
                label = f"Revising design (iteration {iteration})…"
                design_prompt = (
                    f"Original design question: {user_question}\n\n"
                    f"Your previous design:\n{current_design}\n\n"
                    f"Critic's review:\n{critique}\n\n"
                    f"Revise your design to address every concern raised by the critic "
                    f"while preserving what was already strong. "
                    f"Produce a complete, updated design."
                )
                if rag_context:
                    design_prompt += rag_context

            yield f"data: {json.dumps({'type': 'phase', 'phase': 'design', 'iteration': iteration, 'label': label})}\n\n"

            current_design = ""
            try:
                async with client.messages.stream(
                    model=MODEL,
                    max_tokens=8192,
                    system=DESIGN_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": design_prompt}],
                ) as stream:
                    async for text in stream.text_stream:
                        current_design += text
                        yield f"data: {json.dumps({'type': 'text', 'content': text, 'agent': 'design'})}\n\n"
            except Exception as e:
                log.error(f"Design critique — design agent stream error (iter {iteration}): {e}")
                yield f"data: {json.dumps({'type': 'error', 'content': f'Design agent error: {e}'})}\n\n"
                return

            # ── Critic Agent phase ────────────────────────────────────────────
            yield f"data: {json.dumps({'type': 'phase', 'phase': 'critic', 'iteration': iteration, 'label': 'Critical analysis underway…'})}\n\n"

            critic_prompt = (
                f"Original design question: {user_question}\n\n"
                f"Design proposal to review (iteration {iteration}):\n{current_design}"
            )
            critique = ""
            try:
                async with client.messages.stream(
                    model=MODEL,
                    max_tokens=4096,
                    system=critic_system_prompt,
                    messages=[{"role": "user", "content": critic_prompt}],
                ) as stream:
                    async for text in stream.text_stream:
                        critique += text
                        yield f"data: {json.dumps({'type': 'text', 'content': text, 'agent': 'critic'})}\n\n"
            except Exception as e:
                log.error(f"Design critique — critic agent stream error (iter {iteration}): {e}")
                yield f"data: {json.dumps({'type': 'error', 'content': f'Critic agent error: {e}'})}\n\n"
                return

            approved = "DESIGN_APPROVED" in critique
            log.info(f"Design critique iteration {iteration}: approved={approved}")

            if approved or iteration >= max_iterations:
                reason = "approved" if approved else "max_iterations"
                yield f"data: {json.dumps({'type': 'approved', 'iterations': iteration, 'reason': reason})}\n\n"
                break

        global _last_claude_success
        _last_claude_success = time.monotonic()
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        log.error(f"Design critique stream error: {type(e).__name__}: {e}", exc_info=True)
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
