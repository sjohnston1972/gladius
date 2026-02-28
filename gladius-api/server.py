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
import requests as http_requests
import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv

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

CHROMA_HOST = os.getenv("CHROMA_HOST", "chroma-db")
CHROMA_PORT = os.getenv("CHROMA_PORT", "8000")
NVD_TEST_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"

# Track last successful Claude response for health reporting
_last_claude_success: float = 0.0

# Store the most recently saved audit so we can template emails from chat
_last_audit: dict | None = None

# In-memory store for the most recently saved audit result
# The SSE stream picks this up and forwards it to the browser as audit_saved
_pending_audit: dict | None = None

SYSTEM_PROMPT = """You are Gladius, an elite network security auditor. You have access to MCP tools that let you connect to and audit Cisco network devices, query a NIST/CIS security knowledge base, look up CVEs in the NVD database, and send email reports.

Your personality: precise, direct, professional. You are thorough and methodical. You communicate findings clearly with severity ratings. You always recommend remediation steps.

When auditing devices:
1. Connect to the device using connect_to_device
2. Run relevant show commands using run_show_command
3. Cross-reference findings with the knowledge base using query_knowledge_base
4. Check for CVEs using query_nvd with cisco_only=True and the detected IOS version
5. Present findings clearly organised by severity: HIGH, MEDIUM, LOW, PASS
6. Call save_audit_results with ALL findings and calculated compliance scores — ALWAYS do this at the end of every audit, without being asked
7. Offer to push remediations or email a report

When building findings for save_audit_results:
- Set type="hardening" for configuration and compliance findings (missing banners, weak passwords, CDP enabled etc.)
- Set type="cve" for any CVE vulnerabilities found via query_nvd — always include the cve_id field (e.g. "CVE-2024-20399")
- CVE findings should use the CVE ID as the title (e.g. "CVE-2024-20399") and include the NVD URL in the ref field

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

                            yield f"data: {json.dumps({'type': 'tool_start', 'tool': tool_name})}\n\n"
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

                            # After save_audit_results, emit audit_saved to the browser
                            # _pending_audit is set by /api/audit/save (called by the MCP tool)
                            global _pending_audit
                            if tool_name == "save_audit_results" and not is_error and _pending_audit:
                                audit_payload = json.dumps({"type": "audit_saved", "audit": _pending_audit})
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)