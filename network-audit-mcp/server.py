#!/usr/bin/env python3
"""
Network Audit MCP Server
"""

import os
import sys
import time
import logging
import requests
import paramiko
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types
import chromadb
from sentence_transformers import SentenceTransformer

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
log = logging.getLogger(__name__)

CHROMA_HOST     = os.getenv("CHROMA_HOST", "chroma-db")
CHROMA_PORT     = int(os.getenv("CHROMA_PORT", 8000))
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "network_security_guidelines")
EMBED_MODEL     = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
NIST_API_KEY    = os.getenv("NIST_API_KEY")
LAB_USERNAME    = os.getenv("LAB_USERNAME")
LAB_PASSWORD    = os.getenv("LAB_PASSWORD")

_ssh_client  = None
_ssh_channel = None
_device_host = None

log.info("Loading embedding model...")
embed_model = SentenceTransformer(EMBED_MODEL)
log.info("Connecting to Chroma...")
chroma_client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
collection = chroma_client.get_or_create_collection(COLLECTION_NAME)
log.info(f"Chroma ready. Collection contains {collection.count()} vectors.")

app = Server("network-audit-mcp")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="query_knowledge_base",
            description="Query the NIST/CIS network security knowledge base for hardening guidelines and remediation advice.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The security question or topic to look up"},
                    "num_results": {"type": "integer", "description": "Number of results to return (default 5)", "default": 5}
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="connect_to_device",
            description="Establish an SSH connection to a Cisco network device. Must be called before run_show_command or push_config.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "IP address or hostname of the device"},
                    "username": {"type": "string", "description": "SSH username - optional, uses lab default if not provided"},
                    "password": {"type": "string", "description": "SSH password - optional, uses lab default if not provided"}
                },
                "required": ["host"]
            }
        ),
        types.Tool(
            name="run_show_command",
            description="Run a read-only show command on the connected Cisco device. Must call connect_to_device first.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The show command to execute e.g. 'show running-config'"}
                },
                "required": ["command"]
            }
        ),
        types.Tool(
            name="push_config",
            description="Push configuration commands to the connected Cisco device. Only use after explicit user approval.",
            inputSchema={
                "type": "object",
                "properties": {
                    "commands": {"type": "array", "items": {"type": "string"}, "description": "List of configuration commands to push"},
                    "confirmed": {"type": "boolean", "description": "Must be true - confirms user has approved these changes"}
                },
                "required": ["commands", "confirmed"]
            }
        ),
        types.Tool(
            name="disconnect_device",
            description="Close the SSH connection to the current device.",
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="send_email",
            description="Send an email from Gladius. Use for audit reports and CVE summaries.",
            inputSchema={
                "type": "object",
                "properties": {
                    "subject": {"type": "string", "description": "Email subject line"},
                    "body": {"type": "string", "description": "Email body - plain text or HTML"},
                    "recipient": {"type": "string", "description": "Recipient email address - optional, defaults to configured default"},
                    "is_html": {"type": "boolean", "description": "Set to true if body contains HTML", "default": False},
                    "attachment_html": {"type": "string", "description": "Full HTML content to attach as a file"},
                    "attachment_filename": {"type": "string", "description": "Filename for the HTML attachment e.g. audit-report.html"}
                },
                "required": ["subject", "body"]
            }
        ),
        types.Tool(
            name="query_nvd",
            description=(
                "Query the NIST National Vulnerability Database for CVEs. "
                "Use search_term for keyword search e.g. 'Cisco IOS XE 17.12.1'. "
                "Use cisco_only=true to filter by Cisco PSIRT source — more accurate than keyword search for Cisco CVEs. "
                "Use days_back to get recent CVEs by publication date e.g. days_back=30. Max 120 days. "
                "Results are always sorted newest first."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search_term": {
                        "type": "string",
                        "description": "Keyword or platform to search e.g. 'Cisco IOS XE 17.12.1' — optional"
                    },
                    "cisco_only": {
                        "type": "boolean",
                        "description": "Filter by Cisco PSIRT source (psirt@cisco.com) — more precise than keyword for Cisco CVEs"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by CVSS v3 severity — optional",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum CVEs to return (default 20)",
                        "default": 20
                    },
                    "days_back": {
                        "type": "integer",
                        "description": "Return CVEs published in the last N days e.g. 30. Maximum 120."
                    }
                },
                "required": []
            }
        ),
        types.Tool(
            name="get_cve_details",
            description="Get full details for a specific CVE ID e.g. CVE-2024-12345",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "The CVE ID to look up"}
                },
                "required": ["cve_id"]
            }
        ),
        types.Tool(
            name="save_audit_results",
            description="Save completed audit results to the Gladius dashboard. Call this at the end of every audit.",
            inputSchema={
                "type": "object",
                "properties": {
                    "device":    {"type": "string",  "description": "Device hostname"},
                    "ip":        {"type": "string",  "description": "Device IP address"},
                    "ios":       {"type": "string",  "description": "IOS version string"},
                    "timestamp": {"type": "string",  "description": "ISO timestamp of audit"},
                    "findings":  {"type": "array",   "description": "Array of finding objects", "items": {"type": "object"}},
                    "score":     {"type": "object",  "description": "Compliance scores: {overall, nist, cis}"}
                },
                "required": ["device", "ip", "findings", "score"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "query_knowledge_base":
        return await _query_knowledge_base(**arguments)
    elif name == "connect_to_device":
        return await _connect_to_device(**arguments)
    elif name == "run_show_command":
        return await _run_show_command(**arguments)
    elif name == "push_config":
        return await _push_config(**arguments)
    elif name == "disconnect_device":
        return await _disconnect_device()
    elif name == "query_nvd":
        return await _query_nvd(**arguments)
    elif name == "get_cve_details":
        return await _get_cve_details(**arguments)
    elif name == "send_email":
        return await _send_email(**arguments)
    elif name == "save_audit_results":
        return await _save_audit_results(**arguments)
    else:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


async def _query_knowledge_base(query: str, num_results: int = 5) -> list[types.TextContent]:
    log.info(f"Knowledge base query: '{query}'")
    try:
        query_embedding = embed_model.encode(query).tolist()
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=num_results,
            include=["documents", "metadatas", "distances"]
        )
        if not results["documents"][0]:
            return [types.TextContent(type="text", text="No relevant guidelines found.")]
        output = f"Knowledge base results for: '{query}'\n{'=' * 60}\n\n"
        for i, (doc, meta, dist) in enumerate(zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        ), 1):
            relevance = round((1 - dist) * 100, 1)
            output += f"Result {i} - Source: {meta['source']} (Relevance: {relevance}%)\n"
            output += "-" * 40 + "\n"
            output += doc + "\n\n"
        return [types.TextContent(type="text", text=output)]
    except Exception as e:
        log.error(f"Knowledge base query failed: {e}")
        return [types.TextContent(type="text", text=f"ERROR: Knowledge base query failed: {e}")]


async def _connect_to_device(host: str, username: str = None, password: str = None) -> list[types.TextContent]:
    global _ssh_client, _ssh_channel, _device_host
    username = username or LAB_USERNAME
    password = password or LAB_PASSWORD
    if not username or not password:
        return [types.TextContent(type="text", text="ERROR: No credentials provided and no lab defaults configured.")]
    if _ssh_client:
        try:
            _ssh_client.close()
        except Exception:
            pass
    log.info(f"Connecting to {host} as {username}...")
    try:
        _ssh_client = paramiko.SSHClient()
        _ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        _ssh_client.connect(hostname=host, username=username, password=password,
                            look_for_keys=False, allow_agent=False, timeout=15, auth_timeout=15)
        _ssh_channel = _ssh_client.invoke_shell()
        time.sleep(1)
        _clear_buffer()
        _ssh_channel.send("terminal length 0\n")
        time.sleep(0.5)
        _clear_buffer()
        _device_host = host
        log.info(f"Connected to {host}")
        return [types.TextContent(type="text", text=f"Successfully connected to {host} as {username}")]
    except paramiko.AuthenticationException:
        return [types.TextContent(type="text", text=f"ERROR: Authentication failed for {host}.")]
    except Exception as e:
        log.error(f"Connection failed: {e}")
        return [types.TextContent(type="text", text=f"ERROR: Connection failed: {e}")]


async def _run_show_command(command: str) -> list[types.TextContent]:
    if not _ssh_channel:
        return [types.TextContent(type="text", text="ERROR: Not connected. Call connect_to_device first.")]
    blocked = ["conf", "write", "copy", "delete", "reload", "no ", "shutdown"]
    if any(command.strip().lower().startswith(b) for b in blocked):
        return [types.TextContent(type="text", text=f"ERROR: '{command}' not permitted in read-only mode.")]
    log.info(f"Running: {command}")
    try:
        _ssh_channel.send(command + "\n")
        time.sleep(0.5)
        output = _clear_buffer(timeout=10)
        return [types.TextContent(type="text", text=output)]
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: Command failed: {e}")]


async def _push_config(commands: list, confirmed: bool) -> list[types.TextContent]:
    if not confirmed:
        return [types.TextContent(type="text", text="ERROR: Set confirmed=true to proceed.")]
    if not _ssh_channel:
        return [types.TextContent(type="text", text="ERROR: Not connected. Call connect_to_device first.")]
    log.info(f"Pushing {len(commands)} commands to {_device_host}")
    try:
        output = ""
        _ssh_channel.send("configure terminal\n")
        time.sleep(0.5)
        output += _clear_buffer()
        for cmd in commands:
            _ssh_channel.send(cmd + "\n")
            time.sleep(0.3)
            output += _clear_buffer()
        _ssh_channel.send("end\n")
        time.sleep(0.3)
        output += _clear_buffer()
        _ssh_channel.send("write memory\n")
        time.sleep(2)
        output += _clear_buffer()
        return [types.TextContent(type="text", text=f"Configuration applied:\n{output}")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: Config push failed: {e}")]


async def _disconnect_device() -> list[types.TextContent]:
    global _ssh_client, _ssh_channel, _device_host
    msg = "No active connection."
    if _ssh_client:
        try:
            _ssh_client.close()
            msg = f"Disconnected from {_device_host}"
        except Exception as e:
            msg = f"Error during disconnect: {e}"
    _ssh_client = _ssh_channel = _device_host = None
    return [types.TextContent(type="text", text=msg)]


async def _query_nvd(
    search_term: str = None,
    severity: str = None,
    max_results: int = 20,
    days_back: int = None,
    cisco_only: bool = False
) -> list[types.TextContent]:
    log.info(f"NVD query: search_term='{search_term}' severity={severity} days_back={days_back} cisco_only={cisco_only}")

    # Sanitise search_term — Claude sometimes passes literal "None"
    if search_term in (None, "None", "", "null"):
        search_term = None

    if not search_term and not days_back and not cisco_only:
        return [types.TextContent(type="text", text="ERROR: Provide at least one of search_term, days_back, or cisco_only=true.")]

    headers = {}
    if NIST_API_KEY:
        headers["apiKey"] = NIST_API_KEY

    # Note: NVD API does NOT support sortBy or sortOrder parameters — we sort after retrieval
    params = {
        "resultsPerPage": max_results,
        "noRejected": "",
    }

    # Date range — API maximum is 120 consecutive days
    if days_back:
        from datetime import datetime, timezone, timedelta
        days_back = min(days_back, 120)
        end_dt    = datetime.now(timezone.utc)
        start_dt  = end_dt - timedelta(days=days_back)
        params["pubStartDate"] = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"]   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    # Cisco PSIRT source filter — precise, no false positives from third-party mentions of Cisco
    if cisco_only:
        params["sourceIdentifier"] = "psirt@cisco.com"

    if search_term:
        params["keywordSearch"] = search_term

    if severity:
        params["cvssV3Severity"] = severity.upper()

    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers=headers, params=params, timeout=30
        )
        response.raise_for_status()
        data = response.json()

        total           = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        # Sort newest first — NVD API has no sort parameter
        vulnerabilities.sort(
            key=lambda x: x.get("cve", {}).get("published", ""),
            reverse=True
        )

        if not vulnerabilities:
            return [types.TextContent(type="text", text="No CVEs found for the given criteria.")]

        header = "NVD Results"
        if cisco_only:
            header += " [Cisco PSIRT]"
        if search_term:
            header += f" for '{search_term}'"
        if days_back:
            header += f" (last {days_back} days)"
        if severity:
            header += f" [{severity.upper()}]"
        header += f" — {total} total, showing {len(vulnerabilities)}\n{'=' * 60}\n\n"
        output = header

        for item in vulnerabilities:
            cve          = item.get("cve", {})
            cve_id       = cve.get("id", "Unknown")
            published    = cve.get("published", "")[:10]
            descriptions = cve.get("descriptions", [])
            description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
            metrics      = cve.get("metrics", {})
            score        = "N/A"
            sev          = "N/A"
            if "cvssMetricV31" in metrics:
                cvss  = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                sev   = cvss.get("baseSeverity", "N/A")
            elif "cvssMetricV30" in metrics:
                cvss  = metrics["cvssMetricV30"][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                sev   = cvss.get("baseSeverity", "N/A")
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            output += f"[{sev}] {cve_id} — Score: {score} — Published: {published}\n"
            output += f"URL: {nvd_url}\n"
            output += f"{description[:300]}{'...' if len(description) > 300 else ''}\n\n"

        return [types.TextContent(type="text", text=output)]

    except requests.exceptions.Timeout:
        return [types.TextContent(type="text", text="ERROR: NVD API request timed out.")]
    except Exception as e:
        log.error(f"NVD query failed: {e}")
        return [types.TextContent(type="text", text=f"ERROR: NVD query failed: {e}")]


async def _get_cve_details(cve_id: str) -> list[types.TextContent]:
    log.info(f"CVE lookup: {cve_id}")
    headers = {}
    if NIST_API_KEY:
        headers["apiKey"] = NIST_API_KEY
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers=headers, params={"cveId": cve_id}, timeout=30
        )
        response.raise_for_status()
        data            = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return [types.TextContent(type="text", text=f"CVE {cve_id} not found.")]
        cve          = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
        metrics      = cve.get("metrics", {})
        score = sev = vector = "N/A"
        if "cvssMetricV31" in metrics:
            cvss   = metrics["cvssMetricV31"][0]["cvssData"]
            score  = cvss.get("baseScore", "N/A")
            sev    = cvss.get("baseSeverity", "N/A")
            vector = cvss.get("vectorString", "N/A")
        ref_urls = [r["url"] for r in cve.get("references", [])[:5]]
        nvd_url  = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        output   = (
            f"CVE Details: {cve_id}\n{'=' * 60}\n"
            f"Severity:    {sev} ({score})\n"
            f"Vector:      {vector}\n"
            f"Published:   {cve.get('published', '')[:10]}\n"
            f"Modified:    {cve.get('lastModified', '')[:10]}\n"
            f"NVD URL:     {nvd_url}\n\n"
            f"Description:\n{description}\n\n"
        )
        if ref_urls:
            output += "References:\n" + "\n".join(f"  - {u}" for u in ref_urls)
        return [types.TextContent(type="text", text=output)]
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: CVE lookup failed: {e}")]


async def _send_email(subject: str, body: str, recipient: str = None, is_html: bool = False, attachment_html: str = None, attachment_filename: str = None) -> list[types.TextContent]:
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders
    smtp_server   = os.getenv("SMTP_SERVER")
    smtp_port     = int(os.getenv("SMTP_PORT", 587))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_name     = os.getenv("SMTP_FROM_NAME", "Gladius")
    to_address    = recipient or os.getenv("DEFAULT_RECIPIENT")
    if not all([smtp_server, smtp_username, smtp_password, to_address]):
        return [types.TextContent(type="text", text="ERROR: Email configuration incomplete.")]
    log.info(f"Sending email to {to_address}: {subject}")
    try:
        msg            = MIMEMultipart("mixed")
        msg["From"]    = f"{from_name} <{smtp_username}>"
        msg["To"]      = to_address
        msg["Subject"] = subject
        # Body — plain text or HTML inline
        content_type = "html" if is_html and not attachment_html else "plain"
        msg.attach(MIMEText(body, content_type))
        # HTML attachment
        if attachment_html:
            part = MIMEBase("text", "html")
            part.set_payload(attachment_html.encode("utf-8"))
            encoders.encode_base64(part)
            fname = attachment_filename or "audit-report.html"
            part.add_header("Content-Disposition", "attachment", filename=fname)
            part.add_header("Content-Type", "text/html; charset=utf-8")
            msg.attach(part)
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        return [types.TextContent(type="text", text=f"Email sent successfully to {to_address}")]
    except smtplib.SMTPAuthenticationError:
        return [types.TextContent(type="text", text="ERROR: SMTP authentication failed.")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: Email failed: {e}")]



async def _save_audit_results(device: str, ip: str, findings: list, score: dict,
                               ios: str = "", timestamp: str = "") -> list[types.TextContent]:
    """POST audit results to the Gladius API so the dashboard can display them."""
    import datetime
    gladius_api = os.getenv("GLADIUS_API_URL", "http://gladius-api:8080")
    if not timestamp:
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    payload = {
        "device":    device,
        "ip":        ip,
        "ios":       ios,
        "timestamp": timestamp,
        "findings":  findings,
        "score":     score,
    }
    try:
        resp = requests.post(f"{gladius_api}/api/audit/save", json=payload, timeout=10)
        if resp.status_code == 200:
            log.info(f"Audit saved to dashboard: {device} ({ip}), {len(findings)} findings")
            return [types.TextContent(type="text", text=f"Audit saved: {len(findings)} findings recorded for {device}.")]
        else:
            log.error(f"Audit save failed: HTTP {resp.status_code} — {resp.text}")
            return [types.TextContent(type="text", text=f"ERROR: Audit save failed — HTTP {resp.status_code}")]
    except Exception as e:
        log.error(f"Audit save error: {e}", exc_info=True)
        return [types.TextContent(type="text", text=f"ERROR: Could not save audit — {e}")]


def _clear_buffer(timeout: int = 5) -> str:
    output = ""
    start  = time.time()
    while (time.time() - start) < timeout:
        if _ssh_channel.recv_ready():
            chunk   = _ssh_channel.recv(8192).decode("utf-8", errors="ignore")
            output += chunk
            if any(p in chunk for p in ["#", ">"]):
                break
        else:
            time.sleep(0.1)
    return output


async def main():
    log.info("Network Audit MCP Server starting...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())