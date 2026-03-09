#!/usr/bin/env python3
"""
Network Audit MCP Server
"""

import os
import sys

# Disable HuggingFace network calls — use local cache only.
# This saves ~7-10 seconds per cold start by skipping remote validation.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
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
NIST_API_KEY         = os.getenv("NIST_API_KEY")
LAB_USERNAME         = os.getenv("LAB_USERNAME")
LAB_PASSWORD         = os.getenv("LAB_PASSWORD")
SNMP_SERVICE_URL     = os.getenv("SNMP_SERVICE_URL", "http://gladius-snmp:8000")
PSIRT_CLIENT_KEY     = os.getenv("PSIRT_CLIENT_KEY")
PSIRT_CLIENT_SECRET  = os.getenv("PSIRT_CLIENT_SECRET")
PSIRT_TOKEN_URL      = "https://id.cisco.com/oauth2/default/v1/token"
PSIRT_API_BASE       = "https://apix.cisco.com/security/advisories/v2"
EOX_CLIENT_KEY       = os.getenv("EOX_CLIENT_KEY")
EOX_CLIENT_SECRET    = os.getenv("EOX_CLIENT_SECRET")
EOX_API_BASE         = "https://apix.cisco.com/supporttools/eox/rest/5"

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
            name="query_design_kb",
            description="Query the network design knowledge base for CVD guidance, topology patterns, VXLAN/BGP EVPN design, campus/DC architecture, and Cisco Validated Designs. Use this when answering design questions rather than security hardening questions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The design question or topic to look up"},
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
            name="run_nmap_scan",
            description=(
                "Run an nmap network scan against a target IP, hostname, or CIDR range. "
                "Use to discover open ports, running services, OS fingerprints, and known vulnerabilities. "
                "Profiles: quick (fast top ports), service (version detection), full_port (all 65535 ports), "
                "os_detection (OS fingerprint), vuln_scripts (NSE vuln scripts), custom (supply your own args)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or CIDR range e.g. 192.168.1.1 or 10.0.0.0/24"
                    },
                    "profile": {
                        "type": "string",
                        "description": "Scan profile to use",
                        "enum": ["quick", "service", "full_port", "os_detection", "vuln_scripts", "custom"],
                        "default": "quick"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Optional port range e.g. 22,80,443 or 1-1024"
                    },
                    "args": {
                        "type": "string",
                        "description": "Additional nmap flags — only used with the custom profile e.g. -sS -T4 --open"
                    }
                },
                "required": ["target"]
            }
        ),
        types.Tool(
            name="run_dig",
            description=(
                "Run a DNS dig query against a target domain or IP address. "
                "Use to resolve DNS records, trace delegation chains, check zone transfers, "
                "reverse-lookup IPs, and identify DNS misconfigurations or data-exfiltration risks. "
                "Record types: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA, DNSKEY, DS, AXFR, ANY. "
                "Optionally specify a custom resolver (e.g. 8.8.8.8 or 1.1.1.1)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Domain name or IP address to query e.g. example.com or 8.8.8.8"
                    },
                    "record_type": {
                        "type": "string",
                        "description": "DNS record type to query",
                        "enum": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA", "DNSKEY", "DS", "AXFR", "ANY"],
                        "default": "A"
                    },
                    "resolver": {
                        "type": "string",
                        "description": "Custom DNS resolver IP to use e.g. 8.8.8.8 or 1.1.1.1 — optional, uses system default if omitted"
                    },
                    "options": {
                        "type": "string",
                        "description": "Additional dig flags e.g. +trace +short +dnssec +nocmd — optional"
                    }
                },
                "required": ["target"]
            }
        ),
        types.Tool(
            name="run_scapy",
            description=(
                "Run a Scapy-based packet analysis or network probe. "
                "Modes: ping (ICMP echo), traceroute (UDP/ICMP hop trace), "
                "tcp_syn (SYN probe), tcp_full (full 3-way handshake), "
                "arp_scan (LAN ARP discovery), banner_grab (TCP banner), "
                "udp_probe (UDP port probe), "
                "sip_invite (SIP INVITE over UDP to VoIP target), "
                "http_get (raw HTTP GET request via TCP), "
                "dns_query (raw DNS A query via UDP), "
                "syn_flood_test (SYN flood test — sends count SYN packets with randomised source ports), "
                "xmas_scan (FIN+PSH+URG TCP scan), "
                "null_scan (no-flag TCP scan), "
                "fin_scan (FIN-only TCP scan), "
                "rst_probe (send TCP RST to test stateful firewall), "
                "frag_ping (fragmented ICMP to test fragment reassembly), "
                "ttl_probe (ICMP with custom TTL to map firewall distance), "
                "os_fingerprint (send mixed TCP/ICMP probes for passive OS hints), "
                "vlan_hop (802.1Q double-tag VLAN hopping frame — lab/pen-test only). "
                "All operations use a timeout to avoid hanging."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "description": "Operation to perform",
                        "enum": [
                            "ping", "traceroute", "tcp_syn", "tcp_full",
                            "arp_scan", "banner_grab", "udp_probe",
                            "sip_invite", "http_get", "dns_query",
                            "syn_flood_test", "xmas_scan", "null_scan",
                            "fin_scan", "rst_probe", "frag_ping",
                            "ttl_probe", "os_fingerprint", "vlan_hop"
                        ],
                        "default": "ping"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname (for arp_scan use CIDR e.g. 192.168.1.0/24)"
                    },
                    "port": {
                        "type": "integer",
                        "description": "TCP/UDP port — used for tcp_syn, tcp_full, banner_grab, udp_probe, http_get, sip_invite, syn_flood_test, xmas_scan, null_scan, fin_scan, rst_probe",
                        "default": 80
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of packets / hops for ping, traceroute, syn_flood_test",
                        "default": 4
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Per-packet timeout in seconds (1-10)",
                        "default": 3
                    },
                    "ttl": {
                        "type": "integer",
                        "description": "Custom IP TTL value (1-255) — used for ttl_probe",
                        "default": 64
                    },
                    "vlan_id": {
                        "type": "integer",
                        "description": "Outer VLAN ID for vlan_hop (1-4094)",
                        "default": 1
                    },
                    "vlan_id2": {
                        "type": "integer",
                        "description": "Inner VLAN ID for vlan_hop double-tag (1-4094)",
                        "default": 100
                    },
                    "payload": {
                        "type": "string",
                        "description": "Custom payload string for udp_probe or http_get Host header override"
                    }
                },
                "required": ["target"]
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
        ),
        types.Tool(
            name="query_psirt",
            description=(
                "Query the Cisco PSIRT openVuln API for security advisories. "
                "Use search_term for product search e.g. 'ios-xe', 'ios', 'nx-os'. "
                "Use severity to filter by CRITICAL/HIGH/MEDIUM/LOW. "
                "Use advisory_id for a specific advisory e.g. 'cisco-sa-20240327-ios'. "
                "Returns advisory ID, title, CVSS score, severity, associated CVEs, and publication URL."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search_term": {
                        "type": "string",
                        "description": "Product name to search e.g. 'ios-xe', 'ios', 'nx-os', 'asa'"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity level",
                        "enum": ["critical", "high", "medium", "low", "informational"]
                    },
                    "advisory_id": {
                        "type": "string",
                        "description": "Specific advisory ID e.g. 'cisco-sa-20240327-ios'"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum advisories to return (default 20)",
                        "default": 20
                    }
                },
                "required": []
            }
        ),
        types.Tool(
            name="query_eox",
            description=(
                "Query the Cisco EOX (End of Life / End of Sale) API for product lifecycle dates. "
                "Use pids to look up specific product IDs e.g. 'WS-C3750G-24PS-S,CISCO2811'. "
                "Wildcards supported e.g. 'C9300*'. Comma-separate multiple PIDs. "
                "Use start_date/end_date (MM-DD-YYYY) for date-range queries to find products "
                "reaching EoL in a given window. "
                "Returns End-of-Sale, End-of-SW-Maintenance, Last Date of Support, and migration PIDs. "
                "Products not yet EoL are indicated as such (SSA_ERR_026). "
                "During a device audit, run 'show inventory' then call query_eox with the detected PIDs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pids": {
                        "type": "string",
                        "description": "Comma-separated product IDs e.g. 'WS-C3750G-24PS-S,CISCO2811'. Wildcards allowed: 'C9300*'."
                    },
                    "start_date": {
                        "type": "string",
                        "description": "Start date for date-range search (MM-DD-YYYY) e.g. '01-01-2024'"
                    },
                    "end_date": {
                        "type": "string",
                        "description": "End date for date-range search (MM-DD-YYYY) e.g. '12-31-2025'"
                    }
                },
                "required": []
            }
        ),
        types.Tool(
            name="snmp_get_devices",
            description=(
                "Get the list of all SNMP-monitored devices from the Gladius SNMP monitor, "
                "including their current health status, sysName, sysDescr, uptime, interface count, "
                "and response time. Use this at the start of an audit to discover what devices are "
                "being monitored and their current state."
            ),
            inputSchema={"type": "object", "properties": {}}
        ),
        types.Tool(
            name="snmp_poll",
            description=(
                "Query a network device via SNMP to retrieve system information, interface status, "
                "IP addresses, ARP table, BGP neighbors, or Cisco CPU/memory data. "
                "Available profiles: system (sysName/sysDescr/uptime/location), interfaces (ifTable with "
                "admin/oper status and counters), ip_addresses (IP address table), arp (ARP/neighbor table), "
                "bgp (BGP peer states), cisco_cpu (1min/5min CPU %), cisco_memory (pool used/free). "
                "Use during an audit to correlate SNMP data with SSH findings — e.g. check interface "
                "counters, verify IP addresses, or get CPU/memory baselines."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "host":      {"type": "string", "description": "IP address or hostname of the device"},
                    "profile":   {"type": "string", "description": "Data profile: system | interfaces | ip_addresses | arp | bgp | cisco_cpu | cisco_memory", "default": "system"},
                    "community": {"type": "string", "description": "SNMP community string (default: public)", "default": "public"},
                    "version":   {"type": "string", "description": "SNMP version: 1 | 2c | 3 (default: 2c)", "default": "2c"},
                    "port":      {"type": "integer", "description": "SNMP port (default: 161)", "default": 161},
                },
                "required": ["host"]
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "query_knowledge_base":
        return await _query_knowledge_base(**arguments)
    elif name == "query_design_kb":
        return await _query_design_kb(**arguments)
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
    elif name == "run_nmap_scan":
        return await _run_nmap_scan(**arguments)
    elif name == "run_dig":
        return await _run_dig(**arguments)
    elif name == "run_scapy":
        return await _run_scapy(**arguments)
    elif name == "save_audit_results":
        return await _save_audit_results(**arguments)
    elif name == "query_psirt":
        return await _query_psirt(**arguments)
    elif name == "query_eox":
        return await _query_eox(**arguments)
    elif name == "snmp_get_devices":
        return await _snmp_get_devices()
    elif name == "snmp_poll":
        return await _snmp_poll(**arguments)
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


async def _query_design_kb(query: str, num_results: int = 5) -> list[types.TextContent]:
    log.info(f"Design KB query: '{query}'")
    try:
        design_collection = chroma_client.get_or_create_collection("design-guidelines")
        if design_collection.count() == 0:
            return [types.TextContent(type="text", text="Design knowledge base is empty. No documents have been ingested yet.")]
        query_embedding = embed_model.encode(query).tolist()
        results = design_collection.query(
            query_embeddings=[query_embedding],
            n_results=num_results,
            include=["documents", "metadatas", "distances"]
        )
        if not results["documents"][0]:
            return [types.TextContent(type="text", text="No relevant design guidelines found.")]
        output = f"Design knowledge base results for: '{query}'\n{'=' * 60}\n\n"
        for i, (doc, meta, dist) in enumerate(zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        ), 1):
            relevance = round((1 - dist) * 100, 1)
            output += f"Result {i} - Source: {meta.get('source', 'unknown')} (Relevance: {relevance}%)\n"
            output += "-" * 40 + "\n"
            output += doc + "\n\n"
        return [types.TextContent(type="text", text=output)]
    except Exception as e:
        log.error(f"Design KB query failed: {e}")
        return [types.TextContent(type="text", text=f"ERROR: Design knowledge base query failed: {e}")]


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



async def _run_nmap_scan(
    target: str,
    profile: str = "quick",
    ports: str = None,
    args: str = None,
) -> list[types.TextContent]:
    """Run nmap against the given target and return raw output."""
    import re
    import asyncio
    import shlex
    import subprocess

    # Whitelist target characters — IPs, hostnames, CIDR, IPv6 brackets
    if not re.match(r'^[a-zA-Z0-9.\-_/\[\]:]+$', target):
        return [types.TextContent(type="text", text="ERROR: Invalid target — only IPs, hostnames, and CIDR ranges are accepted.")]

    profile_flags: dict[str, list[str]] = {
        "quick":        ["-T4", "-F"],
        "service":      ["-sV", "-T4"],
        "full_port":    ["-p-", "-T4"],
        "os_detection": ["-O", "-T4"],
        "vuln_scripts": ["--script", "vuln", "-T4"],
        "custom":       [],
    }
    flags = list(profile_flags.get(profile, ["-T4", "-F"]))

    if ports:
        # Strip spaces — Claude sometimes passes "22, 443, 53"
        clean_ports = re.sub(r'\s+', '', ports)
        if re.match(r'^[\d,\-]+$', clean_ports):
            # -F (fast/top-100) and -p (explicit ports) are mutually exclusive in nmap
            flags = [f for f in flags if f != "-F"]
            flags += ["-p", clean_ports]

    if profile == "custom" and args:
        try:
            extra = shlex.split(args)
            safe  = [t for t in extra if re.match(r'^[-a-zA-Z0-9.,_/]+$', t)]
            flags.extend(safe)
        except Exception:
            pass

    cmd = ["nmap"] + flags + [target]
    log.info(f"nmap: {' '.join(cmd)}")

    # Run in a thread executor — avoids asyncio subprocess conflicts with the
    # MCP stdio event loop, and ensures all stdout is fully captured.
    def _blocking_run() -> str:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            out = result.stdout.strip()
            err = result.stderr.strip()
            # Always append stderr — nmap writes errors/warnings there (e.g. flag conflicts)
            if err:
                out = (out + "\n" + err).strip() if out else err
            if not out:
                out = f"nmap exited {result.returncode} with no output."
            return out
        except subprocess.TimeoutExpired:
            return "ERROR: nmap timed out after 5 minutes."
        except FileNotFoundError:
            return "ERROR: nmap not found. Rebuild the MCP container — the dockerfile now installs it."
        except Exception as exc:
            log.error(f"nmap error: {exc}")
            return f"ERROR: {exc}"

    output = await asyncio.to_thread(_blocking_run)
    return [types.TextContent(type="text", text=output)]


async def _run_dig(
    target: str,
    record_type: str = "A",
    resolver: str = None,
    options: str = None,
) -> list[types.TextContent]:
    """Run a dig DNS query and return the raw output."""
    import re
    import asyncio
    import shlex
    import subprocess

    # Validate target — domains, IPs, IPv6, in-addr.arpa
    if not re.match(r'^[a-zA-Z0-9.\-_:/\[\]@]+$', target):
        return [types.TextContent(type="text", text="ERROR: Invalid target — only domain names and IP addresses are accepted.")]

    # Validate record type
    allowed_types = {"A","AAAA","MX","NS","TXT","SOA","CNAME","PTR","SRV","CAA","DNSKEY","DS","AXFR","ANY"}
    record_type = record_type.upper() if record_type else "A"
    if record_type not in allowed_types:
        return [types.TextContent(type="text", text=f"ERROR: Invalid record type '{record_type}'.")]

    cmd = ["dig"]

    # Custom resolver
    if resolver:
        if re.match(r'^[0-9a-fA-F.:]+$', resolver):
            cmd.append(f"@{resolver}")
        else:
            return [types.TextContent(type="text", text="ERROR: Invalid resolver address.")]

    cmd += [target, record_type]

    # Safe option whitelist — allow common +flags only
    if options:
        try:
            extra = shlex.split(options)
            safe_opts = [t for t in extra if re.match(r'^\+?[a-zA-Z0-9\-=]+$', t)]
            cmd.extend(safe_opts)
        except Exception:
            pass

    log.info(f"dig: {' '.join(cmd)}")

    def _blocking_run() -> str:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            out = result.stdout.strip()
            err = result.stderr.strip()
            if err:
                out = (out + "\n" + err).strip() if out else err
            if not out:
                out = f"dig exited {result.returncode} with no output."
            return out
        except subprocess.TimeoutExpired:
            return "ERROR: dig timed out after 30 seconds."
        except FileNotFoundError:
            return "ERROR: dig not found. Install dnsutils in the MCP container."
        except Exception as exc:
            log.error(f"dig error: {exc}")
            return f"ERROR: {exc}"

    output = await asyncio.to_thread(_blocking_run)
    return [types.TextContent(type="text", text=output)]



async def _run_scapy(
    target: str,
    mode: str = "ping",
    port: int = 80,
    count: int = 4,
    timeout: int = 3,
    ttl: int = 64,
    vlan_id: int = 1,
    vlan_id2: int = 100,
    payload: str = "",
) -> list[types.TextContent]:
    """Run a Scapy packet operation and return the results as text."""
    import re
    import asyncio
    import subprocess

    # Sanitise target — allow IPs, hostnames, CIDR
    if not re.match(r'^[a-zA-Z0-9.\-_:/\[\]]+$', target):
        return [types.TextContent(type="text", text="ERROR: Invalid target.")]

    allowed_modes = {
        "ping", "traceroute", "tcp_syn", "tcp_full",
        "arp_scan", "banner_grab", "udp_probe",
        "sip_invite", "http_get", "dns_query",
        "syn_flood_test", "xmas_scan", "null_scan",
        "fin_scan", "rst_probe", "frag_ping",
        "ttl_probe", "os_fingerprint", "vlan_hop",
    }
    if mode not in allowed_modes:
        return [types.TextContent(type="text", text=f"ERROR: Unknown mode '{mode}'.")]

    timeout  = max(1, min(10,    int(timeout)))
    count    = max(1,            int(count))
    port     = max(1, min(65535, int(port)))
    ttl      = max(1, min(255,  int(ttl)))
    vlan_id  = max(1, min(4094, int(vlan_id)))
    vlan_id2 = max(1, min(4094, int(vlan_id2)))
    # Sanitise payload — printable ASCII only
    payload  = re.sub(r'[^\x20-\x7e]', '', str(payload))[:256]

    # ── Scripts ──────────────────────────────────────────────────────────────

    if mode == "ping":
        script = f"""
import time as _time
from scapy.all import IP, ICMP, sr1, conf
conf.verb = 0
results = []
for i in range({count}):
    _t0 = _time.monotonic()
    pkt = sr1(IP(dst="{target}")/ICMP(), timeout={timeout}, verbose=0)
    _rtt = (_time.monotonic() - _t0) * 1000
    if pkt:
        results.append(f"Reply from {{pkt.src}}: ttl={{pkt.ttl}} time={{_rtt:.1f}} ms")
    else:
        results.append("Request timed out")
print("\\n".join(results))
"""

    elif mode == "traceroute":
        script = f"""
from scapy.all import IP, UDP, ICMP, sr1, conf
conf.verb = 0
results = []
for ttl in range(1, {count} + 1):
    pkt = sr1(IP(dst="{target}", ttl=ttl)/UDP(dport=33434+ttl), timeout={timeout}, verbose=0)
    if pkt is None:
        results.append(f"  {{ttl:2d}}  * * *")
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 11:
        results.append(f"  {{ttl:2d}}  {{pkt.src}}")
    elif pkt.haslayer(ICMP) and pkt[ICMP].type == 3:
        results.append(f"  {{ttl:2d}}  {{pkt.src}}  [Destination reached]")
        break
    else:
        results.append(f"  {{ttl:2d}}  {{pkt.src}}")
        break
print(f"Traceroute to {target} (max {count} hops):")
print("\\n".join(results))
"""

    elif mode == "tcp_syn":
        script = f"""
from scapy.all import IP, TCP, sr1, conf
import random
conf.verb = 0
sport = random.randint(1024, 65535)
pkt = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="S"), timeout={timeout}, verbose=0)
if pkt is None:
    print(f"No response from {target}:{port} (filtered or host down)")
elif pkt.haslayer("TCP"):
    flags = pkt["TCP"].flags
    if flags == 0x12:
        print(f"TCP SYN-ACK received from {target}:{port} — port OPEN")
    elif flags == 0x14:
        print(f"TCP RST-ACK received from {target}:{port} — port CLOSED")
    else:
        print(f"TCP response flags={{flags}} from {target}:{port}")
else:
    print(f"Non-TCP response: {{pkt.summary()}}")
"""

    elif mode == "tcp_full":
        script = f"""
from scapy.all import IP, TCP, sr1, send, conf
import random, time
conf.verb = 0
sport = random.randint(1024, 65535)
seq   = random.randint(1000, 9999999)
# Step 1: SYN
syn = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="S", seq=seq), timeout={timeout}, verbose=0)
if syn is None:
    print(f"SYN: No response from {target}:{port}")
elif not syn.haslayer("TCP"):
    print(f"SYN: Non-TCP response — {{syn.summary()}}")
elif syn["TCP"].flags == 0x12:
    print(f"SYN-ACK received from {target}:{port} — port OPEN")
    # Step 2: ACK
    ack_pkt = IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="A",
                  seq=seq+1, ack=syn["TCP"].seq+1)
    send(ack_pkt, verbose=0)
    print(f"ACK sent — 3-way handshake complete")
    # Step 3: RST to tear down cleanly
    time.sleep(0.1)
    rst_pkt = IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="R",
                  seq=seq+1, ack=syn["TCP"].seq+1)
    send(rst_pkt, verbose=0)
    print(f"RST sent — connection torn down cleanly")
elif syn["TCP"].flags & 0x04:
    print(f"RST received from {target}:{port} — port CLOSED")
else:
    print(f"Unexpected flags={{syn['TCP'].flags}} from {target}:{port}")
"""

    elif mode == "arp_scan":
        script = f"""
from scapy.all import ARP, Ether, srp, conf
conf.verb = 0
ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="{target}"), timeout={timeout}, verbose=0)
if not ans:
    print("No hosts responded to ARP on {target}")
else:
    print(f"ARP scan results for {target}:")
    print(f"  {{'IP':<18}} {{'MAC':<20}}")
    print(f"  {{'—'*38}}")
    for snd, rcv in ans:
        print(f"  {{rcv.psrc:<18}} {{rcv.hwsrc:<20}}")
    print(f"\\n{{len(ans)}} host(s) found")
"""

    elif mode == "banner_grab":
        script = f"""
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout({timeout})
    s.connect(("{target}", {port}))
    try:
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        print(f"Banner from {target}:{port}:")
        print(banner if banner else "(no banner received)")
    except Exception:
        print(f"Connected to {target}:{port} but no banner received within {timeout}s")
    s.close()
except ConnectionRefusedError:
    print(f"Connection refused: {target}:{port} is CLOSED")
except socket.timeout:
    print(f"Timeout connecting to {target}:{port} — port may be filtered")
except Exception as e:
    print(f"Error: {{e}}")
"""

    elif mode == "udp_probe":
        probe_payload = payload if payload else "\x00" * 4
        script = f"""
from scapy.all import IP, UDP, ICMP, sr1, conf
conf.verb = 0
data = {repr(probe_payload)}
pkt = sr1(IP(dst="{target}")/UDP(dport={port})/data, timeout={timeout}, verbose=0)
if pkt is None:
    print(f"UDP {target}:{port} — no response (open|filtered)")
elif pkt.haslayer(ICMP):
    icmp = pkt[ICMP]
    if icmp.type == 3 and icmp.code == 3:
        print(f"UDP {target}:{port} — ICMP Port Unreachable (port CLOSED)")
    elif icmp.type == 3:
        print(f"UDP {target}:{port} — ICMP Unreachable type=3 code={{icmp.code}} (filtered)")
    else:
        print(f"UDP {target}:{port} — ICMP type={{icmp.type}} code={{icmp.code}}")
elif pkt.haslayer(UDP):
    print(f"UDP {target}:{port} — UDP response received (port OPEN)")
    print(f"Payload: {{bytes(pkt[UDP].payload)[:64]}}")
else:
    print(f"UDP {target}:{port} — unexpected response: {{pkt.summary()}}")
"""

    elif mode == "sip_invite":
        sip_port = port if port != 80 else 5060
        script = f"""
from scapy.all import IP, UDP, TCP, sr1, send, conf
import random
conf.verb = 0

target   = "{target}"
sip_port = {sip_port}
call_id  = hex(random.randint(0x10000, 0xFFFFFF))[2:]
branch   = hex(random.randint(0x10000, 0xFFFFFF))[2:]
src_ip   = "10.0.0.1"
crlf     = "\\r\\n"

def build_sip(transport):
    lines = [
        f"INVITE sip:1000@{{target}} SIP/2.0",
        f"Via: SIP/2.0/{{transport}} {{src_ip}}:{{sip_port}};branch=z9hG4bK{{branch}}",
        f"From: <sip:gladius@{{src_ip}}>;tag=gladius{{call_id}}",
        f"To: <sip:1000@{{target}}>",
        f"Call-ID: {{call_id}}@{{src_ip}}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:gladius@{{src_ip}}>",
        "Max-Forwards: 70",
        "Content-Type: application/sdp",
        "Content-Length: 0",
        "", "",
    ]
    return crlf.join(lines)

def decode_sip(raw):
    first = raw.split("\\r\\n")[0] if raw else "(empty)"
    detail = ""
    if "100" in first:   detail = "  Trying (proxy is processing)"
    elif "180" in first: detail = "  Ringing"
    elif "200" in first: detail = "  200 OK — SIP service exposed!"
    elif "403" in first: detail = "  Forbidden (auth required)"
    elif "404" in first: detail = "  Not Found"
    elif "405" in first: detail = "  Method Not Allowed"
    elif "486" in first: detail = "  Busy Here"
    elif "401" in first: detail = "  Unauthorised — SIP digest auth required"
    elif "407" in first: detail = "  Proxy Auth Required"
    return first, detail

# ── UDP first ─────────────────────────────────────────────────────
sip_msg = build_sip("UDP")
print(f"[UDP] Sending SIP INVITE to {{target}}:{{sip_port}} ...")
udp_pkt = sr1(
    IP(dst=target)/UDP(dport=sip_port, sport=random.randint(5000,5999))/sip_msg.encode(),
    timeout={timeout}, verbose=0
)

if udp_pkt is not None and udp_pkt.haslayer(UDP):
    raw = bytes(udp_pkt[UDP].payload).decode("utf-8", errors="replace")
    first, detail = decode_sip(raw)
    print(f"[UDP] SIP response from {{target}}:{{sip_port}}")
    print(f"  {{first}}")
    if detail: print(detail)
else:
    print(f"[UDP] No response — port filtered or no SIP/UDP service")
    print(f"[TCP] Trying SIP over TCP {{target}}:{{sip_port}} ...")

    # ── TCP fallback ───────────────────────────────────────────────
    sport = random.randint(10000, 60000)
    seq   = random.randint(1000, 9999999)
    syn_ack = sr1(IP(dst=target)/TCP(sport=sport, dport=sip_port, flags="S", seq=seq),
                  timeout={timeout}, verbose=0)
    if not syn_ack or not syn_ack.haslayer(TCP) or (syn_ack[TCP].flags & 0x12) != 0x12:
        print(f"[TCP] Port {{sip_port}} closed or filtered — no SIP service detected")
    else:
        print(f"[TCP] Port {{sip_port}} OPEN (SYN-ACK from {{syn_ack[IP].src}})")
        seq += 1
        ack_num = syn_ack[TCP].seq + 1
        send(IP(dst=target)/TCP(sport=sport, dport=sip_port, flags="A",
             seq=seq, ack=ack_num), verbose=0)
        sip_msg_tcp = build_sip("TCP")
        resp = sr1(
            IP(dst=target)/TCP(sport=sport, dport=sip_port, flags="PA",
               seq=seq, ack=ack_num)/sip_msg_tcp.encode(),
            timeout={timeout}, verbose=0
        )
        if resp and resp.haslayer("Raw"):
            raw = bytes(resp["Raw"].load).decode("utf-8", errors="replace")
            first, detail = decode_sip(raw)
            print(f"[TCP] SIP response from {{target}}:{{sip_port}}")
            print(f"  {{first}}")
            if detail: print(detail)
        elif resp and resp.haslayer(TCP) and (resp[TCP].flags & 0x04):
            print(f"[TCP] RST received — server rejected connection (likely kernel RST race; port is open)")
        else:
            print(f"[TCP] No SIP response after INVITE (server may require TLS on port 5061)")
"""

    elif mode == "http_get":
        http_port = port if port != 80 else 80
        host_header = payload if payload else target
        script = f"""
from scapy.all import IP, TCP, sr1, sr, send, conf
import random, time
conf.verb = 0
sport = random.randint(1024, 65535)
seq   = random.randint(1000, 9999999)

# SYN
syn = sr1(IP(dst="{target}")/TCP(sport=sport, dport={http_port}, flags="S", seq=seq),
          timeout={timeout}, verbose=0)
if not syn or not syn.haslayer("TCP") or syn["TCP"].flags != 0x12:
    print(f"TCP handshake failed to {target}:{http_port} — port closed or filtered")
    exit()

seq += 1
ack_num = syn["TCP"].seq + 1

# ACK
send(IP(dst="{target}")/TCP(sport=sport, dport={http_port}, flags="A",
     seq=seq, ack=ack_num), verbose=0)

# HTTP GET
crlf = "\\r\\n"
http_req = crlf.join([
    "GET / HTTP/1.1",
    f"Host: {host_header}",
    "User-Agent: Gladius-Security-Scanner/1.0",
    "Accept: */*",
    "Connection: close",
    "",
    "",
])
resp = sr1(
    IP(dst="{target}")/TCP(sport=sport, dport={http_port}, flags="PA",
       seq=seq, ack=ack_num)/http_req.encode(),
    timeout={timeout}, verbose=0
)
if resp and resp.haslayer("TCP") and resp.haslayer("Raw"):
    raw = bytes(resp["Raw"].load).decode("utf-8", errors="replace")
    lines = raw.split("\\r\\n")
    status = lines[0] if lines else "(empty)"
    headers = [l for l in lines[1:] if ":" in l][:12]
    print(f"HTTP response from {target}:{http_port}")
    print(f"Status: {{status}}")
    print("Headers:")
    for h in headers:
        print(f"  {{h}}")
elif resp:
    print(f"TCP response (no HTTP data): {{resp.summary()}}")
else:
    print(f"No response to HTTP GET from {target}:{http_port}")

# RST to close
send(IP(dst="{target}")/TCP(sport=sport, dport={http_port}, flags="R",
     seq=seq+len(http_req), ack=ack_num), verbose=0)
"""

    elif mode == "dns_query":
        script = f"""
from scapy.all import IP, UDP, DNS, DNSQR, sr1, conf
conf.verb = 0
pkt = sr1(
    IP(dst="{target}")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="{target}")),
    timeout={timeout}, verbose=0
)
if pkt is None:
    print(f"No DNS response from {target}:53 (not a resolver or filtered)")
elif pkt.haslayer(DNS):
    dns = pkt[DNS]
    print(f"DNS response from {target}:53")
    print(f"  RCODE: {{dns.rcode}} ({{'NOERROR' if dns.rcode==0 else 'ERROR'}})")
    print(f"  Answers: {{dns.ancount}}")
    if dns.ancount > 0:
        an = dns.an
        while an:
            try:
                print(f"  → {{an.rrname.decode()}} {{an.type}} {{an.rdata}}")
            except Exception:
                print(f"  → {{an.summary()}}")
            an = an.payload if an.payload and hasattr(an.payload, 'rrname') else None
    if dns.rcode == 0 and dns.ancount == 0:
        print("  (Open resolver responded but no A record found for this target)")
else:
    print(f"Unexpected response: {{pkt.summary()}}")
"""

    elif mode == "syn_flood_test":
        script = f"""
from scapy.all import IP, TCP, send, conf
import random, time
conf.verb = 0
print(f"SYN flood test: sending {count} SYN packets to {target}:{port}")
sent = 0
for _ in range({count}):
    sport = random.randint(1024, 65535)
    seq   = random.randint(0, 0xFFFFFF)
    send(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="S", seq=seq), verbose=0)
    sent += 1
    time.sleep(0.01)
print(f"Sent {{sent}} SYN packets — check target for SYN_RECV state accumulation")
"""

    elif mode == "xmas_scan":
        script = f"""
from scapy.all import IP, TCP, sr1, conf
import random
conf.verb = 0
sport = random.randint(1024, 65535)
# Xmas: FIN(0x01) + PSH(0x08) + URG(0x20) = 0x29
pkt = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags=0x29), timeout={timeout}, verbose=0)
if pkt is None:
    print(f"Xmas scan {target}:{port} — No response → port OPEN or FILTERED (RFC 793)")
elif pkt.haslayer("TCP") and pkt["TCP"].flags & 0x04:
    print(f"Xmas scan {target}:{port} — RST received → port CLOSED")
elif pkt.haslayer("ICMP"):
    print(f"Xmas scan {target}:{port} — ICMP unreachable → port FILTERED")
else:
    print(f"Xmas scan {target}:{port} — Unexpected: {{pkt.summary()}}")
"""

    elif mode == "null_scan":
        script = f"""
from scapy.all import IP, TCP, sr1, conf
import random
conf.verb = 0
sport = random.randint(1024, 65535)
pkt = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags=0), timeout={timeout}, verbose=0)
if pkt is None:
    print(f"Null scan {target}:{port} — No response → port OPEN or FILTERED")
elif pkt.haslayer("TCP") and pkt["TCP"].flags & 0x04:
    print(f"Null scan {target}:{port} — RST received → port CLOSED")
elif pkt.haslayer("ICMP"):
    print(f"Null scan {target}:{port} — ICMP unreachable → FILTERED")
else:
    print(f"Null scan {target}:{port} — Unexpected: {{pkt.summary()}}")
"""

    elif mode == "fin_scan":
        script = f"""
from scapy.all import IP, TCP, sr1, conf
import random
conf.verb = 0
sport = random.randint(1024, 65535)
pkt = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="F"), timeout={timeout}, verbose=0)
if pkt is None:
    print(f"FIN scan {target}:{port} — No response → port OPEN or FILTERED (RFC 793)")
elif pkt.haslayer("TCP") and pkt["TCP"].flags & 0x04:
    print(f"FIN scan {target}:{port} — RST received → port CLOSED")
elif pkt.haslayer("ICMP"):
    print(f"FIN scan {target}:{port} — ICMP unreachable → FILTERED")
else:
    print(f"FIN scan {target}:{port} — Unexpected: {{pkt.summary()}}")
"""

    elif mode == "rst_probe":
        script = f"""
from scapy.all import IP, TCP, sr1, conf
import random
conf.verb = 0
sport = random.randint(1024, 65535)
# Send RST — a stateful firewall will silently drop it; a stateless one may pass it
pkt = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="R", seq=1000),
          timeout={timeout}, verbose=0)
if pkt is None:
    print(f"RST probe {target}:{port} — No response (stateful firewall likely dropped it)")
elif pkt.haslayer("TCP"):
    flags = pkt["TCP"].flags
    print(f"RST probe {target}:{port} — TCP response flags={{flags}} (unexpected — may be stateless device)")
elif pkt.haslayer("ICMP"):
    print(f"RST probe {target}:{port} — ICMP response: {{pkt['ICMP'].type}}/{{pkt['ICMP'].code}}")
else:
    print(f"RST probe {target}:{port} — Unexpected: {{pkt.summary()}}")
"""

    elif mode == "frag_ping":
        script = f"""
from scapy.all import IP, ICMP, fragment, sr, conf
conf.verb = 0
# Build a large ICMP packet and fragment it into 2 fragments (tests fragment reassembly)
big_pkt = IP(dst="{target}")/ICMP()/("X"*600)
frags   = fragment(big_pkt, fragsize=300)
print(f"Sending {{len(frags)}} ICMP fragments to {target}...")
ans, unans = sr(frags, timeout={timeout}, verbose=0)
if ans:
    for snd, rcv in ans:
        print(f"Reply from {{rcv.src}}: ttl={{rcv.ttl}}")
    print(f"\\nFragmented ICMP reassembled correctly — host processes IP fragments")
else:
    print(f"No reply to fragmented ICMP — host may be filtering fragments or is down")
"""

    elif mode == "ttl_probe":
        script = f"""
from scapy.all import IP, ICMP, sr1, conf
conf.verb = 0
pkt = sr1(IP(dst="{target}", ttl={ttl})/ICMP(), timeout={timeout}, verbose=0)
if pkt is None:
    print(f"TTL probe TTL={ttl} → {target} — No response (host unreachable at this TTL or filtered)")
elif pkt.haslayer(ICMP):
    icmp = pkt[ICMP]
    if icmp.type == 11:
        print(f"TTL probe TTL={ttl} — ICMP Time Exceeded from {{pkt.src}}")
        print(f"  → Intermediate hop at TTL={ttl}: {{pkt.src}}")
    elif icmp.type == 0:
        print(f"TTL probe TTL={ttl} — Echo Reply from {{pkt.src}} (host reached within TTL={ttl})")
        print(f"  → {target} is at most {ttl} hop(s) away")
    elif icmp.type == 3:
        print(f"TTL probe TTL={ttl} — ICMP Unreachable from {{pkt.src}} (code={{icmp.code}})")
    else:
        print(f"TTL probe TTL={ttl} — ICMP type={{icmp.type}} from {{pkt.src}}")
else:
    print(f"TTL probe TTL={ttl} — Non-ICMP response: {{pkt.summary()}}")
"""

    elif mode == "os_fingerprint":
        script = f"""
from scapy.all import IP, TCP, ICMP, UDP, sr1, conf
import random
conf.verb = 0
results = []
sport = random.randint(1024, 65535)

# Probe 1: TCP SYN — check window size + options (key OS fingerprint indicators)
syn = sr1(IP(dst="{target}")/TCP(sport=sport, dport={port}, flags="S",
              options=[("MSS",1460),("SAckOK",""),("Timestamp",(0,0),),("WScale",7)]),
          timeout={timeout}, verbose=0)
if syn and syn.haslayer("TCP"):
    tcp = syn["TCP"]
    results.append(f"TCP SYN response:")
    results.append(f"  Window size : {{tcp.window}}")
    results.append(f"  Flags       : {{tcp.flags}}")
    results.append(f"  Options     : {{tcp.options}}")
    win = tcp.window
    if win == 65535:
        results.append("  → Window=65535: likely macOS/BSD")
    elif win == 8192:
        results.append("  → Window=8192: likely older Windows")
    elif win in (5840, 5792, 14600, 29200, 65483):
        results.append("  → Common Linux window size")
    elif 14000 <= win <= 16000:
        results.append("  → Possible Cisco IOS")
    else:
        results.append(f"  → Window={win}: unknown or modern OS (auto-tuning)")
else:
    results.append(f"TCP SYN to {target}:{port} — no response")

# Probe 2: ICMP echo — check TTL for OS distance estimation
icmp = sr1(IP(dst="{target}")/ICMP(), timeout={timeout}, verbose=0)
if icmp:
    ttl = icmp.ttl
    results.append(f"ICMP Echo Reply TTL: {{ttl}}")
    if ttl >= 128:
        results.append(f"  → TTL {{ttl}}: likely Windows (default 128)")
    elif ttl >= 64:
        results.append(f"  → TTL {{ttl}}: likely Linux/macOS (default 64)")
    elif ttl >= 60:
        results.append(f"  → TTL {{ttl}}: possibly Cisco IOS (default 255, reduced)")
    else:
        results.append(f"  → TTL {{ttl}}: possibly many hops away or uncommon OS")
else:
    results.append("ICMP — no echo reply")

print("\\n".join(results))
"""

    elif mode == "vlan_hop":
        script = f"""
from scapy.all import Ether, Dot1Q, IP, ICMP, sendp, conf
conf.verb = 0
# 802.1Q double-tagging VLAN hopping frame
# Outer tag = native VLAN (trunk port VLAN), inner tag = target VLAN
pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    Dot1Q(vlan={vlan_id}) /          # Outer tag — stripped by switch
    Dot1Q(vlan={vlan_id2}) /         # Inner tag — forwarded into target VLAN
    IP(dst="{target}") /
    ICMP()
)
print(f"VLAN hopping frame: outer VLAN={vlan_id} → inner VLAN={vlan_id2} → {target}")
print(f"Sending on default interface (requires trunk/access port in VLAN {vlan_id})...")
try:
    sendp(pkt, verbose=0, count=3)
    print(f"3 double-tagged frames sent.")
    print(f"  If the switch trunk port uses VLAN {vlan_id} as native VLAN (untagged),")
    print(f"  the outer tag is stripped and the inner VLAN {vlan_id2} frame is forwarded.")
    print(f"  Mitigation: never use VLAN 1 as native VLAN; set all trunk ports explicitly.")
except Exception as e:
    print(f"Send error: {{e}}")
"""

    else:
        script = f'print("ERROR: mode not implemented")'

    # ── subprocess runner ──────────────────────────────────────────────────
    def _blocking_run() -> str:
        try:
            result = subprocess.run(
                ["python3", "-c", script],
                capture_output=True,
                text=True,
                timeout=max(60, timeout * count * 2 + 15),
            )
            out = result.stdout.strip()
            err = result.stderr.strip()
            if err:
                err_lines = [l for l in err.splitlines() if not any(x in l for x in
                    ["WARNING", "Scapy", "DeprecationWarning", "conf", "IPv6",
                     "pcap", "libpcap", "UserWarning", "FutureWarning"])]
                err = "\n".join(err_lines).strip()
            if err:
                out = (out + "\n" + err).strip() if out else err
            return out if out else f"(no output from scapy {mode})"
        except subprocess.TimeoutExpired:
            return f"ERROR: Scapy {mode} timed out."
        except Exception as exc:
            log.error(f"scapy error: {exc}")
            return f"ERROR: {exc}"

    output = await asyncio.to_thread(_blocking_run)
    return [types.TextContent(type="text", text=output)]


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


async def _query_psirt(
    search_term: str = None,
    severity: str = None,
    advisory_id: str = None,
    max_results: int = 20,
) -> list[types.TextContent]:
    """Query the Cisco PSIRT openVuln API for security advisories."""
    if not PSIRT_CLIENT_KEY or not PSIRT_CLIENT_SECRET:
        return [types.TextContent(type="text", text="ERROR: PSIRT_CLIENT_KEY and PSIRT_CLIENT_SECRET not configured.")]

    log.info(f"PSIRT query: search_term='{search_term}' severity={severity} advisory_id={advisory_id}")

    # Get OAuth token
    try:
        token_resp = requests.post(
            PSIRT_TOKEN_URL,
            data={
                "grant_type":    "client_credentials",
                "client_id":     PSIRT_CLIENT_KEY,
                "client_secret": PSIRT_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")
        if not token:
            return [types.TextContent(type="text", text="ERROR: PSIRT OAuth token request returned no token.")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: PSIRT auth failed — {e}")]

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # Choose endpoint
    try:
        if advisory_id:
            url = f"{PSIRT_API_BASE}/advisory/{advisory_id}"
            params = {}
        elif search_term:
            url = f"{PSIRT_API_BASE}/product"
            params = {"product": search_term}
        elif severity:
            url = f"{PSIRT_API_BASE}/severity/{severity.lower()}"
            params = {}
        else:
            url = f"{PSIRT_API_BASE}/latest/{min(max_results, 100)}"
            params = {}

        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: PSIRT API call failed — {e}")]

    advisories = data.get("advisories", [])
    if not advisories and "advisoryId" in data:
        advisories = [data]  # single advisory lookup

    if not advisories:
        return [types.TextContent(type="text", text="No advisories found for the given criteria.")]

    # Build output
    label = f"Cisco PSIRT Advisories"
    if advisory_id:
        label += f" — {advisory_id}"
    elif search_term:
        label += f" — Product: {search_term}"
    elif severity:
        label += f" — Severity: {severity.upper()}"
    else:
        label += f" — Latest {len(advisories)}"

    output = f"{label}\n{'=' * 60}\n\n"

    for adv in advisories[:max_results]:
        adv_id    = adv.get("advisoryId", "Unknown")
        title     = adv.get("advisoryTitle", "No title")
        cvss      = adv.get("cvssBaseScore", "N/A")
        sir       = adv.get("sir", "").upper()
        cves      = ", ".join(adv.get("cves", [])) or "—"
        published = adv.get("firstPublished", "")[:10]
        url_link  = adv.get("publicationUrl", "")
        summary   = adv.get("summary", "")

        output += f"[{sir}] {adv_id}\n"
        output += f"Title    : {title}\n"
        output += f"CVSS     : {cvss}  Published: {published}\n"
        output += f"CVEs     : {cves}\n"
        if url_link:
            output += f"URL      : {url_link}\n"
        if summary:
            output += f"Summary  : {summary[:300]}{'…' if len(summary) > 300 else ''}\n"
        output += "\n"

    output += f"Total shown: {min(len(advisories), max_results)}"
    return [types.TextContent(type="text", text=output)]


async def _query_eox(
    pids: str = None,
    start_date: str = None,
    end_date: str = None,
) -> list[types.TextContent]:
    """Query the Cisco EOX API for product End-of-Life / End-of-Sale dates."""
    if not EOX_CLIENT_KEY or not EOX_CLIENT_SECRET:
        return [types.TextContent(type="text", text="ERROR: EOX_CLIENT_KEY and EOX_CLIENT_SECRET not configured.")]
    if not pids and not (start_date and end_date):
        return [types.TextContent(type="text", text="ERROR: Provide pids or both start_date and end_date (MM-DD-YYYY).")]

    log.info(f"EOX query: pids='{pids}' start='{start_date}' end='{end_date}'")

    # Get OAuth token (same Cisco OAuth endpoint as PSIRT)
    try:
        token_resp = requests.post(
            PSIRT_TOKEN_URL,
            data={
                "grant_type":    "client_credentials",
                "client_id":     EOX_CLIENT_KEY,
                "client_secret": EOX_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")
        if not token:
            return [types.TextContent(type="text", text="ERROR: EOX OAuth token request returned no token.")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: EOX auth failed — {e}")]

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    try:
        if pids:
            pid_str = pids.strip().rstrip(",")
            url = f"{EOX_API_BASE}/EOXByProductID/1/{pid_str}"
        else:
            url = f"{EOX_API_BASE}/EOXByDates/1/{start_date}/{end_date}"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: EOX API call failed — {e}")]

    records = data.get("EOXRecord", [])
    if not records:
        return [types.TextContent(type="text", text="No EOX records returned.")]

    def get_date(field):
        return (field.get("value") or "") if isinstance(field, dict) else ""

    output_lines = []
    found = 0
    skipped = 0

    for rec in records:
        err = rec.get("EOXError", {}) or {}
        err_id = err.get("ErrorID", "")
        if err_id:
            pid_val = rec.get("EOXInputValue", "?")
            if "026" in err_id:
                skipped += 1
                output_lines.append(f"{pid_val}: Not yet EoL (SSA_ERR_026 — no EoX record)\n")
            else:
                output_lines.append(f"{pid_val}: Error — {err_id}: {err.get('ErrorDescription', '')}\n")
            continue

        found += 1
        pid  = rec.get("EOLProductID") or rec.get("EOXInputValue", "?")
        desc = rec.get("ProductIDDescription", "")
        eos  = get_date(rec.get("EndOfSaleDate"))
        swm  = get_date(rec.get("EndOfSWMaintenanceReleases"))
        ldos = get_date(rec.get("LastDateOfSupport"))
        mig  = (rec.get("EOXMigrationDetails") or {}).get("MigrationProductId", "") or "—"
        bull = rec.get("LinkToProductBulletinURL", "")

        output_lines.append(f"PID:      {pid}")
        if desc:
            output_lines.append(f"Name:     {desc}")
        output_lines.append(f"EoS:      {eos or '—'}")
        output_lines.append(f"SW Maint: {swm or '—'}")
        output_lines.append(f"LDoS:     {ldos or '—'}")
        output_lines.append(f"Migrate:  {mig}")
        if bull:
            output_lines.append(f"Bulletin: {bull}")
        output_lines.append("")

    label = "Cisco EOX Results"
    if pids:
        label += f" — {pids}"
    else:
        label += f" — {start_date} to {end_date}"
    summary = f"EoX records: {found}"
    if skipped:
        summary += f" | Not yet EoL: {skipped}"
    output = f"{label}\n{'=' * 60}\n\n" + "\n".join(output_lines) + f"\n{summary}"
    return [types.TextContent(type="text", text=output)]


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


async def _snmp_get_devices() -> list[types.TextContent]:
    """Return all SNMP-monitored devices and their current status."""
    try:
        resp = requests.get(f"{SNMP_SERVICE_URL}/devices", timeout=5)
        resp.raise_for_status()
        devices = resp.json().get("devices", [])
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: SNMP service unreachable — {e}")]

    if not devices:
        return [types.TextContent(type="text", text="No devices registered in the SNMP monitor.")]

    status_icon = {"ok": "✓", "warn": "⚠", "error": "✗", "unknown": "?"}
    lines = [f"SNMP Monitored Devices ({len(devices)} total)", "=" * 60]
    for d in devices:
        icon    = status_icon.get(d.get("status", "unknown"), "?")
        name    = d.get("name", d.get("host", "—"))
        host    = d.get("host", "—")
        sysname = d.get("sysName") or "—"
        descr   = (d.get("sysDescr") or "—")[:80]
        uptime  = d.get("sysUpTime") or "—"
        ifaces  = d.get("ifNumber") or "—"
        rtt     = f"{d['response_ms']}ms" if d.get("response_ms") is not None else "—"
        err     = f" [{d['error']}]" if d.get("error") else ""
        lines.append(
            f"\n{icon} {name} ({host})\n"
            f"  Hostname : {sysname}\n"
            f"  Descr    : {descr}\n"
            f"  Uptime   : {uptime}  Interfaces: {ifaces}  RTT: {rtt}{err}"
        )

    return [types.TextContent(type="text", text="\n".join(lines))]


async def _snmp_poll(
    host: str,
    profile: str = "system",
    community: str = "public",
    version: str = "2c",
    port: int = 161,
) -> list[types.TextContent]:
    """Ad-hoc SNMP poll of any device using a named profile."""
    log.info(f"SNMP poll: {host} profile={profile}")
    try:
        resp = requests.post(
            f"{SNMP_SERVICE_URL}/poll",
            json={"host": host, "port": port, "version": version,
                  "community": community, "profile": profile},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [types.TextContent(type="text", text=f"ERROR: SNMP poll failed — {e}")]

    results = data.get("results", [])
    if not results:
        return [types.TextContent(type="text", text=f"No SNMP data returned from {host} (profile: {profile})")]

    lines = [f"SNMP {profile.upper()} — {host}  ({data.get('elapsed_ms', '?')}ms  {len(results)} rows)", "=" * 60]
    for r in results:
        label = r.get("label") or r.get("oid", "")
        lines.append(f"  {label:<30} {r.get('value', '')}")

    return [types.TextContent(type="text", text="\n".join(lines))]


async def main():
    log.info("Network Audit MCP Server starting...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())