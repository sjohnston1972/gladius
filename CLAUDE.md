# Gladius — Project Brief for Claude Code

## repo - https://github.com/sjohnston1972/gladius

## main project file locations
gladius-api  - C:\docker\net-core\gladius-api
network-audit-mcp - C:\docker\net-core\network-audit-mcp
frontend - C:\docker\net-core\web-projects\gladius


## What Is This

Gladius is a cyberpunk-themed network security audit platform running as a homelab Docker stack.
A user types into a web UI chat, which talks to a FastAPI backend, which drives an AI agent
(Claude claude-sonnet-4-6) via MCP tools that SSH into Cisco network devices, run security checks,
query a NIST/CIS knowledge base, look up CVEs, and save structured results back to the dashboard.

---

## Docker Stack

| Container | Purpose | Internal Port |
|---|---|---|
| `gladius-api` | FastAPI — Claude agent, SSE stream, API endpoints | 8080 |
| `network-audit-mcp` | MCP server — all tools (SSH, ChromaDB, NVD, email) | stdio |
| `chroma-db` | ChromaDB vector store — NIST/CIS knowledge base | 8000 |
| `web-projects` | nginx — serves `index.html` static frontend | 80/443 |

`gladius-api` spawns `network-audit-mcp` as a subprocess via stdio (MCP protocol).
There is no direct HTTP between them except for `save_audit_results` which POSTs back to
`gladius-api` at `http://gladius-api:8080/api/audit/save`.

---

## File Locations (in containers)

```
gladius-api          → /app/server.py
network-audit-mcp    → /app/server.py
web-projects         → /usr/share/nginx/html/index.html   (or check nginx config)
```
## File Locations (in windows)

```
gladius-api  - C:\docker\net-core\gladius-api
network-audit-mcp - C:\docker\net-core\network-audit-mcp
frontend - C:\docker\net-core\web-projects\gladius
```

---

## File Structure

```
gladius/
├── gladius-api/
│   └── server.py          # FastAPI app — Claude agent, SSE, all HTTP endpoints
├── network-audit-mcp/
│   └── server.py          # MCP server — all Claude tools
└── web-projects/gladius/
    └── index.html         # Entire frontend — single file, vanilla JS
```

---

## gladius-api/server.py

FastAPI application. Key responsibilities:

- Caches MCP tool list at startup via `discover_tools()`
- `POST /api/chat` — receives messages, opens a fresh MCP subprocess per request, runs the
  Claude agentic loop with tool use, streams results back as SSE
- `POST /api/audit/save` — receives structured audit results from the MCP `save_audit_results`
  tool, stores in `_pending_audit` global
- `POST /api/email` — receives pre-built HTML report from browser, passes to MCP `send_email`
  tool as an attachment (bypasses Claude for formatting)
- `GET /api/health` and `GET /api/health/full` — health checks for all components
- `GET /api/kb/stats` — returns ChromaDB vector count

### SSE Event Types (streamed to browser)

| Event type | Meaning |
|---|---|
| `text` | Claude text chunk |
| `tool_start` | Claude is calling a tool |
| `tool_done` | Tool call completed |
| `audit_saved` | `save_audit_results` succeeded — contains full audit object |
| `send_templated_email` | Intercept: browser should generate HTML and call `/api/email` |
| `done` | Stream complete |
| `error` | Something failed |

### Key Globals

```python
_pending_audit: dict | None   # Set by /api/audit/save, consumed by SSE stream → audit_saved event
_last_audit: dict | None      # Same data, kept for send_email intercept
_last_claude_success: float   # Monotonic timestamp of last successful Claude response
cached_tools: list            # MCP tool list cached at startup
```

### send_email Intercept

When Claude calls `send_email` and `_last_audit` exists, the API does NOT forward the call to
the MCP server. Instead it emits a `send_templated_email` SSE event to the browser, which then
calls `generateReportHTML()` in JS and POSTs the HTML to `/api/email`. This ensures the
templated report is always sent rather than Claude's improvised plain-text version.

---

## network-audit-mcp/server.py

MCP server, runs as a stdio subprocess. All tools:

| Tool | What it does |
|---|---|
| `connect_to_device` | SSH into a device via Paramiko, stores session in global |
| `run_show_command` | Runs a show command on the connected device |
| `push_config` | Pushes config commands to the device |
| `disconnect_device` | Closes the SSH session |
| `query_knowledge_base` | Semantic search against ChromaDB NIST/CIS knowledge base |
| `query_nvd` | Queries NIST NVD API for CVEs (supports cisco_only=True, days_back, severity) |
| `get_cve_details` | Gets full details for a specific CVE ID |
| `send_email` | Sends email via SMTP — supports plain text body or HTML attachment |
| `save_audit_results` | POSTs structured audit data to `gladius-api /api/audit/save` |

### save_audit_results (recently added — critical)

This was missing from the MCP server and is why report history wasn't working. It now:
1. Accepts `device`, `ip`, `ios`, `timestamp`, `findings[]`, `score{}`
2. POSTs to `$GLADIUS_API_URL/api/audit/save` (default: `http://gladius-api:8080`)
3. gladius-api stores result in `_pending_audit`
4. The active SSE stream detects the tool completed and emits `audit_saved` to the browser

---

## web-projects/index.html

Single-file frontend, ~5000 lines of vanilla JS + CSS. No framework, no build step.

### Key JS Functions

| Function | Purpose |
|---|---|
| `sendMessage()` | Sends chat message to `/api/chat`, handles SSE stream |
| `onToolStart(name, input)` | Renders tool activity in chat bubble |
| `loadDashboard()` | Reads localStorage, updates dashboard stats/findings |
| `renderReports()` | Reads `gladius-audit-history` from localStorage, renders Reports tab |
| `renderFindings()` | Renders findings list with severity filtering |
| `generateReportHTML(audit)` | Generates complete standalone HTML report (same as export) |
| `exportReport(idx)` | Downloads HTML report as a file |
| `emailReport(idx)` | POSTs generated HTML to `/api/email` as attachment |
| `buildAuditContext()` | Injects last 3 audits as context before every chat message |
| `logActivity(text, hi)` | Adds entry to activity log |
| `setSkin(name)` | Switches colour theme |

### localStorage Keys

| Key | Contents |
|---|---|
| `gladius-audit-latest` | Most recent audit object (full) |
| `gladius-audit-history` | Array of last 10 audits, newest first |
| `gladius-skin` | Active colour theme name |
| `gladius-qcmds` | User-defined quick command buttons |

### Audit Object Schema

```json
{
  "device":    "SW-CORE-01",
  "ip":        "10.0.0.1",
  "ios":       "IOS XE 17.6.1",
  "timestamp": "2026-02-28T12:00:00Z",
  "score": {
    "overall": 72,
    "nist":    65,
    "cis":     70
  },
  "findings": [
    {
      "title":    "SSH version 1 enabled",
      "severity": "HIGH",
      "type":     "hardening",
      "category": "Access Security",
      "impact":   "...",
      "fix":      "...",
      "commands": "crypto key generate rsa modulus 2048, ip ssh version 2",
      "ref":      "https://..."
    },
    {
      "title":    "CVE-2024-20399",
      "severity": "CRITICAL",
      "type":     "cve",
      "cve_id":   "CVE-2024-20399",
      "impact":   "...",
      "fix":      "...",
      "ref":      "https://nvd.nist.gov/vuln/detail/CVE-2024-20399"
    }
  ]
}
```

### Colour Themes (Skins)

9 themes stored in `data-skin` attribute on `<html>`:
`gladius`, `hispaniensis`, `mainz`, `fulham`, `pompeii`, `spatha`, `pugio`, `parazonium`, `rudis`

All colours are CSS variables — `--accent`, `--bg`, `--surface`, `--text`, etc.

---

## Environment Variables

### gladius-api (.env)

```
ANTHROPIC_API_KEY=        # Required — Claude API key
CHROMA_HOST=chroma-db     # ChromaDB hostname (Docker service name)
CHROMA_PORT=8000
```

### network-audit-mcp (.env)

```
CHROMA_HOST=chroma-db
CHROMA_PORT=8000
COLLECTION_NAME=network_security_guidelines
EMBED_MODEL=all-MiniLM-L6-v2

NIST_API_KEY=             # NVD API key (optional but recommended to avoid rate limits)

LAB_USERNAME=             # Default SSH username for device connections
LAB_PASSWORD=             # Default SSH password for device connections

SMTP_SERVER=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_NAME=Gladius
DEFAULT_RECIPIENT=        # Default email address for reports

GLADIUS_API_URL=http://gladius-api:8080   # Used by save_audit_results to POST back
```

---

## Data Flow: Full Audit

```
User types "audit 10.0.0.1"
  → sendMessage() POSTs to /api/chat
  → gladius-api opens MCP subprocess
  → Claude receives message + tools list
  → Claude calls connect_to_device(host="10.0.0.1")
  → Claude calls run_show_command() multiple times
  → Claude calls query_knowledge_base() for each finding
  → Claude calls query_nvd(cisco_only=True, search_term="IOS XE 17.6.1")
  → Claude calls save_audit_results(device, ip, findings, score)
      → MCP POSTs to gladius-api /api/audit/save
      → _pending_audit set in gladius-api
      → SSE stream emits audit_saved event with full audit object
      → Browser writes to localStorage (gladius-audit-latest + gladius-audit-history)
      → renderReports() called → Reports tab updates
      → loadDashboard() called → Dashboard stats update
  → Claude calls disconnect_device()
  → Claude presents summary in chat
```

## Data Flow: Email Report

```
User clicks ✉ Email button (Reports tab)  OR  asks Gladius "email me the report"

Via button:
  emailReport(idx) → generateReportHTML(audit) → POST /api/email {subject, html, filename}
  → gladius-api → MCP send_email(attachment_html=...) → SMTP

Via chat:
  Claude calls send_email() → gladius-api intercepts (send_email + _last_audit exists)
  → emits send_templated_email SSE event → browser generateReportHTML() → POST /api/email
  → same path as above
```

---

## Known Issues / Recent Changes

- `save_audit_results` was missing from the MCP server tool list entirely — added Feb 2026.
  This was why report history was not being written. The tool now POSTs to `/api/audit/save`.

- Email reports now send as HTML attachments (not inline HTML) to avoid rendering issues
  in email clients.

- The `send_email` tool intercept in gladius-api means Claude's plain-text email attempts
  are silently replaced with the templated HTML version.

- gladius-api caches the MCP tool list at startup. After updating network-audit-mcp,
  always restart gladius-api too so it picks up new tools.

---

## Deployment Notes

```bash
# After changing gladius-api/server.py:
docker cp server.py gladius-api:/app/server.py
docker restart gladius-api

# After changing network-audit-mcp/server.py:
docker cp server.py network-audit-mcp:/app/server.py
docker restart network-audit-mcp
docker restart gladius-api   # ← always do this too — refreshes tool cache

# After changing index.html:
docker cp index.html web-projects:/usr/share/nginx/html/index.html
# No restart needed — nginx serves it statically
```