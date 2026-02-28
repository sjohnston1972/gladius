<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gladius — Network Security Audit Platform</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:wght@200;300;400&display=swap');

  :root {
    --red:     #c0392b;
    --red-dim: #7a1f16;
    --gold:    #c9a84c;
    --steel:   #8fa3b1;
    --bg:      #0a0c0f;
    --surface: #111318;
    --surface2:#161a1f;
    --border:  #1e2530;
    --text:    #c8d0d8;
    --dim:     #4a5568;
    --mono:    'Share Tech Mono', monospace;
    --sans:    'Rajdhani', sans-serif;
    --light:   'Exo 2', sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--light);
    font-weight: 300;
    line-height: 1.7;
    overflow-x: hidden;
  }

  /* ── Noise overlay ─────────────────────────────────────────────────────── */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
    opacity: 0.6;
  }

  /* ── Hero ──────────────────────────────────────────────────────────────── */
  .hero {
    position: relative;
    min-height: 420px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 80px 40px 60px;
    text-align: center;
    overflow: hidden;
    border-bottom: 1px solid var(--border);
  }

  .hero::after {
    content: '';
    position: absolute;
    inset: 0;
    background:
      radial-gradient(ellipse 60% 50% at 50% 0%, rgba(192,57,43,0.12) 0%, transparent 70%),
      radial-gradient(ellipse 40% 30% at 50% 100%, rgba(201,168,76,0.06) 0%, transparent 60%);
    pointer-events: none;
  }

  /* Sword logo */
  .hero-logo {
    width: 56px;
    height: 56px;
    margin-bottom: 28px;
    filter: drop-shadow(0 0 12px rgba(192,57,43,0.6));
    animation: pulse-glow 3s ease-in-out infinite;
  }

  @keyframes pulse-glow {
    0%, 100% { filter: drop-shadow(0 0 10px rgba(192,57,43,0.5)); }
    50%       { filter: drop-shadow(0 0 22px rgba(192,57,43,0.9)); }
  }

  .hero-eyebrow {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 4px;
    color: var(--red);
    text-transform: uppercase;
    margin-bottom: 16px;
  }

  .hero h1 {
    font-family: var(--sans);
    font-size: clamp(52px, 8vw, 96px);
    font-weight: 700;
    letter-spacing: -1px;
    line-height: 1;
    background: linear-gradient(135deg, #e8eaed 0%, #8fa3b1 50%, #c0392b 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 8px;
  }

  .hero-sub {
    font-family: var(--sans);
    font-size: 18px;
    font-weight: 300;
    color: var(--steel);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 32px;
  }

  .hero-desc {
    max-width: 620px;
    font-size: 16px;
    color: var(--dim);
    line-height: 1.8;
    margin-bottom: 40px;
  }

  .badges {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    justify-content: center;
  }

  .badge {
    font-family: var(--mono);
    font-size: 11px;
    padding: 5px 12px;
    border-radius: 3px;
    letter-spacing: 1px;
  }

  .badge-red    { background: rgba(192,57,43,0.15); color: #e57373; border: 1px solid rgba(192,57,43,0.3); }
  .badge-gold   { background: rgba(201,168,76,0.12); color: #d4a853; border: 1px solid rgba(201,168,76,0.25); }
  .badge-steel  { background: rgba(143,163,177,0.1); color: #8fa3b1; border: 1px solid rgba(143,163,177,0.2); }

  /* ── Screenshot placeholder ─────────────────────────────────────────────── */
  .screenshot-section {
    padding: 60px 40px;
    border-bottom: 1px solid var(--border);
    position: relative;
    z-index: 1;
  }

  .screenshot-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    max-width: 1100px;
    margin: 40px auto 0;
  }

  .screenshot-slot {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    aspect-ratio: 16/9;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    position: relative;
    overflow: hidden;
  }

  .screenshot-slot img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: 5px;
  }

  .screenshot-slot .slot-label {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--dim);
    letter-spacing: 2px;
    text-transform: uppercase;
  }

  .screenshot-slot .slot-icon {
    font-size: 28px;
    opacity: 0.2;
  }

  /* corner brackets on slots */
  .screenshot-slot::before,
  .screenshot-slot::after {
    content: '';
    position: absolute;
    width: 14px;
    height: 14px;
    border-color: var(--red-dim);
    border-style: solid;
  }
  .screenshot-slot::before { top: 8px; left: 8px; border-width: 1px 0 0 1px; }
  .screenshot-slot::after  { bottom: 8px; right: 8px; border-width: 0 1px 1px 0; }

  /* ── Section layout ─────────────────────────────────────────────────────── */
  .section {
    padding: 70px 40px;
    border-bottom: 1px solid var(--border);
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
  }

  .section-label {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 4px;
    color: var(--red);
    text-transform: uppercase;
    margin-bottom: 10px;
  }

  .section h2 {
    font-family: var(--sans);
    font-size: 36px;
    font-weight: 600;
    color: #e8eaed;
    margin-bottom: 32px;
    letter-spacing: -0.5px;
  }

  .section p {
    color: var(--dim);
    font-size: 15px;
    max-width: 700px;
    margin-bottom: 16px;
  }

  /* ── Feature grid ───────────────────────────────────────────────────────── */
  .feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin-top: 40px;
  }

  .feature-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 28px 24px;
    transition: border-color 0.2s, transform 0.2s;
    position: relative;
    overflow: hidden;
  }

  .feature-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--red), transparent);
    opacity: 0;
    transition: opacity 0.2s;
  }

  .feature-card:hover { border-color: var(--red-dim); transform: translateY(-2px); }
  .feature-card:hover::before { opacity: 1; }

  .feature-icon {
    font-size: 22px;
    margin-bottom: 14px;
  }

  .feature-card h3 {
    font-family: var(--sans);
    font-size: 16px;
    font-weight: 600;
    color: #e8eaed;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
  }

  .feature-card p {
    font-size: 13px;
    color: var(--dim);
    line-height: 1.6;
    margin: 0;
  }

  /* ── Architecture diagram ───────────────────────────────────────────────── */
  .arch {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 40px;
    margin-top: 40px;
    font-family: var(--mono);
    font-size: 13px;
    line-height: 2;
    color: var(--steel);
    overflow-x: auto;
  }

  .arch .red  { color: var(--red); }
  .arch .gold { color: var(--gold); }
  .arch .dim  { color: var(--dim); }

  /* ── Tool table ─────────────────────────────────────────────────────────── */
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 32px;
    font-size: 14px;
  }

  th {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--dim);
    text-align: left;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 12px 16px;
    border-bottom: 1px solid rgba(30,37,48,0.6);
    color: var(--steel);
    vertical-align: top;
  }

  tr:hover td { background: var(--surface2); }

  td:first-child {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--gold);
    white-space: nowrap;
  }

  td.severity-high   { color: #e57373; font-family: var(--mono); font-size: 11px; }
  td.severity-medium { color: #ffb74d; font-family: var(--mono); font-size: 11px; }
  td.severity-low    { color: #81c784; font-family: var(--mono); font-size: 11px; }

  /* ── Stack table ────────────────────────────────────────────────────────── */
  .stack-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-top: 32px;
  }

  .stack-item {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 18px 20px;
  }

  .stack-item .name {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--gold);
    margin-bottom: 4px;
  }

  .stack-item .role {
    font-size: 12px;
    color: var(--dim);
  }

  /* ── Code block ─────────────────────────────────────────────────────────── */
  .code-block {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 28px 32px;
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.9;
    color: var(--steel);
    overflow-x: auto;
    margin-top: 24px;
    position: relative;
  }

  .code-block .comment { color: var(--dim); }
  .code-block .cmd     { color: var(--gold); }
  .code-block .arg     { color: #81c784; }
  .code-block .kw      { color: var(--red); }

  .code-label {
    position: absolute;
    top: 12px; right: 16px;
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--dim);
    text-transform: uppercase;
  }

  /* ── Skins row ──────────────────────────────────────────────────────────── */
  .skins-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 24px;
  }

  .skin-chip {
    font-family: var(--mono);
    font-size: 11px;
    padding: 5px 14px;
    border-radius: 20px;
    letter-spacing: 1px;
    border: 1px solid;
  }

  /* ── Flow steps ─────────────────────────────────────────────────────────── */
  .flow {
    display: flex;
    flex-direction: column;
    gap: 0;
    margin-top: 36px;
    position: relative;
  }

  .flow::before {
    content: '';
    position: absolute;
    left: 19px; top: 20px; bottom: 20px;
    width: 1px;
    background: var(--border);
  }

  .flow-step {
    display: flex;
    gap: 20px;
    align-items: flex-start;
    padding: 14px 0;
  }

  .flow-num {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--surface);
    border: 1px solid var(--red-dim);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--red);
    flex-shrink: 0;
    position: relative;
    z-index: 1;
  }

  .flow-content h4 {
    font-family: var(--sans);
    font-size: 15px;
    font-weight: 600;
    color: #e8eaed;
    margin-bottom: 2px;
  }

  .flow-content p {
    font-size: 13px;
    color: var(--dim);
    margin: 0;
  }

  /* ── Footer ─────────────────────────────────────────────────────────────── */
  footer {
    padding: 50px 40px;
    text-align: center;
    position: relative;
    z-index: 1;
  }

  footer .logo-text {
    font-family: var(--sans);
    font-size: 28px;
    font-weight: 700;
    letter-spacing: 4px;
    color: var(--red);
    margin-bottom: 8px;
  }

  footer p {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--dim);
    letter-spacing: 2px;
  }

  /* ── Utility ─────────────────────────────────────────────────────────────── */
  .full-width { max-width: none; }
  .mt-0 { margin-top: 0; }

  .divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 0;
  }
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════════════════════════ HERO ══ -->
<div class="hero">
  <!-- Sword SVG logo -->
  <svg class="hero-logo" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M20 3 L24 18" stroke="#c0392b" stroke-width="1.2" stroke-linecap="round"/>
    <path d="M20 3 L16 18" stroke="#c0392b" stroke-width="1.2" stroke-linecap="round"/>
    <path d="M20 3 L24 18 L20 20 L16 18 Z" fill="#c0392b" opacity="0.15"/>
    <line x1="20" y1="3" x2="20" y2="20" stroke="#c0392b" stroke-width="0.6" opacity="0.6"/>
    <rect x="13" y="18" width="14" height="2.5" rx="1.2" fill="#c0392b"/>
    <rect x="18.5" y="20.5" width="3" height="3" fill="#c0392b" opacity="0.5"/>
    <rect x="19" y="23.5" width="2" height="8" rx="1" fill="#c0392b" opacity="0.7"/>
    <line x1="18.8" y1="25.5" x2="21.2" y2="25.5" stroke="#c0392b" stroke-width="0.6" opacity="0.5"/>
    <line x1="18.8" y1="27.5" x2="21.2" y2="27.5" stroke="#c0392b" stroke-width="0.6" opacity="0.5"/>
    <line x1="18.8" y1="29.5" x2="21.2" y2="29.5" stroke="#c0392b" stroke-width="0.6" opacity="0.5"/>
    <ellipse cx="20" cy="33" rx="3" ry="2" fill="#c0392b"/>
    <circle cx="20" cy="3" r="0.8" fill="#c0392b"/>
  </svg>

  <div class="hero-eyebrow">// Network Security Platform</div>
  <h1>GLADIUS</h1>
  <div class="hero-sub">AI-Powered Cisco Security Auditing</div>
  <p class="hero-desc">
    An autonomous network security auditor that connects to Cisco devices, runs
    comprehensive hardening checks, cross-references findings against NIST 800-53 and
    CIS benchmarks, identifies CVEs, and produces templated compliance reports — all
    driven by a conversational AI agent.
  </p>
  <div class="badges">
    <span class="badge badge-steel">Claude claude-sonnet-4-6</span>
    <span class="badge badge-steel">MCP</span>
    <span class="badge badge-steel">FastAPI</span>
    <span class="badge badge-steel">Docker</span>
    <span class="badge badge-red">Cisco IOS / IOS XE</span>
    <span class="badge badge-gold">NIST 800-53</span>
    <span class="badge badge-gold">CIS Benchmarks</span>
    <span class="badge badge-gold">NVD / CVE</span>
  </div>
</div>


<!-- ══════════════════════════════════════════════════════ SCREENSHOTS ══ -->
<div style="padding: 60px 40px; border-bottom: 1px solid var(--border); position: relative; z-index:1;">
  <div style="max-width:1100px; margin:0 auto;">
    <div class="section-label">// Interface</div>
    <h2 style="font-family:var(--sans);font-size:36px;font-weight:600;color:#e8eaed;letter-spacing:-0.5px;margin-bottom:8px;">Screenshots</h2>
    <p style="color:var(--dim);font-size:14px;margin-bottom:0;">
      Add screenshots to <code style="font-family:var(--mono);font-size:12px;color:var(--gold);">docs/screenshots/</code> and update the
      <code style="font-family:var(--mono);font-size:12px;color:var(--gold);">src</code> attributes below.
    </p>
    <div class="screenshot-grid">
      <div class="screenshot-slot">
        <!-- Replace with: <img src="docs/screenshots/dashboard.png" alt="Dashboard"> -->
        <div class="slot-icon">⚔</div>
        <div class="slot-label">Dashboard</div>
      </div>
      <div class="screenshot-slot">
        <!-- Replace with: <img src="docs/screenshots/chat.png" alt="Chat / Audit"> -->
        <div class="slot-icon">▶</div>
        <div class="slot-label">Chat &amp; Audit</div>
      </div>
      <div class="screenshot-slot">
        <!-- Replace with: <img src="docs/screenshots/report.png" alt="Report"> -->
        <div class="slot-icon">◈</div>
        <div class="slot-label">Audit Report</div>
      </div>
      <div class="screenshot-slot">
        <!-- Replace with: <img src="docs/screenshots/reports-tab.png" alt="Reports History"> -->
        <div class="slot-icon">≡</div>
        <div class="slot-label">Reports History</div>
      </div>
    </div>
  </div>
</div>


<!-- ═══════════════════════════════════════════════════════ FEATURES ══ -->
<div style="border-bottom:1px solid var(--border); position:relative; z-index:1;">
<div class="section">
  <div class="section-label">// Capabilities</div>
  <h2>What Gladius Does</h2>
  <p>Tell Gladius an IP address. It handles the rest — no scripts to run, no checklists to fill in manually.</p>

  <div class="feature-grid">
    <div class="feature-card">
      <div class="feature-icon">🔌</div>
      <h3>Autonomous SSH Auditing</h3>
      <p>Connects to Cisco IOS and IOS XE devices via SSH. Runs show commands, parses output, and identifies misconfigurations without any manual input.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📚</div>
      <h3>NIST &amp; CIS Knowledge Base</h3>
      <p>Findings are cross-referenced against a ChromaDB vector store loaded with NIST 800-53 controls and CIS Cisco IOS XE Benchmark guidance.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🛡</div>
      <h3>Live CVE Lookup</h3>
      <p>Queries the NIST National Vulnerability Database in real time for the detected IOS version. Identifies applicable CVEs with CVSS scores and advisory links.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📊</div>
      <h3>Compliance Scoring</h3>
      <p>Calculates Overall, NIST 800-53, and CIS benchmark compliance scores after every audit. Findings are bucketed by severity: CRITICAL, HIGH, MEDIUM, LOW, PASS.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📄</div>
      <h3>Templated HTML Reports</h3>
      <p>Generates rich standalone HTML reports with a compliance gauge, category scorecard, remediation plan with copyable CLI commands, and a pre-deployment checklist.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">✉</div>
      <h3>Email Delivery</h3>
      <p>Reports are emailed as HTML attachments via SMTP. Ask Gladius in chat or click the email button — both paths produce the same templated output.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">📜</div>
      <h3>Audit History</h3>
      <p>Last 10 audits are stored in the browser. The Reports tab shows compliance trends across devices. Click any row to view full findings or export the report.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">🎨</div>
      <h3>9 Colour Themes</h3>
      <p>Named after Roman gladius variants — Gladius, Hispaniensis, Mainz, Fulham, Pompeii, Spatha, Pugio, Parazonium, Rudis. Because aesthetics matter.</p>
    </div>
  </div>
</div>
</div>


<!-- ══════════════════════════════════════════════════ ARCHITECTURE ══ -->
<div style="border-bottom:1px solid var(--border); position:relative; z-index:1;">
<div class="section">
  <div class="section-label">// Architecture</div>
  <h2>How It Works</h2>
  <p>Four Docker containers. One conversation. No manual steps between "audit this device" and a signed-off remediation report in your inbox.</p>

  <div class="arch">
<span class="dim">┌─────────────────────────────────────────────────────────────────────┐</span>
<span class="dim">│</span>  <span class="red">Browser</span>  ──  nginx (web-projects)  ──  index.html               <span class="dim">│</span>
<span class="dim">│</span>     │                                                                <span class="dim">│</span>
<span class="dim">│</span>     │  SSE stream  /  REST                                          <span class="dim">│</span>
<span class="dim">│</span>     ▼                                                                <span class="dim">│</span>
<span class="dim">│</span>  <span class="gold">gladius-api</span>  (FastAPI :8080)                                      <span class="dim">│</span>
<span class="dim">│</span>     │  Runs Claude claude-sonnet-4-6 with tool use                         <span class="dim">│</span>
<span class="dim">│</span>     │  Intercepts save/email calls, emits SSE events                <span class="dim">│</span>
<span class="dim">│</span>     │                                                                <span class="dim">│</span>
<span class="dim">│</span>     │  stdio (MCP protocol)                                         <span class="dim">│</span>
<span class="dim">│</span>     ▼                                                                <span class="dim">│</span>
<span class="dim">│</span>  <span class="red">network-audit-mcp</span>  (MCP server)                                   <span class="dim">│</span>
<span class="dim">│</span>     │  SSH → Cisco devices          ◄── Paramiko                    <span class="dim">│</span>
<span class="dim">│</span>     │  Vector search                ◄── ChromaDB + MiniLM           <span class="dim">│</span>
<span class="dim">│</span>     │  CVE lookup                   ◄── NIST NVD API                <span class="dim">│</span>
<span class="dim">│</span>     │  Email                        ◄── SMTP                        <span class="dim">│</span>
<span class="dim">│</span>     └─ save_audit_results ──► POST /api/audit/save ──► SSE event   <span class="dim">│</span>
<span class="dim">│</span>                                                                     <span class="dim">│</span>
<span class="dim">│</span>  <span class="gold">chroma-db</span>  (ChromaDB :8000)                                       <span class="dim">│</span>
<span class="dim">│</span>     NIST 800-53 + CIS IOS XE Benchmark vectors                     <span class="dim">│</span>
<span class="dim">└─────────────────────────────────────────────────────────────────────┘</span>
  </div>

  <div class="stack-grid" style="margin-top:32px;">
    <div class="stack-item">
      <div class="name">web-projects</div>
      <div class="role">nginx · serves index.html</div>
    </div>
    <div class="stack-item">
      <div class="name">gladius-api</div>
      <div class="role">FastAPI · Claude agent · SSE</div>
    </div>
    <div class="stack-item">
      <div class="name">network-audit-mcp</div>
      <div class="role">MCP stdio · all tools</div>
    </div>
    <div class="stack-item">
      <div class="name">chroma-db</div>
      <div class="role">Vector store · KB</div>
    </div>
  </div>
</div>
</div>


<!-- ═══════════════════════════════════════════════════════════ FLOW ══ -->
<div style="border-bottom:1px solid var(--border); position:relative; z-index:1;">
<div class="section">
  <div class="section-label">// Audit Flow</div>
  <h2>From Prompt to Report</h2>

  <div class="flow">
    <div class="flow-step">
      <div class="flow-num">01</div>
      <div class="flow-content">
        <h4>You type an IP address</h4>
        <p>e.g. "audit 10.0.0.1" — or use a quick-launch chip on the dashboard.</p>
      </div>
    </div>
    <div class="flow-step">
      <div class="flow-num">02</div>
      <div class="flow-content">
        <h4>Gladius connects via SSH</h4>
        <p>Uses Paramiko to establish an SSH session. Runs show commands — version, running config, interfaces, CDP, SNMP, AAA, logging, NTP and more.</p>
      </div>
    </div>
    <div class="flow-step">
      <div class="flow-num">03</div>
      <div class="flow-content">
        <h4>Findings cross-referenced</h4>
        <p>Each finding is semantically searched against the ChromaDB knowledge base for relevant NIST 800-53 controls and CIS Benchmark guidance.</p>
      </div>
    </div>
    <div class="flow-step">
      <div class="flow-num">04</div>
      <div class="flow-content">
        <h4>CVEs identified</h4>
        <p>The detected IOS version is queried against the NIST NVD. Applicable CVEs are added as findings with CVSS scores, descriptions, and advisory links.</p>
      </div>
    </div>
    <div class="flow-step">
      <div class="flow-num">05</div>
      <div class="flow-content">
        <h4>Results saved automatically</h4>
        <p>Gladius calls <code style="font-family:var(--mono);font-size:11px;color:var(--gold);">save_audit_results</code> without prompting. The dashboard updates instantly via SSE — Reports tab, findings list, compliance scores.</p>
      </div>
    </div>
    <div class="flow-step">
      <div class="flow-num">06</div>
      <div class="flow-content">
        <h4>Export or email the report</h4>
        <p>Download a standalone HTML report or email it as an attachment. The templated report includes a compliance gauge, remediation plan with copyable CLI commands, and a pre-deployment sign-off checklist.</p>
      </div>
    </div>
  </div>
</div>
</div>


<!-- ═════════════════════════════════════════════════════════ TOOLS ══ -->
<div style="border-bottom:1px solid var(--border); position:relative; z-index:1;">
<div class="section">
  <div class="section-label">// MCP Tools</div>
  <h2>Agent Tool Reference</h2>
  <p>Claude has access to these tools via the MCP server. All tool calls are visible in the chat interface as they happen.</p>

  <table>
    <thead>
      <tr>
        <th>Tool</th>
        <th>Purpose</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>connect_to_device</td><td>SSH into a Cisco device. Accepts host, username, password.</td></tr>
      <tr><td>run_show_command</td><td>Execute any show command on the connected device and return output.</td></tr>
      <tr><td>push_config</td><td>Push a list of configuration commands to the device.</td></tr>
      <tr><td>disconnect_device</td><td>Close the SSH session cleanly.</td></tr>
      <tr><td>query_knowledge_base</td><td>Semantic search of NIST 800-53 / CIS Benchmark ChromaDB collection.</td></tr>
      <tr><td>query_nvd</td><td>Query NIST NVD for CVEs by IOS version, date range, or severity.</td></tr>
      <tr><td>get_cve_details</td><td>Fetch full details for a specific CVE ID.</td></tr>
      <tr><td>save_audit_results</td><td>POST structured findings and scores to the dashboard. Called automatically at end of every audit.</td></tr>
      <tr><td>send_email</td><td>Send a report via SMTP. Intercepted by the API to send the templated HTML version.</td></tr>
    </tbody>
  </table>
</div>
</div>


<!-- ═══════════════════════════════════════════════ GETTING STARTED ══ -->
<div style="border-bottom:1px solid var(--border); position:relative; z-index:1;">
<div class="section">
  <div class="section-label">// Setup</div>
  <h2>Getting Started</h2>

  <p>Gladius runs entirely in Docker. Clone the repo, configure your environment variables, and bring the stack up.</p>

  <div class="code-block">
    <span class="code-label">bash</span>
    <span class="comment"># Clone and enter the project</span><br>
    <span class="cmd">git clone</span> <span class="arg">https://github.com/yourusername/gladius.git</span><br>
    <span class="cmd">cd</span> <span class="arg">gladius</span><br><br>
    <span class="comment"># Configure environment variables</span><br>
    <span class="cmd">cp</span> <span class="arg">gladius-api/.env.example gladius-api/.env</span><br>
    <span class="cmd">cp</span> <span class="arg">network-audit-mcp/.env.example network-audit-mcp/.env</span><br><br>
    <span class="comment"># Edit .env files — add your API keys, SMTP config, SSH credentials</span><br>
    <span class="cmd">nano</span> <span class="arg">gladius-api/.env</span><br>
    <span class="cmd">nano</span> <span class="arg">network-audit-mcp/.env</span><br><br>
    <span class="comment"># Start the stack</span><br>
    <span class="cmd">docker compose up</span> <span class="arg">-d</span><br><br>
    <span class="comment"># Open the dashboard</span><br>
    <span class="comment"># http://localhost (or your configured domain)</span>
  </div>

  <h3 style="font-family:var(--sans);font-size:20px;font-weight:600;color:#e8eaed;margin-top:48px;margin-bottom:16px;">Environment Variables</h3>

  <table>
    <thead>
      <tr><th>Variable</th><th>Container</th><th>Description</th></tr>
    </thead>
    <tbody>
      <tr><td>ANTHROPIC_API_KEY</td><td>gladius-api</td><td>Required. Claude API key.</td></tr>
      <tr><td>CHROMA_HOST</td><td>both</td><td>ChromaDB hostname. Default: chroma-db</td></tr>
      <tr><td>NIST_API_KEY</td><td>mcp</td><td>NVD API key. Optional but recommended — avoids rate limits.</td></tr>
      <tr><td>LAB_USERNAME</td><td>mcp</td><td>Default SSH username for device connections.</td></tr>
      <tr><td>LAB_PASSWORD</td><td>mcp</td><td>Default SSH password for device connections.</td></tr>
      <tr><td>SMTP_SERVER</td><td>mcp</td><td>SMTP server hostname for email reports.</td></tr>
      <tr><td>SMTP_USERNAME</td><td>mcp</td><td>SMTP username / sender address.</td></tr>
      <tr><td>SMTP_PASSWORD</td><td>mcp</td><td>SMTP password.</td></tr>
      <tr><td>DEFAULT_RECIPIENT</td><td>mcp</td><td>Default email recipient for reports.</td></tr>
      <tr><td>GLADIUS_API_URL</td><td>mcp</td><td>Internal API URL. Default: http://gladius-api:8080</td></tr>
    </tbody>
  </table>
</div>
</div>


<!-- ═══════════════════════════════════════════════════════ THEMES ══ -->
<div style="border-bottom:1px solid var(--border); position:relative; z-index:1;">
<div class="section">
  <div class="section-label">// Themes</div>
  <h2>Colour Skins</h2>
  <p>Nine themes, each named after a variant of the Roman short sword. Switch via the palette icon in the sidebar.</p>

  <div class="skins-row">
    <span class="skin-chip" style="color:#c0392b;border-color:rgba(192,57,43,0.4);background:rgba(192,57,43,0.08)">Gladius</span>
    <span class="skin-chip" style="color:#8b6914;border-color:rgba(139,105,20,0.4);background:rgba(139,105,20,0.08)">Hispaniensis</span>
    <span class="skin-chip" style="color:#2e6da4;border-color:rgba(46,109,164,0.4);background:rgba(46,109,164,0.08)">Mainz</span>
    <span class="skin-chip" style="color:#2d6a4f;border-color:rgba(45,106,79,0.4);background:rgba(45,106,79,0.08)">Fulham</span>
    <span class="skin-chip" style="color:#7b3f7a;border-color:rgba(123,63,122,0.4);background:rgba(123,63,122,0.08)">Pompeii</span>
    <span class="skin-chip" style="color:#4a6fa5;border-color:rgba(74,111,165,0.4);background:rgba(74,111,165,0.08)">Spatha</span>
    <span class="skin-chip" style="color:#8b2635;border-color:rgba(139,38,53,0.4);background:rgba(139,38,53,0.08)">Pugio</span>
    <span class="skin-chip" style="color:#5a6e8a;border-color:rgba(90,110,138,0.4);background:rgba(90,110,138,0.08)">Parazonium</span>
    <span class="skin-chip" style="color:#6b5e45;border-color:rgba(107,94,69,0.4);background:rgba(107,94,69,0.08)">Rudis</span>
  </div>
</div>
</div>


<!-- ═══════════════════════════════════════════════════════ FOOTER ══ -->
<footer>
  <div class="logo-text">GLADIUS</div>
  <p>// AI-Powered Network Security Auditing · Built with Claude · Runs on Docker</p>
</footer>

</body>
</html>
