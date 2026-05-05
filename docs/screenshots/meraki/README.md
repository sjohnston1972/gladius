# Gladius UI — meraki skin

Captured 2026-05-05 at 1600×1000 viewport via the playwright headless
container against the live homelab deployment. Skin: `meraki` (light
slate/white background, Cisco-Meraki-style green accent `#1A9B3B`).

| File | View |
|---|---|
| [01-dashboard.png](01-dashboard.png) | Network AIOps dashboard — KPI cards, latest findings, compliance score, device inventory. |
| [02-psirt.png](02-psirt.png) | Cisco PSIRT advisories tab. |
| [03-cve.png](03-cve.png) | CVE feed (live NVD). |
| [04-pentest-reports.png](04-pentest-reports.png) | PenTest Reports — list of saved engagements. |
| [05-pentest-engagement-expanded.png](05-pentest-engagement-expanded.png) | Expanded engagement (full page) — exec/technical summaries, attack paths, kill chain, ATT&CK matrix, findings, remediation plan. |
| [06-chat-widget-welcome.png](06-chat-widget-welcome.png) | Floating local-LLM chat widget (Foundation-Sec-8B) — welcome state with capabilities. |
| [07-attck-matrix-with-scope-marker.png](07-attck-matrix-with-scope-marker.png) | ATT&CK coverage matrix — clickable hit tiles, scope marker showing the chat's current focus. |
| [08-finding-detail-drawer.png](08-finding-detail-drawer.png) | Finding detail drawer with adjacency context, ATT&CK link, parent kill-chain step. |

## Reproducing

```bash
# from playwright/scripts/
docker run --rm --network net_core \
  --add-host gladius.clydeford.net:<web-projects container IP> \
  -v "$(pwd)":/app/scripts \
  playwright-playwright \
  python /app/scripts/screenshot_gladius.py
```

The script pre-seeds `localStorage['gladius-skin'] = 'meraki'` before the
page loads so every capture is in the same skin.
