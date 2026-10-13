// Tests for the audit report generator, audit store and agent audit context
// (marker blocks `report`, `audit-store`, `audit-context` in index.html).
// Run: node --test web-projects/gladius/tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readIndex, extractBlock } from './_extract.mjs';

function makeCtx() {
  const html = readIndex();
  const store = new Map();
  const ctx = vm.createContext({
    console,
    localStorage: {
      getItem: k => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: k => store.delete(k),
    },
  });
  for (const n of ['core-helpers', 'report', 'audit-store', 'audit-context']) {
    vm.runInContext(extractBlock(html, n), ctx, { filename: `index.html#${n}` });
  }
  return { ctx, store };
}

// What the audit agent actually sends via save_audit_results
const AGENT_AUDIT = {
  device: 'SW-CORE-01', ip: '10.0.0.1', ios: 'IOS XE 17.6.1', timestamp: '2026-10-13T12:00:00Z',
  score: { overall: 72, nist: 65, cis: 70 },
  findings: [
    { title: 'Telnet enabled on VTY', severity: 'CRITICAL', type: 'hardening', category: 'Access Security',
      impact: 'Cleartext credentials on the wire', fix: 'Restrict VTY to SSH',
      commands: 'line vty 0 15, transport input ssh' },
    { title: 'SSH version 1 enabled', severity: 'HIGH', type: 'hardening',
      impact: 'Weak protocol IMPACT-HIGH', fix: 'Use SSH v2', commands: 'ip ssh version 2' },
    { title: 'No login banner', severity: 'LOW', type: 'hardening', impact: 'No legal notice', fix: 'Add a banner' },
    { title: 'NTP authenticated', severity: 'PASS', type: 'hardening' },
    { title: 'CVE-2024-20399', severity: 'CRITICAL', type: 'cve', cve_id: 'CVE-2024-20399',
      impact: 'CLI command injection', fix: 'Upgrade', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2024-20399' },
  ],
};

test('report includes impact text, commands and CRITICAL hardening findings', () => {
  const { ctx } = makeCtx();
  const out = ctx.generateReportHTML(structuredClone(AGENT_AUDIT));
  assert.match(out, /Cleartext credentials on the wire/);
  assert.match(out, /Weak protocol IMPACT-HIGH/);
  assert.match(out, /transport input ssh/, 'commands rendered in the remediation block');
  assert.match(out, /ip ssh version 2/);
  assert.match(out, /CRITICAL Risk &mdash; 1 issue/);
  assert.match(out, /CRITICAL findings addressed first/);
  // failed = 1 CRITICAL + 1 HIGH + 1 LOW
  assert.match(out, /Detailed Findings &mdash; 3 Issues/);
  // a fix with no commands is prose, not a fake config block
  assert.match(out, /<b>Fix:<\/b> Add a banner/);
});

test('report escapes agent text', () => {
  const { ctx } = makeCtx();
  const a = structuredClone(AGENT_AUDIT);
  a.findings[1].title = '<img src=x onerror=alert(1)>';
  a.findings[1].impact = '<script>bad()</script>';
  const out = ctx.generateReportHTML(a);
  assert.ok(!out.includes('<img src=x'), 'title escaped');
  assert.ok(!out.includes('<script>bad()'), 'impact escaped');
});

test('saveAudit normalises once and keeps 10 deduplicated history entries', () => {
  const { ctx, store } = makeCtx();
  for (let i = 0; i < 12; i++) ctx.saveAudit({ ...structuredClone(AGENT_AUDIT), timestamp: `t${i}` });
  ctx.saveAudit({ ...structuredClone(AGENT_AUDIT), timestamp: 't11' });   // re-save, no duplicate
  const hist = JSON.parse(store.get('gladius-audit-history'));
  assert.equal(hist.length, 10);
  assert.equal(hist[0].timestamp, 't11');
  assert.equal(hist.filter(h => h.timestamp === 't11').length, 1);
  const latest = JSON.parse(store.get('gladius-audit-latest'));
  assert.equal(latest.findings[1].description, 'Weak protocol IMPACT-HIGH');
  assert.equal(latest.findings[1].impact, 'Weak protocol IMPACT-HIGH', 'agent fields kept');
});

test('loadAuditHistory normalises legacy records and coerces scores to numbers', () => {
  const { ctx, store } = makeCtx();
  store.set('gladius-audit-history', JSON.stringify([
    { device: 'old', score: { overall: '<b>9</b>', nist: '41' }, findings: [{ title: 'x', severity: 'high', impact: 'i' }] },
  ]));
  const [a] = ctx.loadAuditHistory();
  assert.equal(a.score.overall, 0);
  assert.equal(a.score.nist, 41);
  assert.equal(a.findings[0].severity, 'HIGH');
  assert.equal(a.findings[0].description, 'i');
  store.set('gladius-audit-history', 'not json');
  assert.equal(ctx.loadAuditHistory().length, 0);
});

test('buildAuditContext uses impact text and counts CRITICAL', () => {
  const { ctx, store } = makeCtx();
  assert.equal(ctx.buildAuditContext(), null);
  store.set('gladius-audit-history', JSON.stringify([AGENT_AUDIT]));   // raw agent shape
  const out = ctx.buildAuditContext();
  assert.match(out, /Findings: 1 CRITICAL, 1 HIGH, 0 MEDIUM, 1 CVE/);
  assert.match(out, /\[CRITICAL\] Telnet enabled on VTY: Cleartext credentials/);
  assert.match(out, /\[HIGH\] SSH version 1 enabled: Weak protocol/);
  // most severe first
  assert.ok(out.indexOf('[CRITICAL]') < out.indexOf('[HIGH]'));
});
