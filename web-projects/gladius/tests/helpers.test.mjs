// Unit tests for the pure helpers in index.html's `core-helpers` marker block.
// Run: node --test web-projects/gladius/tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadHelpers, readIndex } from './_extract.mjs';

const h = loadHelpers('core-helpers');

test('escHtml escapes all five HTML-significant characters', () => {
  assert.equal(h.escHtml(`<a href="x" title='y'>&</a>`),
    '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
});

test('escHtml renders null/undefined as empty and keeps 0', () => {
  assert.equal(h.escHtml(null), '');
  assert.equal(h.escHtml(undefined), '');
  assert.equal(h.escHtml(0), '0');
  assert.equal(h.escHtml(false), 'false');
});

test('index.html has exactly one HTML escaper', () => {
  const src = readIndex();
  assert.equal((src.match(/function escHtml\(/g) || []).length, 1);
  for (const old of ['escH', 'escapeHtml', '_autoEsc', '_apitestEsc', '_itsmEsc']) {
    assert.ok(!new RegExp(`\\b${old}\\(`).test(src), `${old}() should be gone`);
  }
});

test('safeUrl only allows http(s)', () => {
  assert.equal(h.safeUrl('https://nvd.nist.gov/x'), 'https://nvd.nist.gov/x');
  assert.equal(h.safeUrl('HTTP://example.com'), 'HTTP://example.com');
  assert.equal(h.safeUrl('  https://a.b/c '), 'https://a.b/c');
  for (const bad of ['javascript:alert(1)', ' JaVaScRiPt:x', 'data:text/html,x', 'vbscript:x', '//evil', '/rel', '', null, undefined]) {
    assert.equal(h.safeUrl(bad), '#', String(bad));
  }
  assert.equal(h.safeUrl('ftp://x', ''), '');
});

test('jsArg survives HTML-attribute decoding and JS parsing', () => {
  const nasty = `a'b"c\\d</script>&amp; `;
  const attr = h.jsArg(nasty);
  assert.ok(!/["'<>]/.test(attr), 'no raw quotes/brackets in attribute text');
  // Simulate the browser: decode entities in the attribute, then parse as JS.
  const decoded = attr.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  assert.equal(JSON.parse(decoded), nasty);
  assert.equal(h.jsArg(42), '42');
  assert.equal(h.jsArg(undefined), 'null');
});

test('safeHtml escapes interpolations by default, rawHtml opts out', () => {
  const t = '<img src=x>';
  const out = String(h.safeHtml`<b>${t}</b>${h.rawHtml('<i>ok</i>')}${['<a>', h.rawHtml('<br>')]}`);
  assert.equal(out, '<b>&lt;img src=x&gt;</b><i>ok</i>&lt;a&gt;<br>');
  const nested = h.safeHtml`<p>${h.safeHtml`<span>${'&'}</span>`}</p>`;
  assert.equal(`${nested}`, '<p><span>&amp;</span></p>');
});

test('sortBySeverity puts CRITICAL then HIGH first (no 0 || 9 bug) and is stable', () => {
  const fs = [
    { t: 'p', severity: 'PASS' }, { t: 'l', severity: 'LOW' }, { t: 'h1', severity: 'HIGH' },
    { t: 'x', severity: 'WEIRD' }, { t: 'm', severity: 'medium' }, { t: 'c', severity: 'CRITICAL' },
    { t: 'h2', severity: 'HIGH' }, { t: 'n' },
  ];
  assert.deepEqual(h.sortBySeverity(fs).map(f => f.t), ['c', 'h1', 'h2', 'm', 'l', 'p', 'x', 'n']);
  assert.equal(h.sortBySeverity(null).length, 0);
});

test('severity badge class/label', () => {
  assert.equal(h.sevBadgeClass({ severity: 'CRITICAL' }), 'critical');
  assert.equal(h.sevBadgeClass({ severity: 'HIGH' }), 'high');
  assert.equal(h.sevBadgeClass({ severity: 'MEDIUM' }), 'medium');
  assert.equal(h.sevBadgeClass({ severity: 'PASS' }), 'pass');
  assert.equal(h.sevBadgeClass({}), 'low');
  assert.equal(h.sevBadgeClass({ type: 'cve', severity: 'CRITICAL' }), 'cve');
  assert.equal(h.sevBadgeClass({ title: 'CVE-2024-20399' }), 'cve');
  assert.equal(h.sevBadgeLabel({ severity: 'MEDIUM' }), 'MED');
  assert.equal(h.sevBadgeLabel({ severity: 'CRITICAL' }), 'CRIT');
  assert.equal(h.sevBadgeLabel({ type: 'cve' }), 'CVE');
});

test('normalizeFinding maps impact/fix/commands onto legacy fields without losing data', () => {
  const f = { title: 'SSH v1', severity: 'high ', impact: 'weak crypto', fix: 'use v2', commands: 'ip ssh version 2' };
  const n = h.normalizeFinding(f);
  assert.equal(n.severity, 'HIGH');
  assert.equal(n.description, 'weak crypto');
  assert.equal(n.remediation, 'ip ssh version 2');
  assert.equal(n.impact, 'weak crypto');
  assert.equal(n.fix, 'use v2');
  assert.equal(f.severity, 'high ', 'input not mutated');
  // fix used when there are no commands
  assert.equal(h.normalizeFinding({ fix: 'do x' }).remediation, 'do x');
  // existing legacy fields win
  assert.equal(h.normalizeFinding({ description: 'd', impact: 'i' }).description, 'd');
  // array commands are joined
  assert.equal(h.normalizeFinding({ commands: ['a', 'b'] }).remediation, 'a, b');
  // idempotent
  assert.deepEqual(h.normalizeFinding(n), n);
});

test('normalizeAudit normalises every finding and tolerates junk', () => {
  const a = h.normalizeAudit({ device: 'R1', findings: [{ severity: 'critical', impact: 'x' }] });
  assert.equal(a.device, 'R1');
  assert.equal(a.findings[0].severity, 'CRITICAL');
  assert.equal(a.findings[0].description, 'x');
  assert.equal(h.normalizeAudit({ device: 'R2' }).findings.length, 0);
  assert.equal(h.normalizeAudit(null), null);
});

test('trimHistory keeps recent turns, starts on a user turn, respects char budget', () => {
  const msgs = [];
  for (let i = 0; i < 50; i++) msgs.push({ role: i % 2 ? 'assistant' : 'user', content: `m${i}` });
  const t = h.trimHistory(msgs, 9);
  assert.equal(t[0].role, 'user');
  assert.equal(t[t.length - 1].content, 'm49');
  assert.ok(t.length <= 9);
  const big = [{ role: 'user', content: 'x'.repeat(100) }, { role: 'assistant', content: 'y'.repeat(100) }, { role: 'user', content: 'z' }];
  assert.deepEqual(h.trimHistory(big, 30, 150).map(m => m.content), ['z']);
  assert.equal(h.trimHistory([{ role: 'user', content: 'x'.repeat(999) }], 30, 10).length, 1);
  assert.equal(h.trimHistory([], 5).length, 0);
});
