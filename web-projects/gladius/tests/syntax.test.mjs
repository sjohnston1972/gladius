// Syntax-checks every inline <script> block in index.html with `node --check`.
// Run: node --test web-projects/gladius/tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readIndex, inlineScripts } from './_extract.mjs';

test('index.html inline scripts parse', () => {
  const blocks = inlineScripts(readIndex());
  assert.ok(blocks.length >= 1, 'expected at least one inline script');
  const dir = mkdtempSync(join(tmpdir(), 'gladius-fe-'));
  try {
    for (const b of blocks) {
      const p = join(dir, `index-${b.line}.js`);
      // pad so reported line numbers match index.html
      writeFileSync(p, '\n'.repeat(b.line - 1) + b.code);
      try {
        execFileSync(process.execPath, ['--check', p], { stdio: 'pipe' });
      } catch (e) {
        assert.fail(`inline script at index.html:${b.line} failed node --check\n${e.stderr}`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
