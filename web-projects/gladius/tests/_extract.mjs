// Helpers for testing index.html without a browser or build step.
//  - inlineScripts(): every inline <script> block (src= scripts skipped). The
//    <script> inside generateReportHTML()'s template literal closes with
//    <\/script>, so the non-greedy match below never stops inside it.
//  - loadHelpers(): evaluates the source between the
//    `// @test-extract:begin <name>` / `// @test-extract:end <name>` markers in
//    a fresh vm context and returns that context.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
export const INDEX = join(here, '..', 'index.html');

export function readIndex() {
  return readFileSync(INDEX, 'utf8');
}

export function inlineScripts(html) {
  const out = [];
  const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    if (/\bsrc\s*=/.test(m[1] || '')) continue;
    out.push({ line: html.slice(0, m.index).split('\n').length, code: m[2] });
  }
  return out;
}

export function extractBlock(html, name) {
  const begin = `// @test-extract:begin ${name}`;
  const end = `// @test-extract:end ${name}`;
  const i = html.indexOf(begin);
  const j = html.indexOf(end);
  if (i < 0 || j < 0 || j < i) throw new Error(`marker block "${name}" not found in index.html`);
  return html.slice(i + begin.length, j);
}

export function loadHelpers(...names) {
  const html = readIndex();
  const ctx = vm.createContext({ console });
  for (const n of names) vm.runInContext(extractBlock(html, n), ctx, { filename: `index.html#${n}` });
  return ctx;
}
