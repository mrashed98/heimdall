// Repo conventions that svelte-check does not catch. Each rule comes from a
// mistake made more than once (see the rule table in CLAUDE.md). Runs as part
// of `npm run check`, locally and in CI. Rules match the whole file, so a
// list or tag split across lines is caught too.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const dirs = process.argv.length > 2 ? process.argv.slice(2) : ['web/src', 'docs/site/src'];
const exts = /\.(svelte|ts|js|astro)$/;
const q = `['"\`]`;
// An empty array or object literal, optionally parenthesized or cast (`[] as Row[]`).
const EMPTY = String.raw`(?:\(\s*)?(?:\[\s*\]|\{\s*\})(?:\s*as\s+[\w<>\[\]]+)?(?:\s*\))?`;

const rules = [
  {
    // A hand-copied severity list drifts: Channels.svelte dropped `unknown`.
    // Three severity names quoted close together, in any quote style or layout.
    test: new RegExp(`${q}critical${q}[\\s\\S]{0,120}?${q}high${q}[\\s\\S]{0,120}?${q}medium${q}`, 'g'),
    skip: f => f.endsWith('web/src/lib/ui/format.ts') || /\.test\.ts$/.test(f),
    fix: 'import SEVERITIES (and the Severity type) from web/src/lib/ui/format.ts instead of listing severities',
    bad: [`['critical', 'high', 'medium']`, `"critical",\n  "high",\n  "medium"`],
    good: [`['critical', 'high']`],
  },
  {
    // aria-label on a generic element is ignored by screen readers (PR #61, three times).
    test: /<(div|span|p)\b(?![^>]*\srole=)[^>]*\saria-label=/g,
    fix: 'aria-label on a <div>/<span>/<p> without a role is not announced: use <section>/<nav>/<ul>, add a role, or use visible text',
    bad: ['<div aria-label="x">', '<span class="a" aria-label="x">'],
    good: ['<div role="img" aria-label="x">', '<section aria-label="x">'],
  },
  {
    // A failed request turned into empty data shows a false empty state
    // ("Nothing with a fix is open", "the first point appears after...") (PR #75, twice).
    // An empty value as the failure handler, in any form: `.catch(cb)`,
    // `.then(ok, cb)`, or a try/catch block that only sets one.
    test: new RegExp(String.raw`(?:\.catch\(\s*|\.then\([^;]*?,\s*)(?:async\s+)?(?:\([^)]*\)|\w+|function\s*\w*\s*\([^)]*\))\s*(?:=>\s*)?(?:${EMPTY}|\{\s*(?:return\s+${EMPTY}\s*;?)?\s*\})\s*\)|\bcatch\s*(?:\([^)]*\))?\s*\{\s*[\w.]+\s*=\s*${EMPTY}\s*;?\s*\}`, 'g'),
    bad: ['.catch(() => [])', '.catch(e => [])', '.catch((error: unknown) => {})', '.catch(async () => [] as Row[])', '.catch(function () {})',
      '.catch(() => ([]))', '.catch(() => ({}))', '.catch(() => { return []; })', '.catch(e => { return {} })', '.then(ok, () => [])', 'try { load() } catch { rows = [] }', 'catch (e) { this.items = [] }'],
    good: ['.catch(() => null)', '.catch((e) => { failed = true; })', '.then((d) => [d])', 'catch (e) { failed = true }', '.catch(() => [fallback])'],
    skip: f => /\.test\.ts$/.test(f),
    fix: 'a failed request must not look like empty data: .catch(() => null) and show that it could not be loaded, or let the page ErrorState handle it',
  },
];

// Each rule proves its pattern on its own examples first, so a pattern that
// misses a form it names fails here instead of passing silently.
let failures = 0;
for (const r of rules) {
  for (const b of r.bad ?? []) if (!b.match(new RegExp(r.test.source, 'g'))) { console.error(`conventions.mjs: rule "${r.fix.slice(0, 50)}..." misses its bad example: ${b}`); failures++; }
  for (const g of r.good ?? []) if (g.match(new RegExp(r.test.source, 'g'))) { console.error(`conventions.mjs: rule "${r.fix.slice(0, 50)}..." flags its good example: ${g}`); failures++; }
  if (!r.bad?.length) { console.error(`conventions.mjs: rule "${r.fix.slice(0, 50)}..." needs bad examples`); failures++; }
}

function* files(dir) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (exts.test(name)) yield p;
  }
}

for (const dir of dirs) {
  for (const file of files(resolve(root, dir))) {
    const rel = relative(root, file).split(sep).join('/');
    const text = readFileSync(file, 'utf8');
    for (const r of rules) {
      if (r.skip?.(rel)) continue;
      for (const m of text.matchAll(r.test)) {
        const line = text.slice(0, m.index).split('\n').length;
        console.error(`${rel}:${line}: ${r.fix}`);
        failures++;
      }
    }
  }
}
if (failures) process.exit(1);
