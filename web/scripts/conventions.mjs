// Repo conventions that svelte-check does not catch. Each rule comes from a
// mistake made more than once (see the rule table in CLAUDE.md). Runs as part
// of `npm run check`, locally and in CI. Rules match the whole file, so a
// list or tag split across lines is caught too.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const dirs = process.argv.length > 2 ? process.argv.slice(2) : ['web/src', 'docs/site/src'];
const exts = /\.(svelte|ts|astro)$/;
const q = `['"\`]`;

const rules = [
  {
    // A hand-copied severity list drifts: Channels.svelte dropped `unknown`.
    // Three severity names quoted close together, in any quote style or layout.
    test: new RegExp(`${q}critical${q}[\\s\\S]{0,120}?${q}high${q}[\\s\\S]{0,120}?${q}medium${q}`, 'g'),
    skip: f => f.endsWith('web/src/lib/ui/format.ts') || /\.test\.ts$/.test(f),
    fix: 'import SEVERITIES (and the Severity type) from web/src/lib/ui/format.ts instead of listing severities',
  },
  {
    // aria-label on a generic element is ignored by screen readers (PR #61, three times).
    test: /<(div|span|p)\b(?![^>]*\srole=)[^>]*\saria-label=/g,
    fix: 'aria-label on a <div>/<span>/<p> without a role is not announced: use <section>/<nav>/<ul>, add a role, or use visible text',
  },
];

function* files(dir) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (exts.test(name)) yield p;
  }
}

let failures = 0;
for (const dir of dirs) {
  for (const file of files(resolve(root, dir))) {
    const rel = relative(root, file);
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
