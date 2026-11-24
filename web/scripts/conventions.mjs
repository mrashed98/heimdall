// Repo conventions that svelte-check does not catch. Each rule comes from a
// mistake made more than once (see the rule table in CLAUDE.md). Runs as part
// of `npm run check`, locally and in CI.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = new URL('../..', import.meta.url).pathname;
const dirs = process.argv.length > 2 ? process.argv.slice(2) : ['web/src', 'docs/site/src'];
const exts = /\.(svelte|ts|astro)$/;

const rules = [
  {
    // A hand-copied severity list drifts: Channels.svelte dropped `unknown`.
    test: /\[\s*'critical'\s*,\s*'high'/,
    skip: f => f.endsWith('web/src/lib/ui/format.ts') || /\.test\.ts$/.test(f),
    fix: 'import SEVERITIES (and the Severity type) from web/src/lib/ui/format.ts instead of listing severities',
  },
  {
    // aria-label on a generic element is ignored by screen readers (PR #61, three times).
    test: /<(div|span|p)\b(?![^>]*\brole=)[^>]*\baria-label=/,
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
  for (const file of files(join(root, dir))) {
    const rel = relative(root, file);
    readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
      for (const r of rules) {
        if (r.skip?.(rel) || !r.test.test(line)) continue;
        console.error(`${rel}:${i + 1}: ${r.fix}`);
        failures++;
      }
    });
  }
}
if (failures) process.exit(1);
