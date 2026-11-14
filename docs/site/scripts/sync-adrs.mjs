// Copies docs/adr/*.md into the Starlight content collection, so the ADRs
// live in one place (docs/adr/) and still show up on the site.
//
// Each ADR starts with "# Title". Starlight wants the title in frontmatter, so
// the first heading is moved there. The output files are generated and
// gitignored (see the repository .gitignore).
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const adrDir = join(here, '..', '..', 'adr');
const outDir = join(here, '..', 'src', 'content', 'docs', 'decisions');

mkdirSync(outDir, { recursive: true });

// Start clean so a renamed or deleted ADR does not leave a stale page behind.
for (const old of readdirSync(outDir)) {
  if (/^\d{4}-.*\.md$/.test(old)) rmSync(join(outDir, old));
}

const files = readdirSync(adrDir)
  .filter((f) => /^\d{4}-.*\.md$/.test(f))
  .sort();

for (const file of files) {
  const text = readFileSync(join(adrDir, file), 'utf8');
  const lines = text.split('\n');
  const headingAt = lines.findIndex((l) => l.startsWith('# '));
  if (headingAt === -1) {
    throw new Error(`${file}: no "# " heading to use as the title`);
  }
  const title = lines[headingAt].slice(2).trim();
  const number = file.slice(0, 4);
  const body = lines
    .filter((_, i) => i !== headingAt)
    .join('\n')
    .trim();
  const page = [
    '---',
    `title: ${JSON.stringify(`ADR ${number}: ${title}`)}`,
    `description: ${JSON.stringify(`Architecture decision record ${number}.`)}`,
    `sidebar:`,
    `  label: ${JSON.stringify(`${number} ${title}`)}`,
    `editUrl: https://github.com/mrashed98/heimdall/edit/main/docs/adr/${file}`,
    '---',
    '',
    `*Source: [docs/adr/${file}](https://github.com/mrashed98/heimdall/blob/main/docs/adr/${file})*`,
    '',
    body,
    '',
  ].join('\n');
  writeFileSync(join(outDir, file), page);
}

console.log(`sync-adrs: wrote ${files.length} decision pages`);
