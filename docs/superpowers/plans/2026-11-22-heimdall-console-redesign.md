# Heimdall Console Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the web UI as the approved Sentry-style, Heimdall-branded console.

**Architecture:** Backend gains three UI-path-only fields/behaviours on `GET /api/v1/findings`. Frontend keeps its Svelte 5 pages and data code; the shell, theme tokens and every page's markup/CSS are rebuilt to the canvas. Finding detail becomes its own route.

**Tech Stack:** Rust (axum, sqlx), Svelte 5, Vite, vitest, `@fontsource/cinzel` (only new dependency).

**Spec:** docs/superpowers/specs/2026-11-22-heimdall-console-redesign-design.md

## Global Constraints
- Palette tokens exactly as in the spec; no other raw colours in components.
- No runtime CDN; CSP unchanged (`default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'`).
- JS ≤ 250 KB gzipped.
- New API fields only when `ui=true`; API-key default responses byte-identical.
- Keep: six filters, sort, pagination (25), oath form + validation, realm switcher, theme toggle, sign-in methods, admin-only Settings.
- `npm run check`, `npm test`, `npm run build`, `cargo test`, `cargo clippy -- -D warnings` pass.

## Review Focus
- Finding with no advisory (k8scve, eol, majorrelease): row and page render without summary/fix, no "undefined".
- A `fixavailable` row whose `vuln` sibling is resolved or snoozed still shows (fold only when the sibling is visible in the same view).
- Deep link `/findings/123?realms=x` loads the page directly and 404s cleanly for a finding outside the user's realms.
- Narrow viewport (≤700px): rail collapses to a top bar, no horizontal scroll.
- Light theme toggle still produces readable contrast.

---

### Task 1: Findings API, UI path (summary, fix, fold, multi-severity)

**Files:** Modify `src/server.rs` (FindingRow, findings_handler, tests); `docs/http-api.md`.

**Interfaces — Produces:** UI rows gain `summary?: string`, `fix?: string`. `severity` accepts a comma list (`critical,high`) on every path.

- [ ] Test `findings_ui_rows_carry_summary_and_fix_and_fold_fixavailable`: seed advisory with summary, a `vuln` and a sibling `fixavailable` (advice.suggest "2.15.0"), assert `ui=true` returns one row (the vuln) with `summary` and `fix == "2.15.0"`; `ui=true&kind=fixavailable` returns the fixavailable row with `fix`; non-ui call returns both rows and neither field.
- [ ] Test `findings_severity_accepts_a_list`: `severity=critical,high` returns both, excludes medium; `severity=bogus` → 400.
- [ ] Implement: on ui path select `a.summary` (join advisories) and `COALESCE(f.details->'advice'->>'suggest', sib.fix)` where `sib` is a LATERAL over open `fixavailable` findings with same ref_id, component_id, service_id, realm. Fold: when ui and kind not given, `AND NOT (f.kind='fixavailable' AND EXISTS(open vuln sibling))`. Severity: parse list, validate each, bind `text[]`, `f.severity = ANY($9)`.
- [ ] `cargo test findings_` passes; clippy clean; document fields in http-api.md; commit.

### Task 2a: Design system and component library

**Files:** Create `web/src/lib/ui/tokens.css` (all palette, type, space 4/8/12/16/24/32, radius 5/7/10/14, dark default + `[data-theme=light]` and `prefers-color-scheme` light block), `web/src/lib/ui/*.svelte` for each component named in the spec, `web/src/lib/ui/index.ts`, `web/src/lib/ui/ui.test.ts`, `web/src/Catalogue.svelte` (mounted at `/design` only when `import.meta.env.DEV`).

**Interfaces — Produces:** props, exactly:
`Button {variant?: 'primary'|'secondary'|'ghost'|'danger'; size?: 'sm'|'md'; href?: string; type?; disabled?; onclick?; children}`;
`Badge {severity: string}` (normalises unknown values to 'unknown');
`Pill {tone?: 'neutral'|'gold'; mono?: boolean; children}`;
`Input/Select {label: string; hint?: string; error?: string; value (bindable); ...rest}`;
`EpssBar {score?: number|null; percentile?: number|null}`;
`Stat {label: string; value: string|number; tone?: 'default'|'ok'|'critical'}`;
`Panel {title?: string; actions?: Snippet; children}`;
`IssueRow {href; title; sub: string; meta: string[]; epss?; epssPercentile?; severity}`;
`EmptyState {title; body?; action?: Snippet}`;
`DataTable {label; children}`; `Pagination {offset; count; loading; change}`;
`Tabs {items: {id,label,count?}[]; current (bindable)}`; `Menu {label; children}`;
`NavRail {items: {href,label,icon,current}[]; footer?: Snippet}`; `SubNav {title?; children}`; `PageHeader {title; description?; actions?: Snippet}`; `RealmPicker {realms: string[]; selected (bindable)}`.
- [ ] `ui.test.ts` (vitest, no DOM lib): `severityTone('CRITICAL')=='critical'`, `severityTone('weird')=='unknown'`; `epssWidth(0.944)=='94.4%'`, `epssWidth(null)=='0%'`; `epssTone(0.5)=='critical'`, `epssTone(0.05)=='high'`, `epssTone(0.001)=='low'` (helpers live in `ui/format.ts`).
- [ ] Old `lib/components/*` deleted; callers moved to `ui/`.
- [ ] Grep check: no `#` hex colours in `web/src/lib/**/*.svelte` outside `ui/tokens.css` and the logo.
- [ ] check/test/build; commit.

### Task 2: Theme, brand, shell

**Files:** Rewrite `web/src/lib/theme.css`, `web/src/App.svelte`; replace `web/src/lib/assets/logo.svg` with the helmet; add `web/src/lib/components/Logo.svelte`, `web/src/lib/nav.ts` (+ `nav.test.ts`); `web/package.json` (+ `@fontsource/cinzel` exact version, import 700 latin only in `main.ts`).

**Interfaces — Produces:** `route(path: string): {page: 'overview'|'findings'|'finding'|'inventory'|'service'|'releases'|'oaths'|'settings'|'notfound'; id?: number}`; paths `/`, `/findings`, `/findings/:id`, `/services`, `/services/:id`, `/releases`, `/oaths`, `/access` (Settings, admin only, else notfound).

- [ ] `nav.test.ts`: each path above maps as listed; `/findings/0`, `/findings/abc`, `/nope` → notfound; `/access` with admin=false → notfound.
- [ ] Implement `route(path, admin)`; App uses it.
- [ ] Shell per canvas: 68px rail with Logo, icon+label links (aria-current), Settings pinned bottom (admin), avatar menu (name, roles, theme toggle, sign out); realm switcher moves to page headers' filter row (shared component `RealmPicker.svelte`, same URL behaviour). ≤700px: rail becomes a horizontal top bar.
- [ ] Sign-in page per SignIn artboard (centred dark card, refs Better Stack/Height/Synthesia on Mobbin): "Back to docs" link, helmet + wordmark + "Welcome back", card with OIDC button, divider, local form; key-only mode shows one key field; error line above the button keeps the fields.
- [ ] check/test/build pass; commit.

### Task 3: Findings feed

**Files:** Rewrite `web/src/lib/Findings.svelte`; extend `web/src/lib/findings.ts` (+ tests); `web/src/lib/components/SeverityBadge.svelte`; add `web/src/lib/components/EpssBar.svelte`.

**Interfaces — Consumes:** Task 1 fields; Task 2 `RealmPicker`. **Produces:** `views: {id, label, group: 'Views'|'Watch', filters: Partial<Filters>}[]` and `viewFilters(id): Partial<Filters>` in findings.ts; `fixLabel(row) -> string` (`"log4j-core 2.14.1 → 2.15.0"`, or name+version without arrow when no fix, or `''`).

- [ ] Tests: `viewFilters('likely-exploited')` → `{sort:'epss',order:'desc'}`; `'crit-high'` → `{severity:'critical,high'}`; `'fix'` → `{kind:'fixavailable'}`; unknown id → `{}`. `fixLabel` three cases.
- [ ] Layout per Main artboard: 212px sub-nav (wordmark, Views, Watch; Feed shows open count from `/api/v1/status` totals), filter row (search input, severity, kind, service, fix, status selects styled as tokens, RealmPicker, sort select), stream rows (title = summary ?? ref_id ?? kind, `fixLabel`, meta: ref_id · service · realm · opened, EpssBar, SeverityBadge). Row is an `<a href="/findings/{id}">`. View id kept in `?view=`.
- [ ] Pagination unchanged (25). Empty/loading/error states restyled.
- [ ] check/test/build; commit.

### Task 4: Finding page

**Files:** Create `web/src/lib/Finding.svelte`; move oath form + detail fetch out of Findings.svelte.

**Interfaces — Consumes:** `route` → `{page:'finding', id}`; existing `GET /api/v1/findings/:id` (needs a one-row fetch for header: use list endpoint? No — extend detail response in Task 1? Ruling: detail already returns realm, service, purl, version, summary, scores, epss, fixed, aliases; add `id, kind, severity, ref_id, opened_at, status` to the detail JSON in Task 1's commit if missing).
- [ ] Layout per Finding artboard: breadcrumb (Findings / ref_id), title, stat strip (EPSS, CVSS, services), actions (Take an oath scrolls to form, copy upgrade line, advisory links), Highlights dl, purl, affected services with its pagination; right rail: Fix card, Exploit likelihood, Oath form (same validation/POST), Oaths history.
- [ ] 404 from API → NotFound state with link back to Findings.
- [ ] check/test/build; commit.

### Task 5: Overview, Inventory, Releases, Oaths, Settings restyle

**Files:** Overview.svelte, Services.svelte, Releases.svelte, Oaths.svelte, Access.svelte, components (Table, Pagination, EmptyState, RetryState, Skeleton), illustrations recoloured to tokens.

- [ ] Each page: page header (h1 + muted line + RealmPicker where realm-scoped), panels on `--panel` with `--border`, tables per canvas. Overview: stat cards (open, critical, fix available, services), severity bars per realm, Fix-first list (top 5 from findings `has_fix` sorted severity), riskiest services, feeds, releases, EOL. No trend placeholder.
- [ ] Data calls and behaviour unchanged; existing tests pass.
- [ ] check/test/build; commit.

### Task 5b: Docs site landing page

**Files:** `docs/site/src/pages/index.astro` (landing, per Landing artboard: split hero with checklist + integration tiles wired to the helmet (ref 1Password Developer), numbered How-it-works list beside a product panel (ref Retool), three cards with real output: gate report, alert, oath (ref Resend); links built with `import.meta.env.BASE_URL`), delete `docs/site/src/content/docs/index.mdx`, `docs/site/astro.config.mjs` (`redirects: {'/docs': '/heimdall/getting-started/what-is-heimdall/'}`, logo → helmet), `docs/site/src/assets/logo.svg`, `docs/site/public/favicon.svg`, `docs/site/src/styles/custom.css` (Starlight `--sl-color-*` mapped to the palette; Cinzel via `@fontsource/cinzel` for the site title).
- [ ] `npm run build` in docs/site passes (links validator); `dist/index.html` is the landing; `dist/docs/index.html` redirects; every old doc URL still exists in dist.
- [ ] Install command on the page is the real one from getting-started/kubernetes.mdx.
- [ ] Commit.

### Task 6: Verify in the browser

- [ ] Run against the local demo instance (port 8080, DB heimdall_ui), screenshot each page dark + light at 1440 and 390 widths, compare with the canvas, fix drift. Check JS gzip size ≤ 250 KB.
- [ ] Same for the docs landing (`npm run preview`) at 1440 and 390.
- [ ] Open PR.
