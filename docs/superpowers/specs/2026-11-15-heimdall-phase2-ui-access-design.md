# Heimdall Phase 2: Web UI and Access Control

Status: approved direction (user, 2026-11-15). Builds on `2026-11-12-heimdall-design.md` (Phase 1). Phase 1 behaviour, routes and CLI stay as they are unless this document says otherwise.

## 1. Why

Heimdall's Phase 1 is API + CLI + Teams only. People who don't live in a terminal need a friendly web UI to see what is vulnerable, what to upgrade, and to take oaths. Opening a UI to more people needs real access control: today the only credential is an API key with a scope (`ingest` / `read` / `admin`).

Success: someone opens Heimdall in a browser, signs in with the company SSO, and within 10 seconds sees which services in their realms have Critical/High findings and what fixes them, and can snooze one with an oath. It looks and feels like the same product as the docs site and CLI.

## 2. Goals / non-goals / anti-goals

Goals
- Embedded single-page app served by the existing axum server, in the same binary and image.
- Sign-in with OIDC (primary) and local users (break-glass), roles per realm, sessions, audit log.
- Every page uses Heimdall's visual identity (section 6).

Non-goals (this phase)
- Editing `heimdall.yaml` config from the UI (watchers, Teams routes stay in config/GitOps).
- Multi-channel alerting (issue #17), SAML, SCIM, MFA for local users.

Anti-goals (a failure even if it works)
- Breaking the 1 GB RAM / 1 CPU budget, or adding a second container.
- Loading anything from a CDN at runtime (fonts, scripts, images). Clusters may be air-gapped.
- Breaking existing API-key clients (CI gate, Sight, scanner, CLI).
- A generic admin-template look that doesn't read as Heimdall.

## 3. Architecture

- Frontend: **Svelte 5 + Vite + TypeScript** in `web/`. Output `web/dist/`, embedded into the binary with `rust-embed` (already-standard, small). Pin exact versions; commit `package-lock.json`.
- `cargo build` / `cargo test` must work **without Node**: if `web/dist` is absent, embed a tiny placeholder `index.html` ("UI not built; run `npm run build` in web/"). The Dockerfile gains a Node build stage that produces `web/dist` before `cargo build --release`.
- Serving: `/api/*`, `/healthz`, `/readyz`, `/metrics`, `/auth/*` are server routes; any other GET serves the asset or falls back to `index.html` (history-mode routing). Hashed assets get `Cache-Control: public, max-age=31536000, immutable`; `index.html` gets `no-cache`.
- Security headers on UI responses: strict CSP (`default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`.
- Budgets: JS ≤ 250 KB gzipped total; added server RSS ≤ 30 MB at idle; no new background loops except session cleanup folded into the existing retention job.

## 4. Access control

### 4.1 Identities
- **OIDC users**: Authorization Code + PKCE via the `openidconnect` crate. Any compliant issuer (Keycloak, Entra ID, Google, Dex, GitHub via Dex). Identity key = `issuer + sub`; display name from `name`/`preferred_username`; email from `email`.
- **Local users**: username + password, Argon2id hashes (`argon2` crate, OWASP default params). Intended as break-glass. Created via CLI only: `heimdall user create <name> [--role ...]` (prompts for password, no flag for it), `heimdall user passwd <name>`, `heimdall user disable <name>`, `heimdall user list`. Local login can be turned off with `auth.local.enabled: false`.
- **API keys**: unchanged, still sent as `Authorization: Bearer hd_...`. Keys keep their scopes; `read`/`ingest`/`admin` map to the role model below (read = viewer on all realms, admin = admin). Keys are also listed/created/revoked in the UI by admins.

### 4.2 Roles and realms
Roles, each granted for a list of realms or `*`:
- `viewer`: read findings, services, components, releases, oaths.
- `editor`: viewer + create/extend/revoke oaths in those realms.
- `admin`: everything, including users, role grants, API keys, audit log. **Admin is global and still requires the name to be in config `admins`** (Phase 1 rule, spec §12 decision 6). For OIDC users the match is on `preferred_username` or `email`; for local users on the username. A grant of admin to someone not listed is refused, as for keys today.

Grants come from two places, unioned:
1. **Config mappings** (GitOps-friendly), from an OIDC groups claim:
   ```yaml
   auth:
     public_url: https://heimdall.example.com     # used to build the OIDC redirect URI
     session: { idle_hours: 12, absolute_days: 7 }
     local: { enabled: true }
     oidc:
       issuer: https://keycloak.example.com/realms/eng
       client_id: heimdall
       client_secret_env: HEIMDALL_OIDC_CLIENT_SECRET
       scopes: [openid, profile, email, groups]
       groups_claim: groups
       role_mappings:
         - { group: platform, role: editor, realms: ["*"] }
         - { group: payments-devs, role: viewer, realms: [payments] }
       default_role: null        # or { role: viewer, realms: ["*"] } for any signed-in user
   ```
2. **Grants stored in Postgres**, edited by admins in the UI (for local users and individual OIDC users).

A user with no grants can sign in but sees a friendly "no access yet, ask an admin" page. `auth` is optional: with no `auth` block, the UI shows only the API-key sign-in (paste a key, stored in memory for the tab only) so Phase 1 deployments keep working.

### 4.3 Enforcement
- One `Principal { kind: user|key, name, grants }` extractor replaces/extends `Authed`; every existing handler checks role + realm through it. List endpoints (`/api/v1/findings`, `/services`, `/realms`, `/releases`, `/oaths`) **filter to permitted realms** rather than 403. Oath create/extend/revoke check `editor` on the oath's realm(s); an all-realms oath needs editor on `*`.
- Existing API-key semantics and response shapes must not change (the CI gate and Sight depend on them).

### 4.4 Sessions and CSRF
- Server-side sessions in Postgres (`sessions` table: random 256-bit id stored as SHA-256 hash, principal, created_at, last_seen_at, expires_at). Cookie `heimdall_session`: `HttpOnly; Secure; SameSite=Lax; Path=/` (`Secure` dropped only when `public_url` is `http://localhost...`).
- Idle timeout 12 h, absolute 7 days (config). Logout deletes the row. Disabling a user or removing a grant takes effect on the next request (grants re-read per request, cached ≤ 30 s).
- CSRF: cookie-authenticated `POST/PUT/PATCH/DELETE` must send header `X-CSRF-Token` matching the session's token (returned by `GET /auth/me`). Bearer-key requests are exempt.
- Local login: constant-time compare, generic error message, throttle 5 failures per username per 15 min and per IP, logged to audit.
- OIDC: validate `state`, `nonce`, PKCE; ID-token signature and audience via discovery/JWKS (cached); no tokens stored beyond what is needed (store none after login).

### 4.5 Routes (new)
- `GET /auth/login` (lists enabled methods), `POST /auth/local`, `GET /auth/oidc/start`, `GET /auth/oidc/callback`, `POST /auth/logout`, `GET /auth/me` (user, roles, realms, csrf token).
- `GET/POST /api/v1/users`, `PATCH /api/v1/users/{id}` (disable/enable), `GET/PUT /api/v1/users/{id}/grants`, `GET /api/v1/audit` (admin, paginated).
- Migration `0006_users_sessions.sql`: `users`, `user_grants`, `sessions`, `audit_log`, `login_failures`. Retention job prunes expired sessions and login failures; audit log kept 365 days (config `retention.audit_days`).

### 4.6 Audit log
Records: login success/failure (method, user, IP), logout, user created/disabled, grant changes, API key created/revoked, oath created/extended/revoked (oath events already exist; link them). Admins view it in the UI with filters.

## 5. Pages

Navigation (left rail, collapses on mobile): Overview, Findings, Services, Releases, Oaths, and for admins: Access (Users, API keys, Audit). A realm switcher (multi-select, "All my realms" default) sits in the top bar and filters every page; it is remembered in the URL query so links are shareable.

1. **Overview**: counts of open findings by severity per realm (stacked bars), "Fix available" count, top 10 services by risk, latest releases from watchers, end-of-life warnings, last sync time of each feed (OSV, NVD, k8s feed, Sight). Empty state uses an illustration.
2. **Findings**: table with filters (severity, kind, realm, service, has-fix, status: open/snoozed/ignored/resolved), text search on advisory id/alias/package, sortable, paginated server-side. Row detail panel: advisory title, CVSS + vector, aliases, affected component + installed version, fixed versions, which services/images carry it, links to OSV/NVD/GHSA, oath history, and "Take an oath" (snooze/ignore with expiry and reason) for editors.
3. **Services**: list by realm with finding counts; service detail with components (sources: git/ci/cluster/declared, purl, version), images and digests, findings.
4. **Releases**: watcher results (new majors, EOL dates, releases that fix CVEs you're affected by) with the release-note classification.
5. **Oaths**: active / expiring soon / expired, with extend and revoke.
6. **Access** (admin): users (OIDC + local, last login, disable), grants editor (role × realms), API keys (create shows the key once with a copy button, revoke), audit log.
7. **Sign-in page**, **no-access page**, **404**, **error page**.

All lists must work with 10k findings without freezing (server-side paging, no client-side full loads).

## 6. Visual identity (must match the docs site and CLI)

Source of truth: `docs/site/src/styles/custom.css`, `docs/site/src/assets/logo.svg`, `src/ui/banner.rs`, `src/ui/render.rs`. Put these values in one `web/src/lib/theme.css` as CSS custom properties; never hard-code colours in components.

- **Accent** (Bifröst indigo): dark theme `--accent-low #1e2452`, `--accent #5b6ee1`, `--accent-high #b8c3fd`; light theme `--accent-low #dde3ff`, `--accent #3b4fc4`, `--accent-high #2a398f`. Backgrounds/greys follow Starlight's palette (dark page `#17181c`, light page `#ffffff`) so the UI and docs feel like one site.
- **The Bifröst gradient**: `linear-gradient(90deg, #e5484d, #f5a524, #30a46c, #3e63dd, #8e4ec6)`. Used sparingly, exactly as the docs do: a 3px line under the top bar (opacity 0.85), the logo arc, and the sign-in page. Never as a large fill behind text.
- **Logo**: reuse `logo.svg` (Bifröst arc over the watching eye) in the top bar and as the favicon. Wordmark "Heimdall" next to it; tagline "The watcher at the Bifröst" on the sign-in page.
- **Severity colours** (same semantics as the CLI table): Critical = white on `#e5484d` filled badge; High = `#e5484d` text/outline; Medium = `#f5a524`; Low = `#3e63dd`; Unknown/None = neutral grey. Always pair colour with the word (accessibility). Fix-available = `#30a46c`.
- **Fonts**: the same system stacks Starlight uses, no web-font downloads: sans `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji'`; mono `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace`. Advisory ids, purls, versions and digests render in mono.
- **Light and dark**: follow `prefers-color-scheme`, with a toggle in the top bar (stored in `localStorage`). Contrast WCAG AA in both (the docs palette is already checked: `#a5b4fc` on `#17181c` ≈ 9:1, `#3b4fc4` on white ≈ 7:1).
- **Illustrations**: original inline SVGs in the logo's style: thin rounded strokes, the Bifröst arc and eye motif, accent colour plus the gradient used sparingly. Needed: sign-in hero (Heimdall's watchtower at the bridge), "All quiet at the Bifröst" (no findings), "No access yet", 404 "This path leaves the Nine Realms", and a generic error. Each under 6 KB, with `aria-hidden` and a text caption. No third-party illustration packs, no clip-art, no brand logos.
- **Voice**: use the project's names (Sight, Gjallarhorn, Hofund, Oaths, realms) as the CLI and docs do, but always with a plain explanation next to them for newcomers (e.g. "Oaths: snoozed or ignored findings").
- Motion: subtle (≤ 150 ms transitions), respect `prefers-reduced-motion`.

## 7. Testing and CI
- Rust: integration tests (existing `sqlx::test` pattern) for local login + throttling, session expiry, CSRF required on cookie mutations and not on bearer keys, realm filtering per role, editor vs viewer on oaths, admin-requires-`admins`-list, OIDC callback against a `wiremock` issuer (discovery, JWKS, token endpoint), audit entries written, SPA fallback and cache headers, placeholder page when `web/dist` is absent.
- Web: `svelte-check`, `vitest` for the API client and role guards, and a production build. New CI job named `web` (lint, check, test, build); the `docker` job builds with the UI included.
- Existing `fmt`, `clippy -D warnings`, `test`, `helm`, `audit`, `docs` must stay green; `cargo deny` must pass with the new crates.

## 8. Packaging and docs
- `deploy/Dockerfile`: add a Node build stage for `web/`. Image must stay single-binary distroless/alpine as today.
- Helm: values for `auth` config, `HEIMDALL_OIDC_CLIENT_SECRET` via the existing secret, and an optional `ingress` (off by default, className/hosts/tls).
- Docs site: new guide pages "Using the web UI" and "Sign-in and access control" (OIDC setup with Keycloak/Entra examples, local break-glass user, role mappings), reference updates for new routes, config keys, CLI `user` subcommands, and env vars. Screenshots optional.
- README: short "Web UI" section.

## 9. Left to the builder
Component structure, state management (Svelte stores/runes), table implementation (no heavy grid libraries; hand-rolled is fine), chart rendering (inline SVG, no chart library over 30 KB gz), exact page layouts within section 6, and wording, as long as sections 2–8 hold.
