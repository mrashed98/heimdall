# Heimdall console redesign

Status: approved direction (user, 2026-11-22: "yes now it look a lot better").
Mockups: Claude Design canvas https://claude.ai/artifact/2hb9XDNJ7wjQTvKf9WicjW
(artboards Main, Finding, Overview, Inventory, Releases, Oaths, Settings).
Builds on `2026-11-15-heimdall-phase2-ui-access-design.md`; its anti-goals
(no CDN at runtime, 250 KB gzipped JS budget, strict CSP) still hold.

## Why
The Phase 2 UI read as a generic admin template. The user wants a
Sentry-style security console with a palette and logo drawn from the
Heimdall character (bronze-gold armour, steel, sky teal, ember).

## Goals
- Sentry structure: 68px icon rail (logo, Findings, Overview, Inventory,
  Releases, Oaths, Settings at the bottom, user avatar); a 212px sub-nav on
  Findings with saved views; a stream of issue rows; a full finding page
  with a right-hand rail.
- Brand: horned-helmet logo (SVG in the canvas notes), CINZEL "HEIMDALL"
  wordmark, dark palette below. Dark is the default; the light toggle stays
  with a derived light palette.
- Feed rows show the advisory summary and `package installed -> fix`.
- One row per vulnerability: a `fixavailable` finding whose `vuln` sibling
  (same advisory, component, service, realm) is open is folded into it.

## Palette (tokens)
bg #0b1013, rail #070b0d, panel #11181c, panel2 #162026, border #223038,
text #ece6d8, muted #98a6ad, gold #d6a24e, gold-soft #2a2216, sky #74aac0,
critical #ff5b4f, high #f2872f, medium #e8c94f, low #74aac0,
unknown #7d8a91, ok #5cc79a. UI font: system-ui; code: ui-monospace;
wordmark: Cinzel 700, self-hosted.

## Non-goals
- Trend charts (wait on #50 metrics history); the Overview shows no
  placeholder chart in the product.
- New count endpoints for sub-nav views: counts show only where
  `/api/v1/status` already has them.
- Changing roles, auth flows, or API-key clients.

## Anti-goals
- Breaking any existing API response for API-key clients (new fields are
  UI-path only, as EPSS is).
- Dropping existing behaviour: all six filters, sort, pagination, oath
  form, realm switcher, theme toggle, sign-in methods, admin-only Access.

## Calls I made (check these)
- Finding detail moves from a side panel to its own route `/findings/:id`.
- Views map to existing filters: Feed (all open), Likely exploited
  (sort=epss desc), Fix available (kind=fixavailable), Critical & high
  (severity), Kubernetes CVEs (kind=k8scve), Major releases, Release-note
  CVEs, End of life (their kinds).
- "Settings" is the renamed Access page, still admin-only.
