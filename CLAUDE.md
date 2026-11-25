# Heimdall: notes for agents

Rust (axum, sqlx 0.9, Postgres) server in `src/`, Svelte 5 console in `web/`,
Astro Starlight docs in `docs/site/`. CI runs the same commands as below.

```sh
export PATH="/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:$PATH"
export DATABASE_URL=postgres://heimdall:heimdall@localhost:5433/heimdall
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
cd web && npm run check && npm test && npm run build
```

## Rules and what enforces them

Each rule exists because the mistake happened at least twice. Prefer
making a mistake impossible over adding a row here; drop a row once its
mistake can't happen.

| Rule | Enforced by |
|---|---|
| One severity list: import `SEVERITIES` / `Severity` from `web/src/lib/ui/format.ts`. | `web/scripts/conventions.mjs` (in `npm run check`) |
| No `aria-label` on a `div`/`span`/`p` without a role; use a landmark, a role or visible text. | `web/scripts/conventions.mjs` |
| No secret (env value, decrypted UI secret, a webhook URL) in an API response, log, error, audit row or `outbox.last_error`. Route every failure text through `outbox::attempt`. | `outbox.last_error`: `last_error_scrubs_a_secret_the_server_echoed`; channel list response: `list_shows_config_and_ui_channels_without_secrets`; audit rows: `writes_audit_without_values`. Logs and other error responses: review only. |
| A channel's state (missing key, unreadable secret, removed realm, name clash) never loses or re-routes a queued alert. Two deliberate discards: deleting a UI channel discards its own unsent rows (`delete_discards_queued_rows`), and creating one discards unsent rows left under its name and type, so an old channel's backlog never reaches a new destination. The outbox is keyed by `(route, channel_type)`, so anything that changes which channel owns that pair must say what happens to unsent rows. | Tests in `src/notify/tests.rs`: `ui_channel_rows_stay_queued_without_key`, `ui_channel_with_removed_realm_still_gets_remaining_realms`, `delete_ui_channel_clashing_with_config_keeps_queued_rows`, `create_discards_orphaned_rows_for_same_name_and_type`. Judgment beyond these: review. |
| A test must fail when the behavior it names breaks. Drive time with the fixed test clock plus `make_due`, never `Utc::now()` against database defaults; mutate the code once to see the test fail. | Review (no tool) |
| Docs describe the code as it is: check status codes, paths and behaviors against the source before writing them. `docs/superpowers/` holds frozen plans and specs, not current behavior. | Review; `npm run build` in `docs/site` builds the site and validates links, not what the prose says |
| Never run two `cargo test` processes against one `DATABASE_URL` at once: sqlx test databases are named by test path and collide. | Review (no tool) |
