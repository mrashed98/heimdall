# Heimdall: notes for agents

Rust (axum, sqlx 0.9, Postgres) server in `src/`, Svelte 5 console in `web/`,
Astro Starlight docs in `docs/site/`. CI runs the same commands as below.

```sh
scripts/check.sh                 # every CI check, as CI runs them; non-zero at the first failure
scripts/check.sh test web        # some steps (--list shows them; --skip docker to skip one)
make lint                        # no database: format, guards, clippy, web
make hooks                       # before every commit: make fast, then /review-pr on the staged changes
```

Before pushing, run `/review-pr` (`.claude/skills/review-pr/`) on the branch:
every pstack verification step plus `make lint`, and `make check` only when
Postgres and Docker are up; otherwise run `scripts/check.sh` yourself for the
full CI check. The pre-commit hook runs it report-only on the staged changes
(`scripts/review-pr.sh`; skip one commit with `HEIMDALL_SKIP_AI_REVIEW=1`).

Judge a check by its exit status. Piping it through `grep`/`tail` replaces
that status with grep's, which has passed a failing test and a failing
clippy before.

## Rules and what enforces them

Each rule exists because the mistake happened at least twice. Prefer
making a mistake impossible over adding a row here; drop a row once its
mistake can't happen.

| Rule | Enforced by |
|---|---|
| One severity list: import `SEVERITIES` / `Severity` from `web/src/lib/ui/format.ts`. | `web/scripts/conventions.mjs` (in `npm run check`) |
| No `aria-label` on a `div`/`span`/`p` without a role; use a landmark, a role or visible text. | `web/scripts/conventions.mjs` |
| A failed request never looks like empty data: no `.catch(() => [])` or `.catch(() => {})`; catch to `null` and say it could not be loaded. | `web/scripts/conventions.mjs` |
| Every `GET /api/v1` read route is requested without a `realms=` filter by a viewer limited to one realm, with other-realm data seeded that it must hide. Route paths are string literals. | `every_read_route_is_checked_for_realm_scope`: fails for a GET route that `session_read_access_is_realm_scoped` never requests without `realms=` (unless in `NOT_REALM_SCOPED` with a reason), and for a route path it cannot read. That other-realm data was seeded: review. |
| A step that must follow every matcher pass goes in `scheduler::rematch`, the only caller of `match_all` (startup included). The same for any job with two entry points: call one function, don't copy its steps. | Architecture for the matcher (one caller). Other jobs: review. |
| No secret (env value, decrypted UI secret, a webhook URL) in an API response, log, error, audit row or `outbox.last_error`. Route every failure text through `outbox::attempt`. | `outbox.last_error`: `last_error_scrubs_a_secret_the_server_echoed`; channel list response: `list_shows_config_and_ui_channels_without_secrets`; audit rows: `writes_audit_without_values`. Logs and other error responses: review only. |
| A channel's state (missing key, unreadable secret, removed realm, name clash) never loses or re-routes a queued alert. Two deliberate discards: deleting a UI channel discards its own unsent rows (`delete_discards_queued_rows`), and creating one discards unsent rows left under its name and type, so an old channel's backlog never reaches a new destination. The outbox is keyed by `(route, channel_type)`, so anything that changes which channel owns that pair must say what happens to unsent rows. A non-429 HTTP 4xx is the channel's fault (queue held) or the alert's (dropped) per type in `outbox::blame`, which has no catch-all arm, so a new channel type must decide. | `outbox::blame` (exhaustive match), `client_errors_blame_the_channel_or_the_alert` over every type. Tests in `src/notify/tests.rs`: `ui_channel_rows_stay_queued_without_key`, `ui_channel_with_removed_realm_still_gets_remaining_realms`, `delete_ui_channel_clashing_with_config_keeps_queued_rows`, `create_discards_orphaned_rows_for_same_name_and_type`. Judgment beyond these: review. |
| Time comes from `AppState.clock` (`Clock::fixed` in tests), never `Utc::now()` or SQL `now()`. A test that must use the real time (it compares against database `now()`, or a live server checks it) calls `Clock::default().now()`. | `Utc::now()`: clippy `disallowed-methods` (`clippy.toml`). The one exception is `Clock::now` itself (`src/lib.rs`); there is no other `allow`. SQL `now()`: review. |
| A test must fail when the behavior it names breaks; mutate the code once to see it fail. | Review (no tool) |
| Docs describe the code as it is: check status codes, paths and behaviors against the source before writing them. `docs/superpowers/` holds frozen plans and specs, not current behavior. | Links to repo files: `scripts/check_repo_links.py` (CI). Version numbers: `scripts/release_version.py check` (CI) for the places it lists. Site links: `npm run build` in `docs/site`. What the prose says: review. |
| Never run two `cargo test` processes against one `DATABASE_URL` at once: sqlx test databases are named by test path and collide. | `scripts/check.sh` refuses to start while one runs. A bare `cargo test`: review. |
| A guard covers everything it names, and proves it on examples of each form it claims. | `conventions.mjs`: each rule's `bad`/`good` examples are checked first. `every_read_route_is_checked_for_realm_scope`: reads every file under `src/`, and checks its route pattern on each `get` form first. |
| `scripts/check.sh` runs exactly what CI runs; a missing tool or a bad argument fails clearly, never skips. | `scripts/check_ci_sync.py` (`check.sh ci-sync`): fails on a CI check outside check.sh, a step CI never calls, differing Dockerfiles, or a check step (check.sh or docker build) with `if`/`continue-on-error`. `scripts/selftest.py` (`check.sh scripts`): feeds both scripts every bypass found so far and fails if one gets through. |
