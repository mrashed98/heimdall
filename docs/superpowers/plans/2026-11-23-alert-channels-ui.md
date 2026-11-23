# Alert channels in the UI: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admins see every alert channel (from the config and from the UI)
in Settings → Alert channels, and can create, edit, test and delete UI
channels. Their secrets are stored AES-256-GCM-encrypted in Postgres.

**Architecture:** UI channels live in a new `alert_channels` table.

- `notify::store::load` merges config channels with UI channels into one
  `Channels` value, once per alert run or drain tick.
- A UI channel is materialised as an ordinary `ChannelConfig` whose `*_env`
  fields hold synthetic references (`ui:<name>:<field>`). Those references
  resolve through a `Secrets` map of decrypted values, so the existing
  `missing_env`/`request` logic, "missing secret ⇒ stay queued", applies
  unchanged.
- A new admin API (`/api/v1/channels`) and a Svelte tab sit on top.

**Tech Stack:** Rust (axum, sqlx, `ring::aead`, serde), Svelte 5,
vitest, Astro Starlight docs.

**Spec:** `docs/superpowers/specs/2026-11-23-alert-channels-ui-design.md`

## Rulings (deviations from the spec, made while planning)

1. **API path:** `/api/v1/channels` with `Principal` + `require_admin`,
   like `src/admin.rs`, not a new `/api/ui/` prefix. Users, grants and
   audit already work this way, and admin API keys get the same access.
   No existing response shape changes.
2. **AAD:** `alert_channels:<name>`, not `<id>`. Name is unique and
   immutable, and it is known before the insert, which saves a second
   write.
3. **No new Helm value:** the chart's `envFrom: existingSecret` already
   passes every key of that Secret, so `HEIMDALL_SECRET_KEY` goes there.
   The docs say so.

## Global Constraints

- Postgres is the only state. Fits a 1 GB / 1 CPU pod.
- No new crypto crate: add `ring = "0.17"` as a direct dependency (0.17.14
  is already in `Cargo.lock`). `base64 = "0.23"` is already a dependency.
- A saved secret never leaves the server in plaintext:
  - not in API responses;
  - not in logs or errors;
  - not in the audit log;
  - not in `outbox.last_error`.
- A missing or malformed `HEIMDALL_SECRET_KEY` never stops startup and
  never stops config channels from delivering.
- UI channel name and type are immutable after creation.
- Names are unique across config and UI; the config wins a clash.
- WCAG AA; only existing tokens and components from `web/src/lib/ui`, plus
  the new `Dialog`.
- Verbatim copy:
  - empty state: "None yet. Findings stay pending and go out as grouped
    alerts once a channel exists."
  - config badge tooltip: "Defined in heimdall.yaml"
  - secret note: "This value can't be shown again."
- Rust toolchain: `export PATH="/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin:$PATH"`.
  Test DB: `DATABASE_URL=postgres://heimdall:heimdall@localhost:5433/heimdall`.
  Node: `export PATH="/opt/homebrew/bin:$PATH"`.

## Review Focus

1. **Settings that name env vars.** A UI channel whose `settings` contains
   any key ending in `_env` (for example `"webhook_env": "DATABASE_URL"`)
   must be rejected with 400. Otherwise a UI admin could make Heimdall send
   the server's own env vars to a URL. Test:
   `create_rejects_env_keys_in_settings` (Task 2).
2. **Key missing with UI channels present.** Findings in a realm covered
   only by a UI channel must still be queued, not marked notified with
   nothing queued. Test: `ui_channel_rows_stay_queued_without_key`
   (Task 3).
3. **A secret inside an error.** The `last_error` stored for a Telegram
   channel must not contain the bot token from the URL. Test:
   `last_error_is_redacted` (Task 4).
4. **PATCH clears a required secret.** `{"secrets":{"webhook":null}}` on a
   Slack channel → 400, and the stored secret is unchanged. Test:
   `patch_cannot_clear_required_secret` (Task 2).
5. **Delete, then recreate with the same name and type.** The old queued
   rows must not be delivered to the new channel. Test:
   `delete_discards_queued_rows` (Task 4).

---

### Task 1: Secret key and AES-GCM sealing

**Files:**
- Create: `src/secrets.rs`
- Modify: `src/lib.rs` (add `pub mod secrets;`, and add
  `secret_key: Option<Arc<secrets::SecretKey>>` and
  `channel_tests: Arc<std::sync::Mutex<HashMap<String, Instant>>>` to
  `AppState`, initialised in `with_grant_cache_ttl`), `Cargo.toml`
- Test: `src/secrets.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces:
  - `pub struct SecretKey` (wraps `ring::aead::LessSafeKey`; no `Debug`
    that prints the key)
  - `pub fn SecretKey::parse(b64: &str) -> anyhow::Result<SecretKey>`:
    standard base64, exactly 32 bytes.
  - `pub fn SecretKey::from_env() -> Option<SecretKey>`:
    - reads `HEIMDALL_SECRET_KEY`;
    - unset or empty → `None`;
    - malformed → `tracing::error!` (without the value), then `None`.
  - `pub fn SecretKey::seal(&self, aad: &str, plain: &[u8]) -> Vec<u8>`:
    output is a random 12-byte nonce (`ring::rand::SystemRandom`) followed
    by the ciphertext and tag.
  - `pub fn SecretKey::open(&self, aad: &str, sealed: &[u8]) -> anyhow::Result<Vec<u8>>`

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn seal_open_round_trip()            // open(aad, seal(aad, b"x")) == b"x"
#[test] fn open_fails_with_other_aad()       // seal with "alert_channels:a", open with "alert_channels:b" → Err
#[test] fn open_fails_with_other_key()       // two keys from different 32-byte inputs → Err
#[test] fn seal_uses_fresh_nonce()           // two seals of the same input differ
#[test] fn parse_rejects_wrong_length_and_bad_base64() // 31 bytes → Err; "not base64!" → Err; 32 bytes → Ok
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test --lib secrets::`
Expected: compile error (`secrets` module missing).

- [ ] **Step 3: Implement `src/secrets.rs` and the `AppState` fields**

Use `ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, Nonce, Aad}`.
`from_env` is called once in `with_grant_cache_ttl`.

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cargo test --lib secrets::`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/secrets.rs src/lib.rs
git commit -m "feat(secrets): AES-256-GCM sealing keyed by HEIMDALL_SECRET_KEY"
```

---

### Task 2: `alert_channels` table and the channel store

**Files:**
- Create: `migrations/0010_alert_channels.sql`, `src/notify/store.rs`
- Modify:
  - `src/notify/mod.rs` (`pub mod store;`)
  - `src/config.rs`:
    - derive `Serialize` on every channel struct, `ChatId`, `SmtpSecurity`
      and `Severity` if missing;
    - make `ChannelConfig::validate(&self, key)` `pub(crate)`.
- Test: `src/notify/store.rs` (`#[cfg(test)] mod tests`, `#[sqlx::test]`)

**Migration** (`0010_alert_channels.sql`):

```sql
CREATE TABLE alert_channels (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    realms TEXT[] NOT NULL DEFAULT '{}',
    min_severity TEXT NOT NULL,
    digest BOOLEAN,
    settings JSONB NOT NULL DEFAULT '{}',
    secrets BYTEA,
    -- Names of the stored secret fields, readable without the key.
    secret_names TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL
);
ALTER TABLE outbox ADD COLUMN last_error_at TIMESTAMPTZ, ADD COLUMN last_error TEXT;
```

**Interfaces:**
- Consumes: `secrets::SecretKey` (Task 1).
- Produces:
  - `pub struct SecretField { pub name: &'static str, pub required: bool }`
  - `pub fn secret_fields(kind: &str) -> Option<&'static [SecretField]>`.
    The env key is always `<name>_env`. The table:

| type | secret fields |
|---|---|
| teams, slack, discord | `webhook` (required) |
| telegram | `bot_token` (required) |
| pagerduty | `routing_key` (required) |
| alertmanager | `username`, `password`, `bearer_token` (all optional) |
| webhook | `url` (required), `secret` (optional) |
| email | `username`, `password` (optional) |

  - `pub fn ui_secret_ref(name: &str, field: &str) -> String`, which
    returns `format!("ui:{name}:{field}")`.
  - `#[derive(Deserialize)] pub struct NewChannel { #[serde(rename="type")] pub kind: String, pub name: String, #[serde(default)] pub realms: Vec<String>, pub min_severity: Severity, pub digest: Option<bool>, #[serde(default)] pub settings: serde_json::Map<String, Value>, #[serde(default)] pub secrets: HashMap<String, String> }`
  - `#[derive(Deserialize)] pub struct ChannelPatch { pub realms: Option<Vec<String>>, pub min_severity: Option<Severity>, pub digest: Option<Value>, pub settings: Option<Map<String,Value>>, #[serde(default)] pub secrets: HashMap<String, Option<String>> }`.
    For `digest`: absent keeps it; JSON `null` resets it to the type
    default; `true`/`false` sets it. `settings`, when present, replaces
    all non-secret settings.
  - `pub enum StoreError { NoKey, NameTaken, NotFound, Invalid(String), Db(sqlx::Error) }`
  - `pub fn build(kind: &str, name: &str, realms: &[String], min_severity: Severity, digest: Option<bool>, settings: &Map<String,Value>, present: &[&str]) -> Result<ChannelConfig, StoreError>`:
    - assembles `{"type", "name", "realms", "min_severity", "digest", ...settings, "<f>_env": ui_secret_ref(name, f) for f in present}`;
    - deserializes it into `ChannelConfig`;
    - runs `validate(&format!("channel `{name}`"))`.
  - `pub async fn create(pool: &PgPool, cfg: &HeimdallConfig, key: Option<&SecretKey>, actor: &str, c: &NewChannel) -> Result<i64, StoreError>`
  - `pub async fn update(pool: &PgPool, cfg: &HeimdallConfig, key: Option<&SecretKey>, actor: &str, id: i64, p: &ChannelPatch) -> Result<(), StoreError>`
  - `delete` is produced in Task 4.

Validation, the same for create and update (on the merged result):

- `kind` has a `secret_fields` entry → else `Invalid`.
- No `settings` key ends in `_env` or is one of `type`, `name`, `realms`,
  `min_severity`, `digest` → else `Invalid`.
- Every secret key is a known field for the type, every required field is
  present, and no value is empty.
- Every realm is in `cfg.realms`.
- `name` is not empty and not used by a config channel or another row
  (`NameTaken`).
- `build(...)` succeeds.
- `key` is `Some` → else `NoKey`.

Writes:

- `secrets` is `key.seal("alert_channels:<name>", serde_json::to_vec(&map))`, and `secret_names` is the map's sorted keys.
  It is NULL when the map is empty.
- Each successful write records an audit row in the same transaction via
  `crate::admin::record` (make it `pub(crate)` if not already):
  - create: `channel_created` with
    `{"name","type","fields":[<settings keys + secret field names>]}`;
  - update: `channel_updated` with
    `{"name","type","fields":[<changed keys>]}`;
  - values are never included.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn build_maps_secret_fields_to_ui_refs()   // slack, present ["webhook"] → WebhookChannel.webhook_env == "ui:s:webhook"
#[sqlx::test] async fn create_stores_ciphertext_not_plaintext(pool)  // secrets column does not contain the bytes of "https://hooks.example/x"
#[sqlx::test] async fn create_rejects_env_keys_in_settings(pool)      // settings {"webhook_env":"DATABASE_URL"} → Invalid
#[sqlx::test] async fn create_rejects_config_name_and_unknown_realm(pool) // name of a config channel → NameTaken; realms ["nope"] → Invalid
#[sqlx::test] async fn create_without_key_is_no_key(pool)             // key None → NoKey, no row
#[sqlx::test] async fn patch_keeps_omitted_secret_and_clears_null(pool) // webhook type: omit url keeps it; {"secret":null} removes it
#[sqlx::test] async fn patch_cannot_clear_required_secret(pool)       // slack {"webhook":null} → Invalid, stored bytes unchanged
#[sqlx::test] async fn patch_validates_merged_alertmanager_auth(pool) // stored username+password, add bearer_token → Invalid; null both + bearer → Ok
#[sqlx::test] async fn writes_audit_without_values(pool)              // audit detail has field names, not the secret string
```

- [ ] **Step 2: Run them and watch them fail**

Run: `DATABASE_URL=… cargo test --lib notify::store::`
Expected: compile error (`store` missing).

- [ ] **Step 3: Write the migration and implement `src/notify/store.rs`**

- [ ] **Step 4: Run the tests and watch them pass**

Run: `DATABASE_URL=… cargo test --lib notify::store::`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add migrations/0010_alert_channels.sql src/notify/store.rs src/notify/mod.rs src/config.rs src/admin.rs
git commit -m "feat(notify): store UI alert channels with encrypted secrets"
```

---

### Task 3: One channel list for the alert pipeline

**Files:**
- Modify:
  - `src/notify/store.rs` (add `load`)
  - `src/notify/channels/mod.rs` (secrets in `env` lookup)
  - `src/notify/mod.rs`, `src/notify/outbox.rs`, `src/notify/digest.rs`,
    `src/scheduler.rs`, `src/main.rs` (callers)
- Test: `src/notify/tests.rs`, `src/notify/channels/tests.rs`

**Interfaces:**
- Consumes: `store::secret_fields`, `ui_secret_ref`, `build` (Task 2),
  and `SecretKey::open` (Task 1).
- Produces:
  - `pub type Secrets = HashMap<String, String>` in `notify::channels`.
  - `pub fn missing_env(ch: &ChannelConfig, secrets: &Secrets) -> Option<String>`
  - `pub fn request(ch: &ChannelConfig, payload: &Value, now: DateTime<Utc>, secrets: &Secrets) -> anyhow::Result<Request>`
  - Lookup is `secrets.get(var)`, falling back to the env var. An empty
    value counts as unset.
  - `pub enum UiState { Ok, KeyMissing, Unreadable, NameClash }`
  - `pub struct UiChannel { pub id: i64, pub name: String, pub kind: String, pub state: UiState, pub config: Option<ChannelConfig>, pub present: Vec<String> }`
  - `pub struct Channels { pub list: Vec<ChannelConfig>, pub secrets: Secrets, pub ui: Vec<UiChannel> }`
  - `pub async fn store::load(pool: &PgPool, cfg: &HeimdallConfig, key: Option<&SecretKey>) -> anyhow::Result<Channels>`.
    `list` is `cfg.channels()` followed by the UI channels. A UI channel:
    - **Clashing name** → `NameClash`, left out of `list`, and
      `warn_once` is called.
    - **No key** → `KeyMissing`, kept in `list` with no secrets, so its
      rows stay queued.
    - **Decrypt fails** → `Unreadable`, kept in `list`, no secrets.
    - Otherwise its decrypted values go into `secrets` under
      `ui_secret_ref`.
    - `present` comes from the `secret_names` column (Task 2), so it is
      known even when the key is missing or wrong.
  - Signature changes: `enqueue_alerts(pool, cfg, chans: &Channels)`,
    `enqueue_first_run_summary(pool, cfg, chans, realm)`,
    `baseline(pool, cfg, chans, realm)`,
    `digest::maybe_send(pool, cfg, chans, now)`,
    `outbox::drain_once(pool, http, cfg, chans, now)`,
    `drain_with(pool, d, cfg, chans, now)`, `orphaned(pool, chans)`.
    Every `cfg.channels()` call inside `src/notify/` is replaced with
    `chans.list`.
  - Callers (scheduler ticks, `main.rs` baseline) call `store::load` once
    per tick or run, with `st.secret_key.as_deref()`, or
    `SecretKey::from_env()` in the CLI.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn request_reads_secret_from_map_before_env()               // channels/tests.rs: slack with webhook_env "ui:s:webhook", map has URL → Request::Http url == URL
#[sqlx::test] async fn ui_channel_is_delivered_like_a_config_one(pool) // wiremock receives the slack payload for a UI channel
#[sqlx::test] async fn ui_channel_rows_stay_queued_without_key(pool)   // create with key, load with None: row queued, drain sends nothing, finding is queued (outbox row exists)
#[sqlx::test] async fn unreadable_secret_keeps_rows_queued(pool)       // load with a different key → UiState::Unreadable, nothing sent
#[sqlx::test] async fn config_wins_a_name_clash(pool)                  // insert row named like a config channel directly in SQL → NameClash, not in list
```

- [ ] **Step 2: Run them and watch them fail**

Run: `DATABASE_URL=… cargo test --lib notify::`
Expected: compile errors on the new signatures.

- [ ] **Step 3: Implement `load`, thread `Secrets` through and update every caller**

- [ ] **Step 4: Run the whole suite**

Run: `DATABASE_URL=… cargo test`
Expected: everything passes (414 + the new tests); the existing notify
tests are only updated to the new signatures.

- [ ] **Step 5: Commit**

```bash
git add -A src migrations
git commit -m "feat(notify): deliver to UI channels alongside config channels"
```

---

### Task 4: Delivery errors, health and delete

**Files:**
- Modify: `src/notify/outbox.rs`, `src/notify/store.rs`
- Test: `src/notify/tests.rs`

**Interfaces:**
- Consumes: `Channels` (Task 3).
- Produces:
  - `drain_with` writes `last_error_at = now`, `last_error = <why>` on
    Retry, Hold and Rejected. `why` passes through the same redaction as
    logs: every string in `Request::Http.redact` is replaced with `[redacted]`.
  - `pub struct Health { pub queued: i64, pub last_sent_at: Option<DateTime<Utc>>, pub failing: Option<String> }`
  - `pub async fn outbox::health(pool: &PgPool) -> anyhow::Result<HashMap<(String, String), Health>>`.
    It is one grouped query by `(route, channel_type)`:
    - `queued` = count of unsent rows;
    - `last_sent_at` = max `sent_at` where `card->>'failed'` is null;
    - `failing` = `last_error` of the oldest unsent row.
  - `pub async fn outbox::send_now(d: &Delivery<'_>, ch: &ChannelConfig, secrets: &Secrets, now: DateTime<Utc>) -> Result<(), String>`:
    - renders a test `Alert` with title "Heimdall test alert", severity
      `unknown`, the first-run summary's kind, and one note: "This is a
      test from Heimdall. No action is needed.";
    - sends it through `channels::render`, `channels::request` and the
      private `send`;
    - any non-`Sent` outcome becomes `Err(redacted why)`.
  - `pub async fn store::delete(pool: &PgPool, actor: &str, id: i64) -> Result<u64, StoreError>`:
    - in one transaction: delete the row, then
      `UPDATE outbox SET sent_at=now(), card=jsonb_set(card,'{failed}','true'), last_error='channel deleted' WHERE route=$name AND channel_type=$type AND sent_at IS NULL`;
    - audits `channel_deleted` with `{"name","type","discarded":n}`;
    - returns `n`.
  - `pub async fn store::queued_count(pool, id) -> Result<i64, StoreError>`
    for the delete confirmation.

- [ ] **Step 1: Write the failing tests**

```rust
#[sqlx::test] async fn retry_records_last_error(pool)       // wiremock 503 → row has last_error_at and last_error mentioning 503; health(...).failing is Some
#[sqlx::test] async fn last_error_is_redacted(pool)         // telegram via wiremock 500: last_error does not contain the bot token
#[sqlx::test] async fn health_reports_queue_and_last_sent(pool) // 1 sent + 2 queued → queued 2, last_sent_at = sent time, failing None
#[sqlx::test] async fn delete_discards_queued_rows(pool)    // 2 queued; delete → 2; recreate same name/type; drain sends nothing
#[sqlx::test] async fn send_now_reports_errors(pool)        // wiremock 400 → Err containing "400"; 200 → Ok(())
```

- [ ] **Step 2: Run them and watch them fail**

Run: `DATABASE_URL=… cargo test --lib notify::`
Expected: compile errors (`health`, `send_now` and `delete` missing).

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the tests and watch them pass**

Run: `DATABASE_URL=… cargo test`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(notify): record delivery errors, channel health and delete"
```

---

### Task 5: Channels API

**Files:**
- Create: `src/channels_api.rs`
- Modify: `src/lib.rs` (`mod channels_api;`), `src/server.rs:31` (`.merge(crate::channels_api::routes())`)
- Test: `src/channels_api.rs` (`#[cfg(test)]`, using `server::router`
  as the existing server tests do)

**Interfaces:**
- Consumes: `store::{create, update, delete, queued_count, load, secret_fields}`,
  `outbox::{health, send_now}` and `AppState.{secret_key, channel_tests}`.
- Produces (every route `Principal` + `require_admin`, else 403):
  - `GET /api/v1/channels` returns `{ "management_enabled": bool, "channels": [ChannelView] }`.
    `ChannelView` is:
    `{ id: i64|null, source: "config"|"ui", type, name, realms, min_severity, digest: bool, settings: {..}, secrets: {<field>: {"set": bool}}, missing_env: [String], state: "ok"|"key_missing"|"unreadable"|"name_clash", health: {queued, last_sent_at, failing} }`.
    - `settings` is the serialized `ChannelConfig` minus `type`, `name`,
      `realms`, `min_severity`, `digest` and every `*_env` key.
    - For config channels, `missing_env` lists unset var names and
      `secrets.set` reflects env presence. For UI channels,
      `missing_env` is `[]`.
    - The order is the config channels in config order, then UI channels
      by name.
  - `POST /api/v1/channels` (body `NewChannel`) → 201 `{"id": i64}`.
  - `PATCH /api/v1/channels/{id}` (body `ChannelPatch`) → 204.
  - `GET /api/v1/channels/{id}/queued` → `{"queued": i64}`.
  - `DELETE /api/v1/channels/{id}` → 200 `{"discarded": u64}`.
  - `POST /api/v1/channels/{name}/test`:
    - 204 on success;
    - 502 `{"error": "<redacted why>"}` on failure;
    - 429 if the same name was tested less than 10 s ago (in
      `channel_tests`);
    - 409 for a UI channel whose state isn't `ok`;
    - 404 for an unknown name;
    - writes an audit row `channel_tested` with `{"name","type","ok":bool}`.
  - Error mapping: `NoKey`→409, `NameTaken`→409, `NotFound`→404,
    `Invalid(m)`→400 `{"error": m}`.

- [ ] **Step 1: Write the failing tests**

```rust
#[sqlx::test] async fn non_admin_gets_403(pool)
#[sqlx::test] async fn list_shows_config_and_ui_channels_without_secrets(pool) // body does not contain the secret string; secrets.webhook.set == true; source fields right
#[sqlx::test] async fn create_without_key_is_409_and_list_says_disabled(pool)  // management_enabled false
#[sqlx::test] async fn test_endpoint_rate_limits(pool)   // wiremock 200: first 204, immediate second 429
#[sqlx::test] async fn delete_returns_discarded_count(pool)
```

- [ ] **Step 2: Run them and watch them fail**

Run: `DATABASE_URL=… cargo test --lib channels_api::`
Expected: compile error.

- [ ] **Step 3: Implement `src/channels_api.rs` and merge the routes**

- [ ] **Step 4: Run the full suite, clippy and fmt**

Run: `DATABASE_URL=… cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/channels_api.rs src/lib.rs src/server.rs
git commit -m "feat(api): admin endpoints for alert channels"
```

---

### Task 6: Web helpers and the `Dialog` component

**Files:**
- Create: `web/src/lib/channels.ts`, `web/src/lib/channels.test.ts`,
  `web/src/lib/ui/Dialog.svelte`
- Modify: `web/src/lib/ui/index.ts` (export `Dialog`),
  `web/src/lib/ui/ui.test.ts`

**Interfaces:**
- Produces:
  - `export type FieldKind = 'text' | 'url' | 'number' | 'list' | 'select' | 'secret'`
  - `export interface Field { key: string; label: string; kind: FieldKind; required: boolean; options?: string[]; hint?: string }`
  - `export const CHANNEL_TYPES: { id: string; label: string; fields: Field[] }[]`, in this order:

| id | label | fields (secret fields `kind:'secret'`) |
|---|---|---|
| teams | Microsoft Teams | webhook* (secret, "Webhook URL") |
| slack | Slack | webhook* (secret, "Webhook URL") |
| discord | Discord | webhook* (secret, "Webhook URL") |
| telegram | Telegram | bot_token* (secret), chat_id* (text), api_url (url) |
| pagerduty | PagerDuty | routing_key* (secret), url (url) |
| alertmanager | Alertmanager | url* (url), username, password, bearer_token (secret), expire_after_hours (number) |
| email | Email | host* (text), port (number), security (select: starttls, tls, none), from* (text), to* (list), username, password (secret) |
| webhook | Webhook | url* (secret, "Endpoint URL"), secret (secret, "Signing secret") |

  `*` = required.

  - `export function channelBody(type: string, values: Record<string,string>, common: {name:string; realms:string[]; min_severity:string; digest:boolean|null}): object`.
    It returns the POST body:
    - empty optional fields are dropped;
    - `number` fields are parsed to numbers;
    - `list` fields are split on commas and newlines, then trimmed;
    - secret fields go under `secrets`, everything else under `settings`.
  - `export function patchBody(type: string, values: Record<string,string>, replaced: Record<string,'keep'|'replace'|'remove'>, common: {...}): object`:
    - `keep` → the field is omitted;
    - `replace` → the new value;
    - `remove` → `null`.
  - `export function generateSecret(): string`: 32 bytes from
    `crypto.getRandomValues`, as 64 lowercase hex characters.
  - `export function healthLabel(h: {queued:number; last_sent_at:string|null; failing:string|null}, now: Date): { text: string; tone: 'ok'|'warn'|'muted' }`:
    - `failing` → `"Failing"` (warn);
    - else `last_sent_at` → `"Sent <relative>"` (ok), using the existing
      `ui/format.ts` relative-time helper;
    - else `"No deliveries yet"` (muted).
    - When `queued > 0`, append `" · N queued"`.
  - `Dialog.svelte` props:
    `{ open: boolean (bindable), title: string, children: Snippet, actions?: Snippet, onclose?: () => void }`.
    - Native `<dialog>`: `showModal()` when `open` becomes true, `close()`
      when it becomes false.
    - Labelled by its title `<h2>` via `$props.id()`.
    - The native `close` event sets `open = false`, so Escape works.

- [ ] **Step 1: Write the failing tests**

```ts
test('channelBody splits secrets from settings and drops empty optionals')  // slack → {type:'slack', name, realms, min_severity, digest, settings:{}, secrets:{webhook:'https://x'}}
test('channelBody parses numbers and lists')            // email port '587' → 587; to 'a@x, b@x\nc@x' → 3 items
test('patchBody keeps, replaces and removes secrets')   // keep → absent; remove → null
test('generateSecret returns 64 hex chars and differs per call')
test('healthLabel prefers failing, then last sent, then none')
test('Dialog renders title and is labelled by it')      // ui.test.ts, same style as the existing component tests
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cd web && npx vitest run src/lib/channels.test.ts src/lib/ui/ui.test.ts`
Expected: fail (module missing).

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run the web suite and the checks**

Run: `cd web && npx vitest run && npx svelte-check`
Expected: all pass, 0 errors.

- [ ] **Step 5: Commit**

```bash
git add web/src/lib/channels.ts web/src/lib/channels.test.ts web/src/lib/ui
git commit -m "feat(web): channel form helpers and a Dialog component"
```

---

### Task 7: The Alert channels tab

**Files:**
- Create: `web/src/lib/Channels.svelte`
- Modify: `web/src/lib/Access.svelte`:
  - the tab id union gains `'channels'`;
  - tab items become Members & access, API keys, **Alert channels**,
    Audit log;
  - when `tab === 'channels'`, render `<Channels availableRealms={availableRealms} />`
    instead of the table block. Its own loading, data and pagination are
    not used for this tab.

**Interfaces:**
- Consumes: the Task 5 API, the Task 6 helpers and `Dialog`, and
  `Button`, `Badge`, `DataTable`, `EmptyState`, `ErrorState`, `Input`,
  `Menu`, `Pill`, `Select`, `Skeleton` from `./ui`.
- Produces: `Channels.svelte` with props `{ availableRealms: string[] }`.

Behaviour (the spec's UI section has the reference screens):

- **Header row:** "Findings go out as grouped alerts to every channel that
  covers their realm.", with an "Add channel" `Menu` listing
  `CHANNEL_TYPES` labels on the right. If `!management_enabled`, a notice
  replaces the menu: "Set HEIMDALL_SECRET_KEY to add channels here. See
  the alert channels guide."
- **Table columns:** Name, Type, Realms ("All" when empty), Min severity,
  Digest, Last delivery (`healthLabel`), Source (`Badge`: "config" with
  tooltip "Defined in heimdall.yaml", or "UI"), Actions.
- **Row states:**
  - `missing_env` non-empty → "Missing: VAR1, VAR2" under the name;
  - `key_missing` → "Key missing";
  - `unreadable` → "Secret unreadable: re-enter it";
  - `name_clash` → "Name clash with config: delete this channel".
- **Actions:**
  - **Test** on every row: POST test, then a status line with the result
    or the error text.
  - **Edit** on UI rows: opens the dialog.
  - **⋯ menu** on UI rows: Delete.
- **Add/Edit dialog:**
  - Common fields: name (disabled on edit), realms (checkbox group of
    `availableRealms`; none checked = all), minimum severity (`Select`:
    critical, high, medium, low), digest (`Select`: Default, On, Off).
  - Then the type's fields.
  - **Secret fields, new:** password `Input` with a Show toggle, and
    under it "This value can't be shown again."
  - **Secret fields, saved:** "•••••••• Saved" with **Replace**, plus
    **Remove** when the field is not required.
  - **Webhook `secret` field:** a **Generate** button that fills it with
    `generateSecret()`, switches the input to visible and shows Copy.
  - Primary button: "Create channel" or "Save changes". Server 400 errors
    are shown in the dialog.
- **Delete:** a Dialog titled "Delete <name>?" with the body "Alerts for
  these realms will no longer go to this channel. N queued alerts will be
  discarded." N comes from `GET …/queued`. The danger button is "Delete
  channel".
- **Empty:** `EmptyState` titled "No alert channels" with the verbatim
  body from Global Constraints. Its type buttons open the add dialog with
  that type preselected.

Pages have no component tests in this repo. The logic lives in the Task 6
helpers, which are tested. This task's gate is `svelte-check`, the build
and the manual check below.

- [ ] **Step 1: (no test step)**

- [ ] **Step 2: Implement `Channels.svelte` and the Access tab**

- [ ] **Step 3: Check**

Run: `cd web && npx svelte-check && npx vitest run && npm run build`
Expected: 0 errors; all tests pass; the build succeeds.

Manual: run `heimdall serve` against the test DB with `HEIMDALL_SECRET_KEY`
set and one config Slack channel.

- Add a webhook channel with a generated secret.
- Test it against a local `nc -l` endpoint, or check that the 502 message
  shows.
- Edit it: Replace, then Remove the secret.
- Delete it.
- Unset the key and confirm the notice and the "Key missing" state.
- Take screenshots at 1440 and 390 px wide.

- [ ] **Step 4: Commit**

```bash
git add web/src/lib/Channels.svelte web/src/lib/Access.svelte
git commit -m "feat(web): manage alert channels in Settings"
```

---

### Task 8: Docs

**Files:**
- Modify:
  - `docs/site/src/content/docs/guides/alert-channels.mdx`: a new section
    "Managing channels in the console" covering:
    - generating the key (`openssl rand -base64 32`), adding it to the
      Secret named by `existingSecret`, and backing it up;
    - what happens without the key or with a wrong one;
    - that name and type are immutable;
    - that a config name wins a clash;
    - that delete discards queued alerts.
  - `docs/site/src/content/docs/reference/configuration.md`:
    `HEIMDALL_SECRET_KEY` in the env var list.
  - The HTTP API reference page that documents `/api/v1/audit` (find it
    with `grep -rl "api/v1/audit" docs/site`): the six channel endpoints
    and their shapes from Task 5.
  - `docs/site/src/content/docs/project/changelog.md`: an Unreleased entry.
- Create: `docs/adr/0005-encrypted-channel-secrets.md` and its site copy
  `docs/site/src/content/docs/decisions/0005-encrypted-channel-secrets.md`
  (same format as 0003). Decision: UI channel secrets are
  AES-256-GCM-encrypted in Postgres under `HEIMDALL_SECRET_KEY`. Rejected:
  env var names only (needs a restart per channel) and writing Kubernetes
  Secrets (RBAC to write Secrets, and against the spirit of 0003). Add it
  to `decisions/index.md`.

- [ ] **Step 1: Write the docs**

- [ ] **Step 2: Build the docs site**

Run: `cd docs/site && npm run build`
Expected: the build succeeds with no broken links.

- [ ] **Step 3: Commit**

```bash
git add docs
git commit -m "docs: managing alert channels in the console, ADR 0005"
```
