//! Alert channels created in the UI, stored in `alert_channels`.
//!
//! Non-secret fields live in `settings` (the config shape minus `*_env`
//! keys). Secrets are a JSON map from field to value, sealed with the
//! `HEIMDALL_SECRET_KEY` under the AAD `alert_channels:<name>`; the names
//! alone are kept in `secret_names` so they can be listed without the key.
//! A stored channel becomes a `ChannelConfig` whose `*_env` keys hold
//! `ui:<name>:<field>` references instead of environment variable names.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use sqlx::{PgConnection, PgPool};

use super::channels::Secrets;
use crate::config::{ChannelConfig, HeimdallConfig};
use crate::egress::Egress;
use crate::model::Severity;
use crate::secrets::SecretKey;

/// A secret field of a channel type; its config key is `<name>_env`.
pub struct SecretField {
    pub name: &'static str,
    pub required: bool,
}

/// The secret fields of channel type `kind`, or `None` for an unknown type.
pub fn secret_fields(kind: &str) -> Option<&'static [SecretField]> {
    const fn f(name: &'static str, required: bool) -> SecretField {
        SecretField { name, required }
    }
    const WEBHOOK: &[SecretField] = &[f("webhook", true)];
    const TELEGRAM: &[SecretField] = &[f("bot_token", true)];
    const PAGERDUTY: &[SecretField] = &[f("routing_key", true)];
    const ALERTMANAGER: &[SecretField] = &[
        f("username", false),
        f("password", false),
        f("bearer_token", false),
    ];
    const GENERIC: &[SecretField] = &[f("url", true), f("secret", false)];
    const EMAIL: &[SecretField] = &[f("username", false), f("password", false)];
    const JIRA: &[SecretField] = &[f("username", false), f("token", true)];
    Some(match kind {
        "teams" | "slack" | "discord" | "mattermost" => WEBHOOK,
        "jira" => JIRA,
        "telegram" => TELEGRAM,
        "pagerduty" => PAGERDUTY,
        "alertmanager" => ALERTMANAGER,
        "webhook" => GENERIC,
        "email" => EMAIL,
        _ => return None,
    })
}

/// The value a UI channel's `<field>_env` key holds in its `ChannelConfig`.
pub fn ui_secret_ref(name: &str, field: &str) -> String {
    format!("ui:{name}:{field}")
}

/// Keys the store sets itself; `settings` may not carry them.
const RESERVED: &[&str] = &["type", "name", "realms", "min_severity", "digest"];

fn aad(name: &str) -> String {
    format!("alert_channels:{name}")
}

/// `POST /api/ui/channels` body. No `Debug`: it carries secret values.
#[derive(Deserialize)]
pub struct NewChannel {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    pub digest: Option<bool>,
    #[serde(default)]
    pub settings: Map<String, Value>,
    #[serde(default)]
    pub secrets: HashMap<String, String>,
}

/// `PATCH /api/ui/channels/{id}` body. Absent fields keep the stored value.
/// `digest`: `null` resets to the type default, `true`/`false` sets it.
/// `settings` replaces every non-secret setting. A secret mapped to a
/// string replaces it, to `null` clears it. No `Debug`: it carries secrets.
#[derive(Deserialize)]
pub struct ChannelPatch {
    pub realms: Option<Vec<String>>,
    pub min_severity: Option<Severity>,
    #[serde(default, deserialize_with = "present")]
    pub digest: Option<Value>,
    pub settings: Option<Map<String, Value>>,
    #[serde(default)]
    pub secrets: HashMap<String, Option<String>>,
}

/// Keeps an explicit `null` as `Some(Value::Null)`, unlike plain `Option`.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// Error strings never include secret values.
#[derive(Debug)]
pub enum StoreError {
    /// `HEIMDALL_SECRET_KEY` is not set: UI secrets cannot be written.
    NoKey,
    NameTaken,
    NotFound,
    Invalid(String),
    Db(sqlx::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoKey => f.write_str("HEIMDALL_SECRET_KEY is not set"),
            StoreError::NameTaken => f.write_str("channel name is already used"),
            StoreError::NotFound => f.write_str("channel not found"),
            StoreError::Invalid(m) => f.write_str(m),
            StoreError::Db(e) => write!(f, "database: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Db(e)
    }
}

fn invalid(m: impl Into<String>) -> StoreError {
    StoreError::Invalid(m.into())
}

/// The `ChannelConfig` a stored channel stands for, validated like a config
/// channel. `present` lists the secret fields that hold a value.
pub fn build(
    kind: &str,
    name: &str,
    realms: &[String],
    min_severity: Severity,
    digest: Option<bool>,
    settings: &Map<String, Value>,
    present: &[&str],
) -> Result<ChannelConfig, StoreError> {
    // Settings first, so the fixed keys and secret refs always win.
    let mut obj = settings.clone();
    obj.insert("type".into(), kind.into());
    obj.insert("name".into(), name.into());
    obj.insert("realms".into(), realms.into());
    obj.insert("min_severity".into(), json!(min_severity));
    obj.insert("digest".into(), json!(digest));
    for f in present {
        obj.insert(format!("{f}_env"), ui_secret_ref(name, f).into());
    }
    let key = format!("channel `{name}`");
    let c: ChannelConfig =
        serde_json::from_value(Value::Object(obj)).map_err(|e| invalid(format!("{key}: {e}")))?;
    c.validate(&key).map_err(|e| invalid(format!("{e:#}")))?;
    Ok(c)
}

/// A channel's full state, before writing.
struct Draft<'a> {
    kind: &'a str,
    name: &'a str,
    realms: &'a [String],
    min_severity: Severity,
    digest: Option<bool>,
    settings: &'a Map<String, Value>,
    secrets: &'a BTreeMap<String, String>,
}

/// The checks shared by create and update, on the final state. The name is
/// checked by `create` only: it cannot change afterwards.
fn check(cfg: &HeimdallConfig, d: &Draft) -> Result<ChannelConfig, StoreError> {
    let fields = secret_fields(d.kind)
        .ok_or_else(|| invalid(format!("unknown channel type `{}`", d.kind)))?;
    for k in d.settings.keys() {
        if k.ends_with("_env") || RESERVED.contains(&k.as_str()) {
            return Err(invalid(format!("settings may not contain `{k}`")));
        }
    }
    for (k, v) in d.secrets {
        if !fields.iter().any(|f| f.name == k) {
            return Err(invalid(format!(
                "`{k}` is not a secret of type `{}`",
                d.kind
            )));
        }
        if v.trim().is_empty() {
            return Err(invalid(format!("secret `{k}` must not be empty")));
        }
    }
    if let Some(f) = fields
        .iter()
        .find(|f| f.required && !d.secrets.contains_key(f.name))
    {
        return Err(invalid(format!("secret `{}` is required", f.name)));
    }
    if let Some(r) = d.realms.iter().find(|r| !cfg.realms.contains(r)) {
        return Err(invalid(format!("unknown realm `{r}`")));
    }
    let present: Vec<&str> = d.secrets.keys().map(String::as_str).collect();
    build(
        d.kind,
        d.name,
        d.realms,
        d.min_severity,
        d.digest,
        d.settings,
        &present,
    )
}

/// Refuse a destination the channel could never send to, as far as it can
/// be told without a lookup: a refused IP address, or, when
/// `console_channels.allowed_hosts` is set, a host outside it (looked up).
/// A host name that resolves to a refused address is only refused at send
/// time.
async fn check_destination(
    cfg: &HeimdallConfig,
    ch: &ChannelConfig,
    secrets: &BTreeMap<String, String>,
) -> Result<(), StoreError> {
    let refs: Secrets = secrets
        .iter()
        .map(|(field, v)| (ui_secret_ref(ch.name(), field), v.clone()))
        .collect();
    let Some((host, port)) = super::channels::destination(ch, &refs) else {
        return Ok(());
    };
    Egress::new(&cfg.console_channels)
        .check_console(&host, port)
        .await
        .map_err(invalid)
}

/// The `secrets` and `secret_names` column values for `secrets`.
fn seal(
    key: &SecretKey,
    name: &str,
    secrets: &BTreeMap<String, String>,
) -> (Option<Vec<u8>>, Vec<String>) {
    if secrets.is_empty() {
        return (None, Vec::new());
    }
    let plain = serde_json::to_vec(secrets).expect("a string map always serializes");
    (
        Some(key.seal(&aad(name), &plain)),
        secrets.keys().cloned().collect(),
    )
}

async fn name_in_db(conn: &mut PgConnection, name: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM alert_channels WHERE name=$1)")
        .bind(name)
        .fetch_one(conn)
        .await
}

/// A UI channel name must be usable inside `ui:<name>:<field>` unambiguously.
fn check_name(name: &str) -> Result<(), StoreError> {
    if name.trim().is_empty() {
        return Err(invalid("name must not be empty"));
    }
    if name != name.trim() {
        return Err(invalid("name must not start or end with whitespace"));
    }
    if name.contains(':') {
        return Err(invalid("name must not contain `:`"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("name must not contain control characters"));
    }
    Ok(())
}

/// Validate and insert a UI channel; returns its id. Undelivered alerts
/// still queued under the same name and type are discarded.
pub async fn create(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    key: Option<&SecretKey>,
    actor: &str,
    c: &NewChannel,
) -> Result<i64, StoreError> {
    check_name(&c.name)?;
    let secrets: BTreeMap<String, String> = c.secrets.clone().into_iter().collect();
    let built = check(
        cfg,
        &Draft {
            kind: &c.kind,
            name: &c.name,
            realms: &c.realms,
            min_severity: c.min_severity,
            digest: c.digest,
            settings: &c.settings,
            secrets: &secrets,
        },
    )?;
    check_destination(cfg, &built, &secrets).await?;
    if cfg.channels().iter().any(|ch| ch.name() == c.name) {
        return Err(StoreError::NameTaken);
    }
    let key = key.ok_or(StoreError::NoKey)?;
    let mut tx = pool.begin().await?;
    if name_in_db(&mut tx, &c.name).await? {
        return Err(StoreError::NameTaken);
    }
    let (sealed, names) = seal(key, &c.name, &secrets);
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO alert_channels (name, type, realms, min_severity, digest, settings, secrets, secret_names, created_by, updated_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING id",
    )
    .bind(&c.name)
    .bind(&c.kind)
    .bind(&c.realms)
    .bind(c.min_severity)
    .bind(c.digest)
    .bind(Value::Object(c.settings.clone()))
    .bind(sealed)
    .bind(&names)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        // A concurrent create took the name after our check.
        sqlx::Error::Database(d) if d.is_unique_violation() => StoreError::NameTaken,
        e => StoreError::Db(e),
    })?;
    // Unsent rows already under this name and type are orphans (a tick that
    // raced a delete, or a removed config channel; config names were rejected
    // above). Discard them so the new destination never inherits them.
    let discarded = sqlx::query(
        "UPDATE outbox SET sent_at=now(), card=jsonb_set(card,'{failed}','true'), \
         last_error='channel recreated' \
         WHERE route=$1 AND channel_type=$2 AND sent_at IS NULL",
    )
    .bind(&c.name)
    .bind(&c.kind)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let fields: BTreeSet<&str> = c
        .settings
        .keys()
        .map(String::as_str)
        .chain(names.iter().map(String::as_str))
        .collect();
    crate::admin::record(
        &mut tx,
        actor,
        "channel_created",
        json!({"name": c.name, "type": c.kind, "fields": fields, "discarded": discarded}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

#[derive(sqlx::FromRow)]
struct Row {
    name: String,
    #[sqlx(rename = "type")]
    kind: String,
    realms: Vec<String>,
    min_severity: Severity,
    digest: Option<bool>,
    settings: sqlx::types::Json<Map<String, Value>>,
    secrets: Option<Vec<u8>>,
    secret_names: Vec<String>,
}

/// How a stored channel loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiState {
    Ok,
    /// `HEIMDALL_SECRET_KEY` is not set: delivered without secrets, so its
    /// rows stay queued.
    KeyMissing,
    /// Its secrets can't be opened (sealed under another key). It stays in
    /// the list without secrets, so its rows queue and wait.
    Unreadable,
    /// It no longer builds (stored settings fail validation). It is left
    /// out of the list, so alerts raised meanwhile are not queued for it.
    Invalid,
    /// A config channel has the same name: the config one wins.
    NameClash,
}

/// A stored channel as loaded, for the API. Holds no secret values.
#[derive(Debug, Clone)]
pub struct UiChannel {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub state: UiState,
    pub config: Option<ChannelConfig>,
    /// The secret fields that hold a value (from `secret_names`).
    pub present: Vec<String>,
}

/// Every channel the alert pipeline delivers to. No `Debug`: `secrets`
/// holds decrypted values.
pub struct Channels {
    /// The config channels, then the deliverable UI channels.
    pub list: Vec<ChannelConfig>,
    /// The UI channels' decrypted secrets, keyed by `ui_secret_ref`.
    pub secrets: Secrets,
    pub ui: Vec<UiChannel>,
}

impl Channels {
    /// The config channels alone, with no UI channels.
    pub fn from_config(cfg: &HeimdallConfig) -> Channels {
        Channels {
            list: cfg.channels(),
            secrets: Secrets::new(),
            ui: Vec::new(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct LoadRow {
    id: i64,
    #[sqlx(flatten)]
    row: Row,
}

/// The config channels followed by the stored ones, with the stored ones'
/// secrets decrypted. Called once per alert run or drain tick. A stored
/// channel without its secrets (no key, or sealed under another key) stays
/// in `list`, so its rows are queued and wait. Realms removed from the config
/// are ignored (with a warning) rather than dropping the channel. One that
/// clashes with a config name or no longer builds is left out and warned
/// about once.
pub async fn load(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    key: Option<&SecretKey>,
) -> anyhow::Result<Channels> {
    let mut chans = Channels::from_config(cfg);
    let rows: Vec<LoadRow> = sqlx::query_as(
        "SELECT id, name, type, realms, min_severity, digest, settings, secrets, secret_names \
         FROM alert_channels ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let config_names: BTreeSet<String> = chans.list.iter().map(|c| c.name().to_string()).collect();
    for LoadRow { id, row } in rows {
        let present: Vec<&str> = row.secret_names.iter().map(String::as_str).collect();
        // Realms removed from the config since the channel was saved are
        // dropped, so the channel keeps the realms it still validly covers.
        // If none are left, the stored list is kept as is: an empty list
        // would mean "all realms". The channel then covers no configured
        // realm but stays listed, so its queued rows still drain.
        let (known, gone): (Vec<String>, Vec<String>) = row
            .realms
            .iter()
            .cloned()
            .partition(|r| cfg.realms.contains(r));
        if !gone.is_empty() {
            super::warn_once(
                &format!("ui-realms|{}|{}", row.name, gone.join(",")),
                &format!(
                    "alert channel `{}` from the UI covers realms no longer in the config \
                     ({}); they are ignored",
                    row.name,
                    gone.join(", ")
                ),
            );
        }
        let realms = if known.is_empty() {
            &row.realms
        } else {
            &known
        };
        let built = build(
            &row.kind,
            &row.name,
            realms,
            row.min_severity,
            row.digest,
            &row.settings.0,
            &present,
        );
        let mut ui = UiChannel {
            id,
            name: row.name.clone(),
            kind: row.kind.clone(),
            state: UiState::Ok,
            config: None,
            present: row.secret_names.clone(),
        };
        if config_names.contains(&row.name) {
            super::warn_once(
                &format!("ui-clash|{}", row.name),
                &format!(
                    "alert channel `{}` from the UI has the name of a config channel; \
                     the config one is used and the UI one is skipped",
                    row.name
                ),
            );
            ui.state = UiState::NameClash;
            ui.config = built.ok();
            chans.ui.push(ui);
            continue;
        }
        let config = match built {
            Ok(c) => c,
            Err(e) => {
                // Trade-off: a row that no longer builds is left out of
                // `list`, so `enqueue_alerts` queues nothing for it and its
                // alerts are lost until it is fixed; there is no
                // `ChannelConfig` to queue them under. `build` errors name
                // fields, never secret values (it never sees them).
                super::warn_once(
                    &format!("ui-invalid|{}", row.name),
                    &format!("alert channel `{}` from the UI is skipped: {e}", row.name),
                );
                ui.state = UiState::Invalid;
                chans.ui.push(ui);
                continue;
            }
        };
        if let Some(sealed) = &row.secrets {
            match key {
                None => ui.state = UiState::KeyMissing,
                Some(k) => match k.open(&aad(&row.name), sealed).ok().and_then(|plain| {
                    serde_json::from_slice::<BTreeMap<String, String>>(&plain).ok()
                }) {
                    Some(values) => {
                        for (field, value) in values {
                            chans
                                .secrets
                                .insert(ui_secret_ref(&row.name, &field), value);
                        }
                    }
                    None => {
                        super::warn_once(
                            &format!("ui-unreadable|{}", row.name),
                            &format!(
                                "alert channel `{}`: its secrets can't be read with the \
                                 current {}; its alerts stay queued until they are re-entered",
                                row.name,
                                crate::secrets::ENV_VAR
                            ),
                        );
                        ui.state = UiState::Unreadable;
                    }
                },
            }
        }
        chans.list.push(config.clone());
        ui.config = Some(config);
        chans.ui.push(ui);
    }
    Ok(chans)
}

/// Apply `p` to channel `id`. Validation runs on the merged state; on any
/// error the row is left unchanged.
pub async fn update(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    key: Option<&SecretKey>,
    actor: &str,
    id: i64,
    p: &ChannelPatch,
) -> Result<(), StoreError> {
    let mut tx = pool.begin().await?;
    let row: Option<Row> = sqlx::query_as(
        "SELECT name, type, realms, min_severity, digest, settings, secrets, secret_names FROM alert_channels WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let row = row.ok_or(StoreError::NotFound)?;
    // The stored secrets must be opened to merge them.
    let key = key.ok_or(StoreError::NoKey)?;
    // Secrets sealed under another key are unreadable. The patch may then
    // only proceed if it re-enters or explicitly clears every stored secret
    // (names come from `secret_names`, readable without the key); the row
    // is then resealed with the current key.
    let old: BTreeMap<String, String> = match &row.secrets {
        None => BTreeMap::new(),
        Some(sealed) => match key
            .open(&aad(&row.name), sealed)
            .ok()
            .and_then(|plain| serde_json::from_slice(&plain).ok())
        {
            Some(m) => m,
            None => {
                if let Some(n) = row
                    .secret_names
                    .iter()
                    .find(|n| !p.secrets.contains_key(n.as_str()))
                {
                    return Err(invalid(format!(
                        "re-enter secret `{n}`: it can't be read with the current key"
                    )));
                }
                BTreeMap::new()
            }
        },
    };
    let fields = secret_fields(&row.kind)
        .ok_or_else(|| invalid(format!("unknown channel type `{}`", row.kind)))?;
    let mut secrets = old.clone();
    for (k, v) in &p.secrets {
        if !fields.iter().any(|f| f.name == k) {
            return Err(invalid(format!(
                "`{k}` is not a secret of type `{}`",
                row.kind
            )));
        }
        match v {
            Some(v) => secrets.insert(k.clone(), v.clone()),
            None => secrets.remove(k),
        };
    }
    let realms = p.realms.clone().unwrap_or_else(|| row.realms.clone());
    // A realm removed from the config since it was saved doesn't block an
    // unrelated edit; only a realm the edit adds must be configured.
    let checked_realms: Vec<String> = realms
        .iter()
        .filter(|r| cfg.realms.contains(r) || !row.realms.contains(r))
        .cloned()
        .collect();
    let min_severity = p.min_severity.unwrap_or(row.min_severity);
    let digest = match &p.digest {
        None => row.digest,
        Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err(invalid("digest must be true, false or null")),
    };
    let settings = p.settings.clone().unwrap_or_else(|| row.settings.0.clone());
    let built = check(
        cfg,
        &Draft {
            kind: &row.kind,
            name: &row.name,
            realms: &checked_realms,
            min_severity,
            digest,
            settings: &settings,
            secrets: &secrets,
        },
    )?;
    check_destination(cfg, &built, &secrets).await?;

    let mut changed: BTreeSet<&str> = BTreeSet::new();
    if realms != row.realms {
        changed.insert("realms");
    }
    if min_severity != row.min_severity {
        changed.insert("min_severity");
    }
    if digest != row.digest {
        changed.insert("digest");
    }
    let old_settings = &row.settings.0;
    for k in settings.keys().chain(old_settings.keys()) {
        if settings.get(k) != old_settings.get(k) {
            changed.insert(k);
        }
    }
    for k in secrets.keys().chain(old.keys()) {
        if secrets.get(k) != old.get(k) {
            changed.insert(k);
        }
    }

    let (sealed, names) = seal(key, &row.name, &secrets);
    sqlx::query(
        "UPDATE alert_channels SET realms=$2, min_severity=$3, digest=$4, settings=$5, secrets=$6, secret_names=$7, updated_at=now(), updated_by=$8 WHERE id=$1",
    )
    .bind(id)
    .bind(&realms)
    .bind(min_severity)
    .bind(digest)
    .bind(Value::Object(settings.clone()))
    .bind(sealed)
    .bind(&names)
    .bind(actor)
    .execute(&mut *tx)
    .await?;
    crate::admin::record(
        &mut tx,
        actor,
        "channel_updated",
        json!({"name": row.name, "type": row.kind, "fields": changed}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The name and type of channel `id`, locked until the transaction ends.
async fn name_and_type(conn: &mut PgConnection, id: i64) -> Result<(String, String), StoreError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, type FROM alert_channels WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(conn)
            .await?;
    row.ok_or(StoreError::NotFound)
}

/// How many alerts are queued for channel `id`: what deleting it discards.
pub async fn queued_count(pool: &PgPool, cfg: &HeimdallConfig, id: i64) -> Result<i64, StoreError> {
    let mut tx = pool.begin().await?;
    let (name, kind) = name_and_type(&mut tx, id).await?;
    if config_owns(cfg, &name, &kind) {
        return Ok(0);
    }
    let n = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE route=$1 AND channel_type=$2 AND sent_at IS NULL",
    )
    .bind(&name)
    .bind(&kind)
    .fetch_one(&mut *tx)
    .await?;
    Ok(n)
}

/// Whether a config channel has this name and type. It wins a clash with a
/// UI channel, so the queued rows under that (name, type) are its own.
fn config_owns(cfg: &HeimdallConfig, name: &str, kind: &str) -> bool {
    cfg.channels()
        .iter()
        .any(|c| c.name() == name && c.type_name() == kind)
}

/// Delete channel `id` and discard its queued alerts in the same
/// transaction, so a later channel with the same name and type never sends
/// them. If a config channel has the same name and type, the queued alerts
/// are that channel's and are left alone. Needs no key. Returns how many
/// alerts were discarded.
pub async fn delete(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    actor: &str,
    id: i64,
) -> Result<u64, StoreError> {
    let mut tx = pool.begin().await?;
    let (name, kind) = name_and_type(&mut tx, id).await?;
    sqlx::query("DELETE FROM alert_channels WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let discarded = if config_owns(cfg, &name, &kind) {
        0
    } else {
        sqlx::query(
            "UPDATE outbox SET sent_at=now(), card=jsonb_set(card,'{failed}','true'), \
             last_error='channel deleted' \
             WHERE route=$1 AND channel_type=$2 AND sent_at IS NULL",
        )
        .bind(&name)
        .bind(&kind)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };
    crate::admin::record(
        &mut tx,
        actor,
        "channel_deleted",
        json!({"name": name, "type": kind, "discarded": discarded}),
    )
    .await?;
    tx.commit().await?;
    Ok(discarded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;

    fn cfg() -> HeimdallConfig {
        HeimdallConfig::from_yaml(
            "realms: [prod, staging]\nchannels:\n  - type: slack\n    name: cfg-slack\n    webhook_env: SLACK_URL\n    min_severity: high\n",
        )
        .unwrap()
    }

    fn key() -> SecretKey {
        SecretKey::parse(&STANDARD.encode([7u8; 32])).unwrap()
    }

    fn new(v: serde_json::Value) -> NewChannel {
        serde_json::from_value(v).unwrap()
    }

    fn patch(v: serde_json::Value) -> ChannelPatch {
        serde_json::from_value(v).unwrap()
    }

    async fn stored(pool: &PgPool, id: i64) -> (Option<Vec<u8>>, Vec<String>) {
        sqlx::query_as("SELECT secrets, secret_names FROM alert_channels WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn opened(k: &SecretKey, name: &str, sealed: &[u8]) -> serde_json::Value {
        serde_json::from_slice(&k.open(&format!("alert_channels:{name}"), sealed).unwrap()).unwrap()
    }

    #[test]
    fn build_maps_secret_fields_to_ui_refs() {
        let c = build(
            "slack",
            "s",
            &[],
            Severity::High,
            None,
            &Map::new(),
            &["webhook"],
        )
        .unwrap();
        let ChannelConfig::Slack(w) = c else {
            panic!("not slack")
        };
        assert_eq!(w.webhook_env, "ui:s:webhook");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_stores_ciphertext_not_plaintext(pool: PgPool) {
        let k = key();
        let id = create(
            &pool,
            &cfg(),
            Some(&k),
            "alice",
            &new(json!({"type":"slack","name":"s","min_severity":"high",
                "secrets":{"webhook":"https://hooks.example/x"}})),
        )
        .await
        .unwrap();
        let (sealed, names) = stored(&pool, id).await;
        let sealed = sealed.unwrap();
        let plain = b"https://hooks.example/x";
        assert!(!sealed.windows(plain.len()).any(|w| w == plain));
        assert_eq!(names, ["webhook"]);
        assert_eq!(
            opened(&k, "s", &sealed),
            json!({"webhook":"https://hooks.example/x"})
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_rejects_env_keys_in_settings(pool: PgPool) {
        let err = create(
            &pool,
            &cfg(),
            Some(&key()),
            "alice",
            &new(json!({"type":"slack","name":"s","min_severity":"high",
                "settings":{"webhook_env":"DATABASE_URL"},
                "secrets":{"webhook":"https://hooks.example/x"}})),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_rejects_config_name_and_unknown_realm(pool: PgPool) {
        let err = create(
            &pool,
            &cfg(),
            Some(&key()),
            "alice",
            &new(
                json!({"type":"slack","name":"cfg-slack","min_severity":"high",
                "secrets":{"webhook":"https://hooks.example/x"}}),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::NameTaken), "{err:?}");
        let err = create(
            &pool,
            &cfg(),
            Some(&key()),
            "alice",
            &new(
                json!({"type":"slack","name":"s","min_severity":"high","realms":["nope"],
                "secrets":{"webhook":"https://hooks.example/x"}}),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_without_key_is_no_key(pool: PgPool) {
        let err = create(
            &pool,
            &cfg(),
            None,
            "alice",
            &new(json!({"type":"slack","name":"s","min_severity":"high",
                "secrets":{"webhook":"https://hooks.example/x"}})),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::NoKey), "{err:?}");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM alert_channels")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_keeps_a_realm_removed_from_the_config(pool: PgPool) {
        let k = key();
        let id = create(
            &pool,
            &cfg(),
            Some(&k),
            "alice",
            &new(
                json!({"type":"slack","name":"s","min_severity":"high","realms":["prod","staging"],
                "secrets":{"webhook":"https://hooks.example/x"}}),
            ),
        )
        .await
        .unwrap();
        // staging is gone from the config now.
        let narrowed = HeimdallConfig::from_yaml("realms: [prod]\n").unwrap();
        update(
            &pool,
            &narrowed,
            Some(&k),
            "bob",
            id,
            &patch(json!({"min_severity":"critical"})),
        )
        .await
        .unwrap();
        let realms: Vec<String> =
            sqlx::query_scalar("SELECT realms FROM alert_channels WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            realms,
            ["prod", "staging"],
            "the stored realm is kept, not dropped"
        );
        // Adding a realm the config doesn't have is still refused.
        assert!(matches!(
            update(
                &pool,
                &narrowed,
                Some(&k),
                "bob",
                id,
                &patch(json!({"realms":["prod","nope"]}))
            )
            .await,
            Err(StoreError::Invalid(_))
        ));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_keeps_omitted_secret_and_clears_null(pool: PgPool) {
        let k = key();
        let cfg = cfg();
        let id = create(
            &pool,
            &cfg,
            Some(&k),
            "alice",
            &new(json!({"type":"webhook","name":"w","min_severity":"high",
                "secrets":{"url":"https://hook.example/u","secret":"sig"}})),
        )
        .await
        .unwrap();
        update(
            &pool,
            &cfg,
            Some(&k),
            "bob",
            id,
            &patch(json!({"secrets":{"secret":null}})),
        )
        .await
        .unwrap();
        let (sealed, names) = stored(&pool, id).await;
        assert_eq!(names, ["url"]);
        assert_eq!(
            opened(&k, "w", &sealed.unwrap()),
            json!({"url":"https://hook.example/u"})
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_cannot_clear_required_secret(pool: PgPool) {
        let k = key();
        let cfg = cfg();
        let id = create(
            &pool,
            &cfg,
            Some(&k),
            "alice",
            &new(json!({"type":"slack","name":"s","min_severity":"high",
                "secrets":{"webhook":"https://hooks.example/x"}})),
        )
        .await
        .unwrap();
        let before = stored(&pool, id).await;
        let err = update(
            &pool,
            &cfg,
            Some(&k),
            "bob",
            id,
            &patch(json!({"secrets":{"webhook":null}})),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(stored(&pool, id).await, before);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_recovers_unreadable_secrets(pool: PgPool) {
        let cfg = cfg();
        let a = key();
        let b = SecretKey::parse(&STANDARD.encode([9u8; 32])).unwrap();
        let id = create(
            &pool,
            &cfg,
            Some(&a),
            "alice",
            &new(json!({"type":"slack","name":"s","min_severity":"high",
                "secrets":{"webhook":"https://hooks.example/x"}})),
        )
        .await
        .unwrap();
        let before = stored(&pool, id).await;
        let err = update(
            &pool,
            &cfg,
            Some(&b),
            "bob",
            id,
            &patch(json!({"min_severity":"critical"})),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(stored(&pool, id).await, before);
        update(
            &pool,
            &cfg,
            Some(&b),
            "bob",
            id,
            &patch(json!({"secrets":{"webhook":"https://hooks.example/new"}})),
        )
        .await
        .unwrap();
        let (sealed, names) = stored(&pool, id).await;
        assert_eq!(names, ["webhook"]);
        assert_eq!(
            opened(&b, "s", &sealed.unwrap()),
            json!({"webhook":"https://hooks.example/new"})
        );

        // A webhook channel: re-entering only `url` would drop `secret`.
        let id = create(
            &pool,
            &cfg,
            Some(&a),
            "alice",
            &new(json!({"type":"webhook","name":"w","min_severity":"high",
                "secrets":{"url":"https://hook.example/u","secret":"sig"}})),
        )
        .await
        .unwrap();
        let before = stored(&pool, id).await;
        let err = update(
            &pool,
            &cfg,
            Some(&b),
            "bob",
            id,
            &patch(json!({"secrets":{"url":"https://hook.example/v"}})),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, StoreError::Invalid(m) if m.contains("`secret`")),
            "{err:?}"
        );
        assert_eq!(stored(&pool, id).await, before);
        update(
            &pool,
            &cfg,
            Some(&b),
            "bob",
            id,
            &patch(json!({"secrets":{"url":"https://hook.example/v","secret":null}})),
        )
        .await
        .unwrap();
        let (sealed, names) = stored(&pool, id).await;
        assert_eq!(names, ["url"]);
        assert_eq!(
            opened(&b, "w", &sealed.unwrap()),
            json!({"url":"https://hook.example/v"})
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_unrelated_to_secrets_cannot_drop_unreadable_ones(pool: PgPool) {
        let cfg = cfg();
        let a = key();
        let b = SecretKey::parse(&STANDARD.encode([9u8; 32])).unwrap();
        let id = create(
            &pool,
            &cfg,
            Some(&a),
            "alice",
            &new(
                json!({"type":"alertmanager","name":"am","min_severity":"high",
                "settings":{"url":"https://am.example"},
                "secrets":{"username":"u","password":"p"}}),
            ),
        )
        .await
        .unwrap();
        let before = stored(&pool, id).await;
        let err = update(
            &pool,
            &cfg,
            Some(&b),
            "bob",
            id,
            &patch(json!({"min_severity":"critical"})),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(stored(&pool, id).await, before);
        let sev: Severity =
            sqlx::query_scalar("SELECT min_severity FROM alert_channels WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sev, Severity::High);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_rejects_bad_names(pool: PgPool) {
        for name in ["a:b", " a", ""] {
            let err = create(
                &pool,
                &cfg(),
                Some(&key()),
                "alice",
                &new(json!({"type":"slack","name":name,"min_severity":"high",
                    "secrets":{"webhook":"https://hooks.example/x"}})),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&err, StoreError::Invalid(m) if m.contains("name")),
                "{name:?}: {err:?}"
            );
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM alert_channels")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_validates_merged_alertmanager_auth(pool: PgPool) {
        let k = key();
        let cfg = cfg();
        let id = create(
            &pool,
            &cfg,
            Some(&k),
            "alice",
            &new(
                json!({"type":"alertmanager","name":"am","min_severity":"high",
                "settings":{"url":"https://am.example"},
                "secrets":{"username":"u","password":"p"}}),
            ),
        )
        .await
        .unwrap();
        let err = update(
            &pool,
            &cfg,
            Some(&k),
            "bob",
            id,
            &patch(json!({"secrets":{"bearer_token":"t"}})),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        update(
            &pool,
            &cfg,
            Some(&k),
            "bob",
            id,
            &patch(json!({"secrets":{"username":null,"password":null,"bearer_token":"t"}})),
        )
        .await
        .unwrap();
        let (sealed, names) = stored(&pool, id).await;
        assert_eq!(names, ["bearer_token"]);
        assert_eq!(
            opened(&k, "am", &sealed.unwrap()),
            json!({"bearer_token":"t"})
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn writes_audit_without_values(pool: PgPool) {
        let k = key();
        let cfg = cfg();
        let id = create(
            &pool,
            &cfg,
            Some(&k),
            "alice",
            &new(json!({"type":"webhook","name":"w","min_severity":"high",
                "secrets":{"url":"https://hook.example/topsecret"}})),
        )
        .await
        .unwrap();
        update(
            &pool,
            &cfg,
            Some(&k),
            "bob",
            id,
            &patch(json!({"min_severity":"critical","secrets":{"secret":"hmac-value"}})),
        )
        .await
        .unwrap();
        let rows: Vec<(String, String, serde_json::Value)> =
            sqlx::query_as("SELECT username, action, detail FROM audit_log ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].0.as_str(), rows[0].1.as_str()),
            ("alice", "channel_created")
        );
        assert_eq!(
            rows[0].2,
            json!({"name":"w","type":"webhook","fields":["url"],"discarded":0})
        );
        assert_eq!(
            (rows[1].0.as_str(), rows[1].1.as_str()),
            ("bob", "channel_updated")
        );
        assert_eq!(
            rows[1].2,
            json!({"name":"w","type":"webhook","fields":["min_severity","secret"]})
        );
        for (_, _, d) in &rows {
            let s = d.to_string();
            assert!(!s.contains("topsecret") && !s.contains("hmac-value"), "{s}");
        }
    }
}
