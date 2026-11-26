use std::path::Path;

use anyhow::Context;
use chrono::Weekday;
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::model::Severity;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeimdallConfig {
    pub realms: Vec<String>,
    #[serde(default)]
    pub digest: DigestConfig,
    /// Microsoft Teams routes (the original form; still supported).
    #[serde(default)]
    pub teams: Vec<TeamsRoute>,
    /// Alert channels of any type, Teams included.
    #[serde(default)]
    pub channels: Vec<ChannelConfig>,
    #[serde(default)]
    pub watchers: WatcherTargets,
    #[serde(default)]
    pub declared: Vec<DeclaredComponent>,
    #[serde(default)]
    pub registries: Vec<RegistryCred>,
    #[serde(default)]
    pub schedules: Schedules,
    /// Registry hosts or host/org prefixes (e.g. `ghcr.io/mrashed98`) whose
    /// images are ours and never release-watched.
    #[serde(default)]
    pub own_registries: Vec<String>,
    /// Key names allowed to hold the admin scope.
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub nvd: NvdConfig,
    #[serde(default)]
    pub retention: Retention,
    #[serde(default)]
    pub sight: SightConfig,
    pub auth: Option<AuthConfig>,
    /// Limits on channels created in the console.
    #[serde(default)]
    pub console_channels: crate::egress::ConsoleChannels,
}

impl HeimdallConfig {
    pub fn load(path: &Path) -> anyhow::Result<HeimdallConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::from_yaml(&text).with_context(|| format!("config {}", path.display()))
    }

    /// Parse and validate YAML text.
    pub fn from_yaml(text: &str) -> anyhow::Result<HeimdallConfig> {
        let cfg: HeimdallConfig = serde_saphyr::from_str(text).context("parsing")?;
        cfg.validate().context("invalid")?;
        Ok(cfg)
    }

    /// Semantic checks serde cannot express. Errors name the offending key.
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::bail;
        if let Some(d) = &self.sight.docker {
            d.host
                .parse::<crate::inventory::docker::DockerHost>()
                .map_err(|e| anyhow::anyhow!("sight.docker.host: {e}"))?;
            if d.name
                .as_deref()
                .is_some_and(|n| n.trim().is_empty() || n.contains('/'))
            {
                bail!("sight.docker.name must not be empty or contain `/`");
            }
            if let Some(r) = self.docker_realm() {
                if !self.realms.iter().any(|x| x == r) {
                    bail!("sight.docker.realm: `{r}` is not in realms");
                }
            }
        }
        if self.digest.hour > 23 {
            bail!("digest.hour must be 0-23, got {}", self.digest.hour);
        }
        for (key, v) in [
            ("schedules.sight_minutes", self.schedules.sight_minutes),
            ("schedules.osv_minutes", self.schedules.osv_minutes),
            ("schedules.k8s_cve_minutes", self.schedules.k8s_cve_minutes),
            (
                "schedules.watchers_minutes",
                self.schedules.watchers_minutes,
            ),
            ("nvd.minutes", self.nvd.minutes),
        ] {
            if v == 0 {
                bail!("{key} must be greater than 0");
            }
        }
        if let Some(auth) = &self.auth {
            let url = url::Url::parse(&auth.public_url).context("auth.public_url")?;
            if url.host_str().is_none()
                || !(url.scheme() == "https"
                    || (url.scheme() == "http" && url.host_str() == Some("localhost")))
                || url.username() != ""
                || url.password().is_some()
            {
                bail!("auth.public_url must be HTTPS or HTTP localhost");
            }
            if auth.session.idle_hours == 0 || auth.session.absolute_days == 0 {
                bail!("auth.session timeouts must be positive");
            }
            for cidr in &auth.trusted_proxies {
                cidr.parse::<ipnet::IpNet>()
                    .context("auth.trusted_proxies")?;
            }
            if let Some(oidc) = &auth.oidc {
                if oidc.groups_max_age_minutes < 5 {
                    bail!("auth.oidc.groups_max_age_minutes must be at least 5");
                }
                for (role, realms) in oidc
                    .role_mappings
                    .iter()
                    .map(|m| (m.role, &m.realms))
                    .chain(oidc.default_role.iter().map(|g| (g.role, &g.realms)))
                {
                    if role == Role::Admin && realms.as_slice() != ["*"] {
                        bail!("admin grants require all realms");
                    }
                }
                if oidc.client_id.is_empty()
                    || oidc.client_secret_env.is_empty()
                    || url::Url::parse(&oidc.issuer).is_err()
                {
                    bail!("auth.oidc requires a valid issuer, client_id and client_secret_env");
                }
                for grant in oidc
                    .role_mappings
                    .iter()
                    .map(|m| &m.realms)
                    .chain(oidc.default_role.iter().map(|g| &g.realms))
                {
                    if grant.is_empty()
                        || grant.iter().any(|r| r != "*" && !self.realms.contains(r))
                    {
                        bail!("auth.oidc mapping has unknown or empty realms");
                    }
                }
            }
        }
        let known = |r: &str| self.realms.iter().any(|k| k == r);
        for (i, t) in self.teams.iter().enumerate() {
            for r in &t.realms {
                if !known(r) {
                    bail!("teams[{i}].realms: unknown realm `{r}` (not in `realms`)");
                }
            }
        }
        let mut names: Vec<(String, String)> = Vec::new();
        for (i, t) in self.teams.iter().enumerate() {
            let key = format!("teams[{i}]");
            check_name(&key, &t.name, &mut names)?;
            check_env(&format!("{key}.webhook_env"), &t.webhook_env)?;
        }
        for (i, c) in self.channels.iter().enumerate() {
            let key = format!("channels[{i}]");
            check_name(&key, c.name(), &mut names)?;
            for r in c.realms() {
                if !known(r) {
                    bail!("{key}.realms: unknown realm `{r}` (not in `realms`)");
                }
            }
            c.validate(&key)?;
        }
        for (i, d) in self.declared.iter().enumerate() {
            if !known(&d.realm) {
                bail!(
                    "declared[{i}].realm: unknown realm `{}` (not in `realms`)",
                    d.realm
                );
            }
        }
        if let Some(r) = self.sight.realm.as_deref() {
            if !known(r) {
                bail!("sight.realm: unknown realm `{r}` (not in `realms`)");
            }
        }
        Ok(())
    }

    /// Every alert channel: the `teams:` routes (as Teams channels) first,
    /// then `channels:`. Names are unique across both (see `validate`).
    pub fn channels(&self) -> Vec<ChannelConfig> {
        self.teams
            .iter()
            .cloned()
            .map(ChannelConfig::Teams)
            .chain(self.channels.iter().cloned())
            .collect()
    }

    /// The realm in-process Sight scans: `sight.realm`, else the first realm.
    pub fn sight_realm(&self) -> Option<&str> {
        self.sight
            .realm
            .as_deref()
            .or(self.realms.first().map(|r| r.as_str()))
    }

    /// The realm of the in-process Docker scan, when one is configured.
    pub fn docker_realm(&self) -> Option<&str> {
        let d = self.sight.docker.as_ref()?;
        d.realm.as_deref().or(self.sight_realm())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub public_url: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub local: LocalConfig,
    pub oidc: Option<OidcConfig>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(default = "idle_hours")]
    pub idle_hours: u32,
    #[serde(default = "absolute_days")]
    pub absolute_days: u32,
}
fn idle_hours() -> u32 {
    12
}
fn absolute_days() -> u32 {
    7
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_hours: idle_hours(),
            absolute_days: absolute_days(),
        }
    }
}
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub enabled: bool,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_env: String,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default = "groups_max_age_minutes")]
    pub groups_max_age_minutes: u32,
    #[serde(default)]
    pub admin_match_username: bool,
    #[serde(default)]
    pub groups_claim: Option<String>,
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
    pub default_role: Option<GrantConfig>,
}
fn groups_max_age_minutes() -> u32 {
    60
}

impl OidcConfig {
    pub fn effective_scopes(&self) -> Vec<String> {
        let mut scopes = self.scopes.clone().unwrap_or_else(|| {
            let mut scopes = vec!["openid".into(), "profile".into(), "email".into()];
            if self.groups_claim.is_some() {
                scopes.push("groups".into());
            }
            scopes
        });
        if !scopes.iter().any(|scope| scope == "openid") {
            scopes.insert(0, "openid".into());
        }
        scopes
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMapping {
    pub group: String,
    pub role: Role,
    pub realms: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantConfig {
    pub role: Role,
    pub realms: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

/// In-process Sight (`heimdall serve` scanning the cluster it runs in).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SightConfig {
    /// The realm of the cluster Heimdall runs in. Default: the first realm.
    pub realm: Option<String>,
    /// Also read a Docker host's running containers (Sight for Docker).
    pub docker: Option<DockerSight>,
}

/// `sight.docker`: the Docker host Heimdall reads in-process.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerSight {
    /// `unix:///var/run/docker.sock` (default), or `tcp://host:2375` for a
    /// socket proxy.
    #[serde(default = "default_docker_host")]
    pub host: String,
    /// The host's name in service names (`<name>/<service>`). Default: the
    /// name Docker reports.
    pub name: Option<String>,
    /// The realm its containers belong to. Default: `sight.realm`, else the
    /// first realm.
    pub realm: Option<String>,
}

fn default_docker_host() -> String {
    crate::inventory::docker::DEFAULT_HOST.to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestConfig {
    #[serde(default = "default_weekday")]
    pub weekday: Weekday,
    #[serde(default = "default_hour")]
    pub hour: u32,
    #[serde(default = "default_timezone")]
    pub timezone: Tz,
}

impl Default for DigestConfig {
    fn default() -> Self {
        DigestConfig {
            weekday: default_weekday(),
            hour: default_hour(),
            timezone: default_timezone(),
        }
    }
}

fn default_weekday() -> Weekday {
    Weekday::Mon
}
fn default_hour() -> u32 {
    9
}
fn default_timezone() -> Tz {
    Tz::UTC
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeamsRoute {
    pub name: String,
    /// Name of the environment variable holding the webhook URL.
    pub webhook_env: String,
    /// Empty means all realms.
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

fn check_name(key: &str, name: &str, seen: &mut Vec<(String, String)>) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("{key}.name must not be empty");
    }
    if let Some((_, other)) = seen.iter().find(|(n, _)| n == name) {
        anyhow::bail!("{key}.name: channel name `{name}` is already used by {other}");
    }
    seen.push((name.to_string(), key.to_string()));
    Ok(())
}

fn check_env(key: &str, var: &str) -> anyhow::Result<()> {
    if var.trim().is_empty() {
        anyhow::bail!("{key} must name an environment variable");
    }
    Ok(())
}

fn check_opt_env(key: &str, var: &Option<String>) -> anyhow::Result<()> {
    match var {
        Some(v) => check_env(key, v),
        None => Ok(()),
    }
}

/// An http(s) URL without credentials in it (those go in `*_env` keys).
fn check_url(key: &str, raw: &str) -> anyhow::Result<()> {
    let u = url::Url::parse(raw).map_err(|e| anyhow::anyhow!("{key}: invalid URL: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        anyhow::bail!("{key}: URL must be http or https");
    }
    if !u.username().is_empty() || u.password().is_some() {
        anyhow::bail!("{key}: URL must not contain credentials; use the *_env keys");
    }
    Ok(())
}

/// One alert channel. `type` picks the kind; every kind has `name`,
/// `realms` (empty: all) and `min_severity`. Secrets are never written
/// inline: `*_env` keys name the environment variable that holds them.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ChannelConfig {
    Teams(TeamsRoute),
    Slack(WebhookChannel),
    Discord(WebhookChannel),
    Telegram(TelegramChannel),
    PagerDuty(PagerDutyChannel),
    Alertmanager(AlertmanagerChannel),
    Webhook(GenericWebhookChannel),
    Email(EmailChannel),
}

/// The fields every channel type shares.
macro_rules! common {
    ($self:ident, $c:ident => $e:expr) => {
        match $self {
            ChannelConfig::Teams($c) => $e,
            ChannelConfig::Slack($c) | ChannelConfig::Discord($c) => $e,
            ChannelConfig::Telegram($c) => $e,
            ChannelConfig::PagerDuty($c) => $e,
            ChannelConfig::Alertmanager($c) => $e,
            ChannelConfig::Webhook($c) => $e,
            ChannelConfig::Email($c) => $e,
        }
    };
}

impl ChannelConfig {
    pub fn name(&self) -> &str {
        common!(self, c => &c.name)
    }

    /// Realms this channel covers; empty means all.
    pub fn realms(&self) -> &[String] {
        common!(self, c => &c.realms)
    }

    pub fn min_severity(&self) -> Severity {
        common!(self, c => c.min_severity)
    }

    /// The `type` value, also stored with each outbox row.
    pub fn type_name(&self) -> &'static str {
        match self {
            ChannelConfig::Teams(_) => "teams",
            ChannelConfig::Slack(_) => "slack",
            ChannelConfig::Discord(_) => "discord",
            ChannelConfig::Telegram(_) => "telegram",
            ChannelConfig::PagerDuty(_) => "pagerduty",
            ChannelConfig::Alertmanager(_) => "alertmanager",
            ChannelConfig::Webhook(_) => "webhook",
            ChannelConfig::Email(_) => "email",
        }
    }

    /// Does this channel cover `realm`? An empty realm list covers all.
    /// Does this channel receive the weekly digest and the first-run
    /// summary? The `digest` key, else true except for paging channels
    /// (PagerDuty, Alertmanager), where a weekly summary would page someone.
    pub fn wants_digest(&self) -> bool {
        let explicit = common!(self, c => c.digest);
        explicit.unwrap_or(!matches!(
            self,
            ChannelConfig::PagerDuty(_) | ChannelConfig::Alertmanager(_)
        ))
    }

    pub fn covers(&self, realm: &str) -> bool {
        let realms = self.realms();
        realms.is_empty() || realms.iter().any(|r| r == realm)
    }

    /// Type-specific checks; `key` is `channels[i]`.
    pub(crate) fn validate(&self, key: &str) -> anyhow::Result<()> {
        use anyhow::bail;
        match self {
            ChannelConfig::Teams(c) => check_env(&format!("{key}.webhook_env"), &c.webhook_env),
            ChannelConfig::Slack(c) | ChannelConfig::Discord(c) => {
                check_env(&format!("{key}.webhook_env"), &c.webhook_env)
            }
            ChannelConfig::Telegram(c) => {
                check_env(&format!("{key}.bot_token_env"), &c.bot_token_env)?;
                if c.chat_id.as_string().trim().is_empty() {
                    bail!("{key}.chat_id must not be empty");
                }
                if let Some(u) = &c.api_url {
                    check_url(&format!("{key}.api_url"), u)?;
                }
                Ok(())
            }
            ChannelConfig::PagerDuty(c) => {
                check_env(&format!("{key}.routing_key_env"), &c.routing_key_env)?;
                if let Some(u) = &c.url {
                    check_url(&format!("{key}.url"), u)?;
                }
                Ok(())
            }
            ChannelConfig::Alertmanager(c) => {
                check_url(&format!("{key}.url"), &c.url)?;
                check_opt_env(&format!("{key}.username_env"), &c.username_env)?;
                check_opt_env(&format!("{key}.password_env"), &c.password_env)?;
                check_opt_env(&format!("{key}.bearer_token_env"), &c.bearer_token_env)?;
                if c.username_env.is_some() != c.password_env.is_some() {
                    bail!("{key}.username_env and {key}.password_env must be set together");
                }
                if c.username_env.is_some() && c.bearer_token_env.is_some() {
                    bail!(
                        "{key}.bearer_token_env cannot be combined with username_env/password_env"
                    );
                }
                if c.expire_after_hours == 0 {
                    bail!("{key}.expire_after_hours must be greater than 0");
                }
                Ok(())
            }
            ChannelConfig::Webhook(c) => {
                check_env(&format!("{key}.url_env"), &c.url_env)?;
                check_opt_env(&format!("{key}.secret_env"), &c.secret_env)
            }
            ChannelConfig::Email(c) => {
                if c.host.trim().is_empty() {
                    bail!("{key}.host must not be empty");
                }
                check_opt_env(&format!("{key}.username_env"), &c.username_env)?;
                check_opt_env(&format!("{key}.password_env"), &c.password_env)?;
                if c.username_env.is_some() != c.password_env.is_some() {
                    bail!("{key}.username_env and {key}.password_env must be set together");
                }
                if c.security == SmtpSecurity::None && c.username_env.is_some() {
                    bail!(
                        "{key}.username_env: SMTP credentials need `security: starttls` or `tls`; \
                         `none` would send the password in clear text"
                    );
                }
                c.from.parse::<lettre::message::Mailbox>().map_err(|e| {
                    anyhow::anyhow!("{key}.from: invalid address `{}`: {e}", c.from)
                })?;
                if c.to.is_empty() {
                    bail!("{key}.to must list at least one address");
                }
                for (j, to) in c.to.iter().enumerate() {
                    to.parse::<lettre::message::Mailbox>().map_err(|e| {
                        anyhow::anyhow!("{key}.to[{j}]: invalid address `{to}`: {e}")
                    })?;
                }
                Ok(())
            }
        }
    }
}

/// Slack or Discord: an incoming webhook whose URL is the secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookChannel {
    pub name: String,
    /// Name of the environment variable holding the webhook URL.
    pub webhook_env: String,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

/// A Telegram chat id: a number (`-1001234567890`) or `@channelname`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ChatId {
    Number(i64),
    Name(String),
}

impl ChatId {
    pub fn as_string(&self) -> String {
        match self {
            ChatId::Number(n) => n.to_string(),
            ChatId::Name(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramChannel {
    pub name: String,
    /// Name of the environment variable holding the bot token.
    pub bot_token_env: String,
    pub chat_id: ChatId,
    /// Bot API base URL. Default `https://api.telegram.org`.
    pub api_url: Option<String>,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PagerDutyChannel {
    pub name: String,
    /// Name of the environment variable holding the Events API v2
    /// integration (routing) key.
    pub routing_key_env: String,
    /// Events API endpoint. Default `https://events.pagerduty.com/v2/enqueue`
    /// (`https://events.eu.pagerduty.com/v2/enqueue` for EU accounts).
    pub url: Option<String>,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertmanagerChannel {
    pub name: String,
    /// Base URL; alerts are POSTed to `{url}/api/v2/alerts`.
    pub url: String,
    /// Basic auth: names of the variables holding user and password.
    pub username_env: Option<String>,
    pub password_env: Option<String>,
    /// Bearer token: name of the variable holding it.
    pub bearer_token_env: Option<String>,
    /// `endsAt` is the delivery time plus this many hours: Heimdall sends
    /// each alert once, and Alertmanager expires it after that.
    #[serde(default = "default_expire_after_hours")]
    pub expire_after_hours: u32,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

fn default_expire_after_hours() -> u32 {
    24
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenericWebhookChannel {
    pub name: String,
    /// Name of the environment variable holding the URL to POST to.
    pub url_env: String,
    /// Name of the environment variable holding the HMAC-SHA256 secret.
    /// When set, every request carries `X-Heimdall-Signature: sha256=<hex>`.
    pub secret_env: Option<String>,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

/// How the SMTP connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    /// Plain connection upgraded with STARTTLS (required). Default port 587.
    Starttls,
    /// Implicit TLS from the first byte. Default port 465.
    Tls,
    /// No encryption. Default port 25. Only for a relay on a trusted network.
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmailChannel {
    pub name: String,
    pub host: String,
    /// Default by `security`: 587, 465 or 25.
    pub port: Option<u16>,
    #[serde(default = "default_smtp_security")]
    pub security: SmtpSecurity,
    /// Names of the variables holding the SMTP user and password.
    pub username_env: Option<String>,
    pub password_env: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
    /// Receive the weekly digest and the first-run summary. Default: true,
    /// except for paging channels (pagerduty, alertmanager).
    pub digest: Option<bool>,
}

impl EmailChannel {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.security {
            SmtpSecurity::Starttls => 587,
            SmtpSecurity::Tls => 465,
            SmtpSecurity::None => 25,
        })
    }
}

fn default_smtp_security() -> SmtpSecurity {
    SmtpSecurity::Starttls
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherTargets {
    #[serde(default)]
    pub github: Vec<GithubTarget>,
    #[serde(default)]
    pub endoflife: Vec<EolTarget>,
    #[serde(default)]
    pub tf_registry: Vec<TfTarget>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubTarget {
    pub repo: String,
    pub inventory_name: String,
    #[serde(default)]
    pub major_component: u8,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EolTarget {
    pub product: String,
    pub inventory_name: String,
    #[serde(default)]
    pub major_component: u8,
    pub cpe: Option<String>,
    /// GitHub repo used for release notes.
    pub repo: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TfKind {
    Provider,
    Module,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TfTarget {
    /// `registry.terraform.io` or `registry.opentofu.org`
    pub registry: String,
    pub kind: TfKind,
    pub source: String,
    pub current: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredComponent {
    pub realm: String,
    pub service: String,
    pub purl: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCred {
    pub host: String,
    /// Name of the environment variable holding the credential.
    pub secret_env: String,
}

/// Polling intervals in minutes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedules {
    #[serde(default = "default_sight")]
    pub sight_minutes: u32,
    #[serde(default = "default_osv")]
    pub osv_minutes: u32,
    #[serde(default = "default_k8s_cve")]
    pub k8s_cve_minutes: u32,
    #[serde(default = "default_watchers")]
    pub watchers_minutes: u32,
}

impl Default for Schedules {
    fn default() -> Self {
        Schedules {
            sight_minutes: default_sight(),
            osv_minutes: default_osv(),
            k8s_cve_minutes: default_k8s_cve(),
            watchers_minutes: default_watchers(),
        }
    }
}

fn default_sight() -> u32 {
    15
}
fn default_osv() -> u32 {
    15
}
fn default_k8s_cve() -> u32 {
    30
}
fn default_watchers() -> u32 {
    60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvdConfig {
    #[serde(default = "default_nvd_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_nvd_minutes")]
    pub minutes: u32,
}

impl Default for NvdConfig {
    fn default() -> Self {
        NvdConfig {
            api_key_env: default_nvd_key_env(),
            minutes: default_nvd_minutes(),
        }
    }
}

fn default_nvd_key_env() -> String {
    "NVD_API_KEY".to_string()
}
fn default_nvd_minutes() -> u32 {
    120
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    #[serde(default = "default_findings_days")]
    pub findings_days: u32,
    #[serde(default = "default_releases_days")]
    pub releases_days: u32,
    #[serde(default = "default_outbox_days")]
    pub outbox_days: u32,
    #[serde(default = "default_findings_days")]
    pub audit_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            findings_days: default_findings_days(),
            releases_days: default_releases_days(),
            outbox_days: default_outbox_days(),
            audit_days: default_findings_days(),
        }
    }
}

fn default_findings_days() -> u32 {
    365
}
fn default_releases_days() -> u32 {
    365
}
fn default_outbox_days() -> u32 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_security_config_defaults_and_validation() {
        let base = "realms: [prod]\nauth:\n  public_url: http://localhost\n  oidc:\n    issuer: https://example.com\n    client_id: client\n    client_secret_env: SECRET\n";
        let cfg = HeimdallConfig::from_yaml(base).unwrap();
        let oidc = cfg.auth.unwrap().oidc.unwrap();
        assert_eq!(oidc.effective_scopes(), ["openid", "profile", "email"]);
        assert_eq!(oidc.groups_max_age_minutes, 60);
        assert!(!oidc.admin_match_username);
        let cfg = HeimdallConfig::from_yaml(&format!("{base}    groups_claim: groups\n")).unwrap();
        assert_eq!(
            cfg.auth.unwrap().oidc.unwrap().effective_scopes(),
            ["openid", "profile", "email", "groups"]
        );
        let cfg = HeimdallConfig::from_yaml(&format!(
            "{base}    groups_claim: groups\n    scopes: [custom]\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.auth.unwrap().oidc.unwrap().effective_scopes(),
            ["openid", "custom"]
        );
        let cfg =
            HeimdallConfig::from_yaml(&format!("{base}    scopes: [openid, custom]\n")).unwrap();
        assert_eq!(
            cfg.auth.unwrap().oidc.unwrap().effective_scopes(),
            ["openid", "custom"]
        );
        assert!(
            HeimdallConfig::from_yaml(&format!("{base}    groups_max_age_minutes: 4\n")).is_err()
        );
        assert!(HeimdallConfig::from_yaml(&format!(
            "{base}    role_mappings: [{{group: x, role: admin, realms: [prod]}}]\n"
        ))
        .is_err());
        assert!(HeimdallConfig::from_yaml(
            "realms: [prod]\nauth: {public_url: http://localhost, trusted_proxies: [bad]}"
        )
        .is_err());
    }
    #[test]
    fn auth_config_validates() {
        let yaml = "realms: [prod]\nauth:\n  public_url: https://example.com\n  local: {enabled: true}\n  oidc:\n    issuer: https://example.com/issuer\n    client_id: heimdall\n    client_secret_env: SECRET\n    scopes: [openid, profile]\n    groups_claim: groups\n    role_mappings:\n      - {group: team, role: editor, realms: [prod]}\n    default_role: {role: viewer, realms: ['*']}\n";
        let cfg = HeimdallConfig::from_yaml(yaml).unwrap();
        assert_eq!(cfg.auth.unwrap().session.idle_hours, 12);
        assert!(HeimdallConfig::from_yaml(
            "realms: [prod]\nauth: {public_url: 'http://example.com'}"
        )
        .is_err());
        assert!(HeimdallConfig::from_yaml(
            "realms: [prod]\nauth: {public_url: 'http://localhost', session: {idle_hours: 0}}"
        )
        .is_err());
        assert!(HeimdallConfig::from_yaml("realms: [prod]\nauth: {public_url: 'https://example.com', local: {enabled: true, typo: true}}").is_err());
        assert!(
            HeimdallConfig::from_yaml(&yaml.replace("realms: [prod]}", "realms: [missing]}"))
                .is_err()
        );
    }

    #[test]
    fn example_config_parses_with_defaults() {
        let cfg = HeimdallConfig::load(Path::new("heimdall.example.yaml")).unwrap();
        assert_eq!(cfg.realms, vec!["dev-k3s"]);
        assert_eq!(cfg.digest.weekday, chrono::Weekday::Mon);
        assert_eq!(cfg.digest.hour, 9);
        assert_eq!(cfg.schedules.sight_minutes, 15);
        assert_eq!(cfg.schedules.watchers_minutes, 60);
        let k8s = cfg
            .watchers
            .github
            .iter()
            .find(|t| t.repo == "kubernetes/kubernetes")
            .unwrap();
        assert_eq!(k8s.major_component, 1);
        assert_eq!(cfg.sight_realm(), Some("dev-k3s"));
    }

    fn load_str(yaml: &str) -> anyhow::Result<HeimdallConfig> {
        HeimdallConfig::from_yaml(yaml)
    }

    fn err(yaml: &str) -> String {
        format!("{:#}", load_str(yaml).unwrap_err())
    }

    #[test]
    fn unknown_keys_are_rejected_and_named() {
        let e = err("realms: [a]\nwatchers:\n  github:\n    - { repo: x/y, inventory_name: y, major_componant: 1 }");
        assert!(e.contains("major_componant"), "{e}");
        let e = err("realms: [a]\nbogus: 1");
        assert!(e.contains("bogus"), "{e}");
        let e = err("realms: [a]\nteams:\n  - { name: t, webhook_env: E, min_severity: high, min_severity2: x }");
        assert!(e.contains("min_severity2"), "{e}");
    }

    #[test]
    fn semantic_validation_names_the_key() {
        assert!(err("realms: [a]\ndigest: { hour: 99 }").contains("digest.hour"));
        assert!(err("realms: [a]\nschedules: { osv_minutes: 0 }").contains("schedules.osv_minutes"));
        assert!(err("realms: [a]\nnvd: { minutes: 0 }").contains("nvd.minutes"));
        assert!(err("realms: [a]\nteams:\n  - { name: t, webhook_env: E, realms: [zz], min_severity: high }")
            .contains("teams[0].realms"));
        assert!(err(
            "realms: [a]\ndeclared:\n  - { realm: zz, service: s, purl: 'pkg:generic/x@1' }"
        )
        .contains("declared[0].realm"));
        assert!(err("realms: [a]\nsight: { realm: zz }").contains("sight.realm"));
        assert!(load_str("realms: [a]\ndigest: { hour: 23 }").is_ok());
    }

    const ALL_CHANNELS: &str = "realms: [prod, dev]\n\
teams:\n  - {name: legacy, webhook_env: TEAMS_URL, min_severity: high}\n\
channels:\n\
  - {type: teams, name: t2, webhook_env: T2, realms: [prod], min_severity: critical}\n\
  - {type: slack, name: s, webhook_env: SLACK_URL, min_severity: high}\n\
  - {type: discord, name: d, webhook_env: DISCORD_URL, min_severity: high}\n\
  - {type: telegram, name: tg, bot_token_env: TG_TOKEN, chat_id: -1001234567890, min_severity: high}\n\
  - {type: telegram, name: tg2, bot_token_env: TG_TOKEN, chat_id: '@ops', min_severity: high}\n\
  - {type: pagerduty, name: pd, routing_key_env: PD_KEY, min_severity: critical}\n\
  - {type: alertmanager, name: am, url: 'http://alertmanager:9093', bearer_token_env: AM_TOKEN, min_severity: high}\n\
  - {type: webhook, name: w, url_env: HOOK_URL, secret_env: HOOK_SECRET, realms: [dev], min_severity: low}\n\
  - {type: email, name: m, host: smtp.example.com, security: tls, username_env: U, password_env: P, \
     from: 'Heimdall <h@example.com>', to: [ops@example.com], min_severity: high}\n";

    #[test]
    fn every_channel_type_parses() {
        let cfg = load_str(ALL_CHANNELS).unwrap();
        let chans = cfg.channels();
        let types: Vec<&str> = chans.iter().map(|c| c.type_name()).collect();
        assert_eq!(
            types,
            [
                "teams",
                "teams",
                "slack",
                "discord",
                "telegram",
                "telegram",
                "pagerduty",
                "alertmanager",
                "webhook",
                "email"
            ]
        );
        assert_eq!(chans[0].name(), "legacy");
        assert!(chans[1].covers("prod") && !chans[1].covers("dev"));
        assert!(chans[2].covers("dev"));
        let ChannelConfig::Telegram(t) = &chans[4] else {
            panic!()
        };
        assert_eq!(t.chat_id.as_string(), "-1001234567890");
        let ChannelConfig::Alertmanager(a) = &chans[7] else {
            panic!()
        };
        assert_eq!(a.expire_after_hours, 24);
        let ChannelConfig::Email(m) = &chans[9] else {
            panic!()
        };
        assert_eq!(m.port(), 465);
    }

    #[test]
    fn digest_defaults_off_for_paging_channels() {
        let cfg = load_str(
            "realms: [a]\n\
             teams:\n  - {name: t, webhook_env: T, min_severity: high, digest: false}\n\
             channels:\n\
             \x20 - {type: slack, name: s, webhook_env: S, min_severity: high}\n\
             \x20 - {type: pagerduty, name: pd, routing_key_env: K, min_severity: high}\n\
             \x20 - {type: alertmanager, name: am, url: 'http://am', min_severity: high}\n\
             \x20 - {type: alertmanager, name: am2, url: 'http://am', min_severity: high, digest: true}\n",
        )
        .unwrap();
        let chans = cfg.channels();
        let wants: Vec<(&str, bool)> = chans.iter().map(|c| (c.name(), c.wants_digest())).collect();
        assert_eq!(
            wants,
            [
                ("t", false),
                ("s", true),
                ("pd", false),
                ("am", false),
                ("am2", true)
            ]
        );
    }

    #[test]
    fn smtp_credentials_need_tls() {
        let e = err("realms: [a]\nchannels:\n  - {type: email, name: m, host: h, security: none, \
                     username_env: U, password_env: P, from: a@b.c, to: [a@b.c], min_severity: high}");
        assert!(e.contains("channels[0].username_env"), "{e}");
        assert!(load_str(
            "realms: [a]\nchannels:\n  - {type: email, name: m, host: h, security: none, \
                          from: a@b.c, to: [a@b.c], min_severity: high}"
        )
        .is_ok());
    }

    #[test]
    fn example_channels_block_parses() {
        // The commented `channels:` example in heimdall.example.yaml.
        let text = std::fs::read_to_string("heimdall.example.yaml").unwrap();
        let block: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.starts_with("# channels:"))
            .take_while(|l| l.starts_with("# "))
            .map(|l| &l[2..])
            .collect();
        assert!(block.len() > 5, "example block not found");
        let cfg = load_str(&format!("realms: [dev-k3s]\n{}", block.join("\n"))).unwrap();
        assert_eq!(cfg.channels.len(), 6);
    }

    #[test]
    fn channel_keys_are_checked_per_type() {
        // A key of another type is unknown here.
        let e = err("realms: [a]\nchannels:\n  - {type: slack, name: s, webhook_env: X, chat_id: 1, min_severity: high}");
        assert!(e.contains("chat_id"), "{e}");
        let e = err("realms: [a]\nchannels:\n  - {type: sms, name: s, min_severity: high}");
        assert!(e.contains("sms"), "{e}");
        let e = err("realms: [a]\nchannels:\n  - {type: telegram, name: s, bot_token_env: X, min_severity: high}");
        assert!(e.contains("chat_id"), "{e}");
        // A secret inline instead of in an `*_env` key.
        let e = err("realms: [a]\nchannels:\n  - {type: slack, name: s, webhook: 'https://hooks.slack.com/x', min_severity: high}");
        assert!(e.contains("webhook"), "{e}");
    }

    #[test]
    fn channel_validation_names_the_key() {
        let cases = [
            (
                "teams:\n  - {name: ops, webhook_env: A, min_severity: high}\nchannels:\n  - {type: slack, name: ops, webhook_env: B, min_severity: high}",
                "channels[0].name: channel name `ops` is already used by teams[0]",
            ),
            (
                "channels:\n  - {type: slack, name: s, webhook_env: B, realms: [zz], min_severity: high}",
                "channels[0].realms",
            ),
            (
                "channels:\n  - {type: slack, name: '', webhook_env: B, min_severity: high}",
                "channels[0].name",
            ),
            (
                "channels:\n  - {type: slack, name: s, webhook_env: '', min_severity: high}",
                "channels[0].webhook_env",
            ),
            (
                "channels:\n  - {type: alertmanager, name: am, url: 'http://u:p@am:9093', min_severity: high}",
                "channels[0].url: URL must not contain credentials",
            ),
            (
                "channels:\n  - {type: alertmanager, name: am, url: 'not a url', min_severity: high}",
                "channels[0].url",
            ),
            (
                "channels:\n  - {type: alertmanager, name: am, url: 'http://am', username_env: U, min_severity: high}",
                "channels[0].username_env",
            ),
            (
                "channels:\n  - {type: alertmanager, name: am, url: 'http://am', username_env: U, password_env: P, bearer_token_env: T, min_severity: high}",
                "channels[0].bearer_token_env",
            ),
            (
                "channels:\n  - {type: email, name: m, host: h, from: 'not an address', to: [a@b.c], min_severity: high}",
                "channels[0].from",
            ),
            (
                "channels:\n  - {type: email, name: m, host: h, from: a@b.c, to: [], min_severity: high}",
                "channels[0].to",
            ),
            (
                "channels:\n  - {type: email, name: m, host: h, from: a@b.c, to: [a@b.c, nope], min_severity: high}",
                "channels[0].to[1]",
            ),
            (
                "channels:\n  - {type: pagerduty, name: p, routing_key_env: K, url: 'ftp://x', min_severity: high}",
                "channels[0].url",
            ),
        ];
        for (yaml, want) in cases {
            let e = err(&format!("realms: [a]\n{yaml}"));
            assert!(e.contains(want), "{want}: {e}");
        }
        let e = err("realms: [a]\nchannels:\n  - {type: email, name: m, host: h, from: a@b.c, to: [a@b.c], security: ssl, min_severity: high}");
        assert!(e.contains("ssl"), "{e}");
    }

    #[test]
    fn helm_default_config_passes() {
        let values = std::fs::read_to_string("deploy/helm/heimdall/values.yaml").unwrap();
        // Only the `config` block; the rest of values.yaml is Helm's.
        #[derive(serde::Deserialize)]
        struct Values {
            config: HeimdallConfig,
        }
        let v: Values = serde_saphyr::from_str(&values).unwrap();
        v.config.validate().unwrap();
    }

    #[test]
    fn sight_realm_can_be_set() {
        let cfg: HeimdallConfig =
            serde_saphyr::from_str("realms: [a, b]\nsight: { realm: b }").unwrap();
        assert_eq!(cfg.sight_realm(), Some("b"));
    }
}
