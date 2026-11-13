use std::path::Path;

use anyhow::Context;
use chrono::Weekday;
use chrono_tz::Tz;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeimdallConfig {
    pub realms: Vec<String>,
    #[serde(default)]
    pub digest: DigestConfig,
    #[serde(default)]
    pub teams: Vec<TeamsRoute>,
    #[serde(default)]
    pub watchers: WatcherTargets,
    #[serde(default)]
    pub declared: Vec<DeclaredComponent>,
    #[serde(default)]
    pub registries: Vec<RegistryCred>,
    #[serde(default)]
    pub schedules: Schedules,
    /// Registry hosts or host/org prefixes (e.g. `ghcr.io/yourorg`) whose
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
}

impl HeimdallConfig {
    pub fn load(path: &Path) -> anyhow::Result<HeimdallConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        serde_yaml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct TeamsRoute {
    pub name: String,
    /// Name of the environment variable holding the webhook URL.
    pub webhook_env: String,
    /// Empty means all realms.
    #[serde(default)]
    pub realms: Vec<String>,
    pub min_severity: Severity,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WatcherTargets {
    #[serde(default)]
    pub github: Vec<GithubTarget>,
    #[serde(default)]
    pub endoflife: Vec<EolTarget>,
    #[serde(default)]
    pub tf_registry: Vec<TfTarget>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubTarget {
    pub repo: String,
    pub inventory_name: String,
    #[serde(default)]
    pub major_component: u8,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
pub struct TfTarget {
    /// `registry.terraform.io` or `registry.opentofu.org`
    pub registry: String,
    pub kind: TfKind,
    pub source: String,
    pub current: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredComponent {
    pub realm: String,
    pub service: String,
    pub purl: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryCred {
    pub host: String,
    /// Name of the environment variable holding the credential.
    pub secret_env: String,
}

/// Polling intervals in minutes.
#[derive(Debug, Clone, Deserialize)]
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
pub struct Retention {
    #[serde(default = "default_findings_days")]
    pub findings_days: u32,
    #[serde(default = "default_releases_days")]
    pub releases_days: u32,
    #[serde(default = "default_outbox_days")]
    pub outbox_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            findings_days: default_findings_days(),
            releases_days: default_releases_days(),
            outbox_days: default_outbox_days(),
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
    }
}
