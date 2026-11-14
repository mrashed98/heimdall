use std::path::Path;

use anyhow::Context;
use chrono::Weekday;
use chrono_tz::Tz;
use serde::Deserialize;

use crate::model::Severity;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let known = |r: &str| self.realms.iter().any(|k| k == r);
        for (i, t) in self.teams.iter().enumerate() {
            for r in &t.realms {
                if !known(r) {
                    bail!("teams[{i}].realms: unknown realm `{r}` (not in `realms`)");
                }
            }
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

    /// The realm in-process Sight scans: `sight.realm`, else the first realm.
    pub fn sight_realm(&self) -> Option<&str> {
        self.sight
            .realm
            .as_deref()
            .or(self.realms.first().map(|r| r.as_str()))
    }
}

/// In-process Sight (`heimdall serve` scanning the cluster it runs in).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SightConfig {
    /// The realm of the cluster Heimdall runs in. Default: the first realm.
    pub realm: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
