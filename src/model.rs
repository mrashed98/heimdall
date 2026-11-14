//! Shared enums. Each is stored as lowercase `text` (with a CHECK in SQL).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    /// Higher is worse. Unknown sits between medium and low: it alerts like
    /// medium, but a real "low" is still ranked below it.
    fn rank(self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Unknown => 1,
            Severity::Low => 0,
        }
    }
}

// Hand-written (not derived) because derive would order by declaration order.
impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Git,
    Ci,
    Cluster,
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    Vuln,
    FixAvailable,
    MajorRelease,
    OathExpired,
    Eol,
    K8sCve,
    ReleaseNoteCve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MatchSource {
    Osv,
    Nvd,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OathKind {
    Snooze,
    Ignore,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_puts_unknown_above_low() {
        use Severity::*;
        let mut v = vec![Low, Unknown, Critical, Medium, High];
        v.sort();
        assert_eq!(v, vec![Low, Unknown, Medium, High, Critical]);
        assert!(Critical > High && High > Medium && Medium > Unknown && Unknown > Low);
    }

    #[test]
    fn severity_yaml_is_lowercase() {
        let s: Severity = serde_saphyr::from_str("high").unwrap();
        assert_eq!(s, Severity::High);
    }
}
