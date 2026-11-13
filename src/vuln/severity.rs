//! Turn the many severity shapes found in OSV records into one `Severity`.

use std::str::FromStr;

use cvss::Cvss;
use serde_json::Value;

use crate::model::Severity;

/// Order: CVSS score, then GHSA words, then Debian urgency / Ubuntu priority,
/// then Unknown.
pub fn normalize(osv_vuln: &Value) -> Severity {
    if let Some(score) = cvss_score(osv_vuln) {
        return from_score(score);
    }
    let words = osv_vuln
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
        .map(from_word);
    if let Some(s) = words.filter(|s| *s != Severity::Unknown) {
        return s;
    }
    distro_severity(osv_vuln)
}

/// Highest numeric CVSS base score among the v3/v4 vectors in `severity[]`.
/// Vectors the `cvss` crate cannot parse (v2, garbage) are skipped so the
/// caller falls through to the next source.
pub fn cvss_score(osv_vuln: &Value) -> Option<f64> {
    osv_vuln
        .get("severity")?
        .as_array()?
        .iter()
        .filter(|e| matches!(e["type"].as_str(), Some("CVSS_V3" | "CVSS_V4")))
        .filter_map(|e| Cvss::from_str(e["score"].as_str()?).ok())
        .map(|c| c.score())
        .reduce(f64::max)
}

pub fn merge(a: Severity, b: Severity) -> Severity {
    a.max(b)
}

fn from_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

/// GHSA words, Debian urgency and Ubuntu priority share one vocabulary.
fn from_word(word: &str) -> Severity {
    match word.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" | "negligible" | "unimportant" => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Debian puts `urgency` and Ubuntu `priority` in `affected[].ecosystem_specific`
/// (some records carry them in `database_specific`). Worst one wins.
fn distro_severity(osv_vuln: &Value) -> Severity {
    let mut places: Vec<&Value> = vec![&osv_vuln["database_specific"]];
    if let Some(affected) = osv_vuln["affected"].as_array() {
        places.extend(affected.iter().map(|a| &a["ecosystem_specific"]));
    }
    places
        .into_iter()
        .flat_map(|p| [p["urgency"].as_str(), p["priority"].as_str()])
        .flatten()
        .map(from_word)
        .fold(Severity::Unknown, |acc, s| {
            // Unknown must not beat a real Low, so only real words are merged.
            if s == Severity::Unknown {
                acc
            } else if acc == Severity::Unknown {
                s
            } else {
                merge(acc, s)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn severity_from_cvss_v3() {
        // The fixture also says database_specific CRITICAL; use a vector-only
        // record so the CVSS path is what is tested.
        let v = serde_json::json!({
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        });
        assert_eq!(normalize(&v), Severity::Critical);
        assert_eq!(cvss_score(&v), Some(9.8));
        let f = fixture(include_str!(
            "../../tests/fixtures/osv/GHSA-h7vf-3kq9-m2wx.json"
        ));
        assert_eq!(normalize(&f), Severity::Critical);
    }

    #[test]
    fn severity_from_ghsa_words() {
        let f = fixture(include_str!(
            "../../tests/fixtures/osv/GHSA-9c4p-j6rt-v5nz.json"
        ));
        assert_eq!(cvss_score(&f), None);
        assert_eq!(normalize(&f), Severity::Medium);
    }

    #[test]
    fn severity_from_debian_urgency() {
        let f = fixture(include_str!("../../tests/fixtures/osv/DSA-5678-1.json"));
        assert_eq!(normalize(&f), Severity::High);
    }

    #[test]
    fn unscorable_cvss_falls_through_and_unknown_is_default() {
        let v = serde_json::json!({
            "severity": [{"type": "CVSS_V3", "score": "garbage"}],
            "database_specific": {"severity": "LOW"}
        });
        assert_eq!(normalize(&v), Severity::Low);
        assert_eq!(normalize(&serde_json::json!({})), Severity::Unknown);
    }

    #[test]
    fn merge_takes_higher() {
        assert_eq!(
            merge(Severity::High, Severity::Critical),
            Severity::Critical
        );
        assert_eq!(merge(Severity::Low, Severity::Unknown), Severity::Unknown);
    }
}
