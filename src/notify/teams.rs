//! Teams Adaptive Cards (version 1.4) wrapped in the Workflows webhook
//! payload. Every card Gjallarhorn sends is built here.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::AlertGroup;
use crate::model::{FindingKind, Severity};

/// Items shown on one card; the rest are counted ("and N more"). Teams
/// rejects payloads over about 28 KB.
pub(crate) const MAX_ROWS: usize = 25;
/// Breaking-change lines quoted on a major release card.
const MAX_BREAKING: usize = 5;
/// Longest advisory summary or quoted line, in characters.
const MAX_TEXT: usize = 300;

/// The Workflows payload for one alert group.
pub fn card(group: &AlertGroup) -> Value {
    let mut body = vec![title_block(&title(group), group.worst())];
    if let Some(a) = &group.advisory {
        if !a.summary.is_empty() {
            body.push(text_block(&clip(&a.summary), true));
        }
    }
    if let Some(s) = scores(group) {
        body.push(text_block(&s, true));
    }
    for item in group.items.iter().take(MAX_ROWS) {
        let heading = match &item.service {
            Some(s) if !s.is_empty() => format!("{} / {s}", item.realm),
            _ => item.realm.clone(),
        };
        body.push(json!({
            "type": "Container",
            "separator": true,
            "items": [
                {"type": "TextBlock", "text": heading, "weight": "Bolder", "wrap": true},
                {"type": "FactSet", "facts": facts(item.kind, &item.details)},
            ],
        }));
    }
    if group.items.len() > MAX_ROWS {
        body.push(text_block(
            &format!("and {} more", group.items.len() - MAX_ROWS),
            true,
        ));
    }
    if let Some(r) = &group.release {
        let lines: Vec<String> = r
            .breaking
            .iter()
            .take(MAX_BREAKING)
            .map(|l| format!("- {}", clip(l)))
            .collect();
        if !lines.is_empty() {
            body.push(text_block("Breaking changes:", false));
            body.push(text_block(&lines.join("\n"), false));
        }
    }
    message(body, links(group))
}

/// The "Heimdall has opened his eyes" card: open findings by severity.
pub fn summary_card(realm: &str, counts: &[(Severity, i64)]) -> Value {
    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ];
    let facts: Vec<Value> = order
        .iter()
        .map(|sev| {
            let n = counts
                .iter()
                .find(|(s, _)| s == sev)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            fact(&capitalized(*sev), &n.to_string())
        })
        .collect();
    let body = vec![
        title_block("Heimdall has opened his eyes", Severity::Unknown),
        text_block(
            &format!("Realm {realm} is now watched. Open findings by severity:"),
            false,
        ),
        json!({"type": "FactSet", "facts": facts}),
        text_block(
            "Critical and high findings follow as separate cards; the rest come in the weekly digest.",
            true,
        ),
    ];
    message(body, Vec::new())
}

/// Wrap card body and actions in the Workflows webhook payload.
pub(crate) fn message(body: Vec<Value>, actions: Vec<Value>) -> Value {
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "msteams": {"width": "Full"},
                "body": body,
                "actions": actions,
            },
        }],
    })
}

pub(crate) fn title_block(text: &str, severity: Severity) -> Value {
    let color = match severity {
        Severity::Critical | Severity::High => "Attention",
        Severity::Medium => "Warning",
        _ => "Default",
    };
    json!({"type": "TextBlock", "text": text, "size": "Large", "weight": "Bolder",
           "color": color, "wrap": true})
}

pub(crate) fn text_block(text: &str, subtle: bool) -> Value {
    json!({"type": "TextBlock", "text": text, "wrap": true, "isSubtle": subtle})
}

pub(crate) fn link(title: &str, url: &str) -> Value {
    json!({"type": "Action.OpenUrl", "title": title, "url": url})
}

fn fact(title: &str, value: &str) -> Value {
    json!({"title": title, "value": value})
}

/// Cut long text so one card stays well under the Teams size limit.
pub(crate) fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_TEXT {
        return s.to_string();
    }
    let cut: String = s.chars().take(MAX_TEXT).collect();
    format!("{cut}…")
}

/// "critical", "high", ... as stored.
pub(crate) fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

fn capitalized(s: Severity) -> String {
    let name = severity_name(s);
    name[..1].to_uppercase() + &name[1..]
}

/// The package name in a purl: `github.com/gin-gonic/gin` for
/// `pkg:golang/github.com/gin-gonic/gin@v1.9.0`, `postgresql` for
/// `pkg:generic/postgresql@17.2`. Falls back to the purl itself.
pub(crate) fn package_name(purl: &str) -> String {
    use std::str::FromStr;
    match packageurl::PackageUrl::from_str(purl) {
        Ok(p) => match p.namespace() {
            Some(ns) => format!("{ns}/{}", p.name()),
            None => p.name().to_string(),
        },
        Err(_) => purl.to_string(),
    }
}

/// Where to read about an advisory: NVD for a bare CVE id, OSV otherwise
/// (GHSA, GO, OSV ids and the like).
pub(crate) fn advisory_url(id: &str) -> String {
    if id.starts_with("CVE-") {
        format!("https://nvd.nist.gov/vuln/detail/{id}")
    } else {
        format!("https://osv.dev/vulnerability/{id}")
    }
}

/// "upgrade to 2.4.1 (latest 3.0.0)", or "upgrade to 2.4.1" when that is the latest.
fn advice_text(advice: &Value) -> Option<String> {
    let suggest = advice["suggest"].as_str()?;
    match advice["latest"].as_str() {
        Some(latest) if latest != suggest => {
            Some(format!("upgrade to {suggest} (latest {latest})"))
        }
        _ => Some(format!("upgrade to {suggest}")),
    }
}

fn str_of<'a>(d: &'a Value, field: &str) -> &'a str {
    d[field].as_str().unwrap_or_default()
}

/// Services named by the group's items (or by a release-note CVE's details).
fn services(group: &AlertGroup) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for item in &group.items {
        match &item.service {
            Some(s) if !s.is_empty() => {
                out.insert(s.clone());
            }
            _ => {}
        }
        // An OathExpired finding names its service in details.
        if let Some(s) = item.details["service"].as_str() {
            out.insert(s.to_string());
        }
        if let Some(list) = item.details["services"].as_array() {
            out.extend(list.iter().filter_map(|s| s.as_str().map(str::to_string)));
        }
    }
    out.into_iter().collect()
}

fn title(g: &AlertGroup) -> String {
    let first = g.items.first().map(|i| &i.details).unwrap_or(&Value::Null);
    match g.kind {
        FindingKind::Vuln => {
            let affected: BTreeSet<(&str, Option<&str>)> = g
                .items
                .iter()
                .map(|i| (i.realm.as_str(), i.service.as_deref()))
                .collect();
            format!(
                "⚠ {} ({}) affects {} service(s)",
                g.ref_id,
                severity_name(g.worst()),
                affected.len()
            )
        }
        FindingKind::FixAvailable => format!(
            "Fix available: upgrade {} {} → {} fixes {}",
            package_name(str_of(first, "purl")),
            str_of(first, "version"),
            first["advice"]["suggest"].as_str().unwrap_or("?"),
            g.ref_id
        ),
        FindingKind::MajorRelease => format!(
            "{} {} released (major)",
            str_of(first, "target"),
            str_of(first, "version")
        ),
        FindingKind::OathExpired => {
            format!("Oath expired: {} on {}", g.ref_id, services(g).join(", "))
        }
        FindingKind::Eol => format!(
            "{} {} reaches end of support on {}",
            str_of(first, "target"),
            str_of(first, "cycle"),
            str_of(first, "eol")
        ),
        FindingKind::K8sCve => format!("Kubernetes security advisory {}", g.ref_id),
        FindingKind::ReleaseNoteCve => format!(
            "{} {} release notes mention {} (affects {})",
            str_of(first, "target"),
            str_of(first, "version"),
            first["id"].as_str().unwrap_or(&g.ref_id),
            services(g).join(", ")
        ),
    }
}

/// "OSV 7.5 · NVD 9.8", or the one score known.
fn scores(g: &AlertGroup) -> Option<String> {
    let from_advisory = g.advisory.as_ref().map(|a| &a.scores);
    let from_item = g.items.first().map(|i| &i.details["scores"]);
    let s = from_advisory
        .filter(|s| s.as_object().is_some_and(|o| !o.is_empty()))
        .or(from_item)?;
    let parts: Vec<String> = [("osv", "OSV"), ("nvd", "NVD")]
        .iter()
        .filter_map(|(k, label)| s[*k].as_f64().map(|v| format!("{label} {v}")))
        .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// The facts about one finding, by its kind.
fn facts(kind: FindingKind, d: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    match kind {
        FindingKind::Vuln | FindingKind::FixAvailable => {
            out.push(fact("Component", str_of(d, "purl")));
            out.push(fact("Version", str_of(d, "version")));
            let fix = advice_text(&d["advice"]).unwrap_or_else(|| "no fixed version yet".into());
            out.push(fact("Fix", &fix));
            let notes = labels(d);
            if !notes.is_empty() {
                out.push(fact("Note", &notes.join(" · ")));
            }
        }
        FindingKind::OathExpired => {
            out.push(fact("Component", str_of(d, "name_key")));
            out.push(fact("Oath", str_of(d, "kind")));
            out.push(fact("Reason", &clip(str_of(d, "reason"))));
            out.push(fact("Sworn on version", str_of(d, "version_at_creation")));
        }
        FindingKind::MajorRelease => {
            out.push(fact("Running", str_of(d, "current")));
            out.push(fact("New major", str_of(d, "version")));
        }
        FindingKind::Eol => {
            out.push(fact("Running", str_of(d, "version")));
            out.push(fact("End of support", str_of(d, "eol")));
            out.push(fact("Latest in cycle", str_of(d, "latest")));
        }
        FindingKind::K8sCve => {
            out.push(fact("Summary", &clip(str_of(d, "summary"))));
        }
        FindingKind::ReleaseNoteCve => {
            let ids: Vec<&str> = d["ids"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            out.push(fact("Mentioned", &ids.join(", ")));
            out.push(fact("Advisory", str_of(d, "advisory")));
        }
    }
    out
}

/// "indirect dependency" and "NVD match only, verify" where they apply.
/// The NVD label is for libraries only: infra (generic, oci) is matched by
/// CPE on purpose.
fn labels(d: &Value) -> Vec<&'static str> {
    let mut out = Vec::new();
    if d["direct"] == Value::Bool(false) {
        out.push("indirect dependency");
    }
    let purl_type = str_of(d, "purl")
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    if d["match_source"] == "nvd" && !matches!(purl_type, "generic" | "oci" | "") {
        out.push("NVD match only, verify");
    }
    out
}

/// Buttons: the advisory, the release notes, the Kubernetes issue.
fn links(g: &AlertGroup) -> Vec<Value> {
    let mut out = Vec::new();
    let first = g.items.first().map(|i| &i.details).unwrap_or(&Value::Null);
    match g.kind {
        FindingKind::Vuln
        | FindingKind::FixAvailable
        | FindingKind::OathExpired
        | FindingKind::ReleaseNoteCve
        | FindingKind::K8sCve => {
            out.push(link(
                &format!("Open {}", g.ref_id),
                &advisory_url(&g.ref_id),
            ));
        }
        FindingKind::MajorRelease | FindingKind::Eol => {}
    }
    let notes = g
        .release
        .as_ref()
        .and_then(|r| r.notes_url.clone())
        .or_else(|| first["notes_url"].as_str().map(str::to_string));
    if let Some(url) = notes {
        out.push(link("Release notes", &url));
    }
    if g.kind == FindingKind::K8sCve {
        if let Some(url) = first["url"].as_str().filter(|u| !u.is_empty()) {
            out.push(link("Tracking issue", url));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::model::{FindingKind, Severity};
    use crate::notify::{AdvisoryInfo, AlertItem, ReleaseInfo};

    fn item(id: i64, kind: FindingKind, service: &str, details: Value) -> AlertItem {
        AlertItem {
            finding_id: id,
            kind,
            realm: "prod".to_string(),
            service: Some(service.to_string()),
            severity: Severity::High,
            details,
        }
    }

    fn group(kind: FindingKind, ref_id: &str, items: Vec<AlertItem>) -> AlertGroup {
        AlertGroup {
            kind,
            ref_id: ref_id.to_string(),
            items,
            absorbed: vec![],
            advisory: None,
            release: None,
        }
    }

    fn vuln_item(service: &str, purl: &str, direct: bool, source: &str) -> AlertItem {
        item(
            1,
            FindingKind::Vuln,
            service,
            json!({
                "purl": purl,
                "version": "v1.9.0",
                "fixed": ["v1.9.1"],
                "advice": {"suggest": "v1.9.1", "latest": "v1.10.0"},
                "oath": null,
                "direct": direct,
                "match_source": source,
                "scores": {"osv": 7.5, "nvd": 9.8},
            }),
        )
    }

    /// The snapshot group: one advisory in two services, one of them indirect.
    fn fixture_group() -> AlertGroup {
        let mut g = group(
            FindingKind::Vuln,
            "GHSA-gin-0001",
            vec![
                vuln_item(
                    "api",
                    "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
                    true,
                    "osv",
                ),
                vuln_item(
                    "worker",
                    "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
                    false,
                    "both",
                ),
            ],
        );
        g.advisory = Some(AdvisoryInfo {
            summary: "gin mishandles header parsing".to_string(),
            scores: json!({"osv": 7.5, "nvd": 9.8}),
        });
        g
    }

    fn text(v: &Value) -> String {
        v.to_string()
    }

    #[test]
    fn card_snapshot() {
        let got = card(&fixture_group());
        let path = "tests/fixtures/teams/vuln_card.json";
        if std::env::var("HEIMDALL_UPDATE_SNAPSHOTS").is_ok() {
            std::fs::write(path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        }
        let want: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn card_is_a_workflows_message() {
        let c = card(&fixture_group());
        assert_eq!(c["type"], "message");
        let a = &c["attachments"][0];
        assert_eq!(a["contentType"], "application/vnd.microsoft.card.adaptive");
        assert_eq!(a["content"]["type"], "AdaptiveCard");
        assert_eq!(a["content"]["version"], "1.4");
    }

    #[test]
    fn card_labels_indirect() {
        let t = text(&card(&fixture_group()));
        assert!(t.contains("indirect dependency"), "{t}");
        let direct_only = group(
            FindingKind::Vuln,
            "GHSA-x",
            vec![vuln_item("api", "pkg:npm/a@1.0.0", true, "osv")],
        );
        assert!(!text(&card(&direct_only)).contains("indirect dependency"));
    }

    #[test]
    fn card_labels_nvd_only() {
        let lib = group(
            FindingKind::Vuln,
            "CVE-2026-1",
            vec![vuln_item("api", "pkg:npm/a@1.0.0", true, "nvd")],
        );
        assert!(text(&card(&lib)).contains("NVD match only, verify"));
        let infra = group(
            FindingKind::Vuln,
            "CVE-2026-1",
            vec![vuln_item("db", "pkg:generic/postgresql@17.2", true, "nvd")],
        );
        assert!(!text(&card(&infra)).contains("NVD match only"));
        let both = group(
            FindingKind::Vuln,
            "CVE-2026-1",
            vec![vuln_item("api", "pkg:npm/a@1.0.0", true, "both")],
        );
        assert!(!text(&card(&both)).contains("NVD match only"));
    }

    #[test]
    fn card_shows_both_scores() {
        assert!(text(&card(&fixture_group())).contains("OSV 7.5 · NVD 9.8"));
    }

    #[test]
    fn card_links_osv_or_nvd() {
        assert!(
            text(&card(&fixture_group())).contains("https://osv.dev/vulnerability/GHSA-gin-0001")
        );
        let cve = group(
            FindingKind::Vuln,
            "CVE-2026-1",
            vec![vuln_item("api", "pkg:npm/a@1.0.0", true, "nvd")],
        );
        assert!(text(&card(&cve)).contains("https://nvd.nist.gov/vuln/detail/CVE-2026-1"));
    }

    #[test]
    fn fix_card_shows_advice() {
        let g = group(
            FindingKind::FixAvailable,
            "GHSA-foo",
            vec![item(
                1,
                FindingKind::FixAvailable,
                "api",
                json!({"purl": "pkg:npm/foo@2.4.0", "version": "2.4.0",
                       "advice": {"suggest": "2.4.1", "latest": "3.0.0"},
                       "direct": false, "advisory": "GHSA-foo"}),
            )],
        );
        let c = card(&g);
        assert_eq!(
            c["attachments"][0]["content"]["body"][0]["text"],
            "Fix available: upgrade foo 2.4.0 → 2.4.1 fixes GHSA-foo"
        );
        let t = text(&c);
        assert!(t.contains("upgrade to 2.4.1 (latest 3.0.0)"), "{t}");
        assert!(t.contains("indirect dependency"), "{t}");
    }

    #[test]
    fn major_card_quotes_breaking_lines() {
        let mut g = group(
            FindingKind::MajorRelease,
            "17.0",
            vec![item(
                1,
                FindingKind::MajorRelease,
                "",
                json!({"target": "postgres", "version": "17.0", "current": "16.4", "line": "17"}),
            )],
        );
        g.items[0].service = None;
        g.release = Some(ReleaseInfo {
            notes_url: Some("https://example.com/notes/17.0".to_string()),
            breaking: (1..=7).map(|i| format!("breaking change {i}")).collect(),
        });
        let c = card(&g);
        assert_eq!(
            c["attachments"][0]["content"]["body"][0]["text"],
            "postgres 17.0 released (major)"
        );
        let t = text(&c);
        for i in 1..=5 {
            assert!(t.contains(&format!("breaking change {i}")), "{t}");
        }
        assert!(!t.contains("breaking change 6"), "{t}");
        assert!(t.contains("https://example.com/notes/17.0"), "{t}");
    }

    #[test]
    fn release_note_cve_card() {
        let mut g = group(
            FindingKind::ReleaseNoteCve,
            "GHSA-abc",
            vec![item(
                1,
                FindingKind::ReleaseNoteCve,
                "",
                json!({"target": "pkg:npm/lib", "version": "1.2.3", "id": "CVE-2026-7",
                       "ids": ["CVE-2026-7"], "advisory": "GHSA-abc",
                       "services": ["api", "web"], "notes_url": "https://example.com/n"}),
            )],
        );
        g.items[0].service = None;
        let c = card(&g);
        assert_eq!(
            c["attachments"][0]["content"]["body"][0]["text"],
            "pkg:npm/lib 1.2.3 release notes mention CVE-2026-7 (affects api, web)"
        );
        assert!(text(&c).contains("https://example.com/n"));
    }

    #[test]
    fn long_groups_are_capped() {
        let items: Vec<AlertItem> = (0..40)
            .map(|i| vuln_item(&format!("svc{i:02}"), "pkg:npm/a@1.0.0", true, "osv"))
            .collect();
        let t = text(&card(&group(FindingKind::Vuln, "GHSA-x", items)));
        assert!(t.contains("svc24"));
        assert!(!t.contains("svc25"));
        assert!(t.contains("and 15 more"), "{t}");
    }
}
