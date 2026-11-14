//! Teams formatter: Adaptive Cards (version 1.4) wrapped in the Workflows
//! webhook payload, rendered from the neutral [`Alert`].

use serde_json::{json, Value};

use super::alert::{clip, Alert, AlertKind, Fact, Link};
use super::AlertGroup;
use crate::model::Severity;

/// Items shown on one card; the rest are counted ("and N more"). Teams
/// rejects payloads over about 28 KB.
pub(crate) const MAX_ROWS: usize = 25;
/// Serialized card size above which rows are cut further (Teams rejects
/// payloads over about 28 KB, and a rejected card is lost).
pub(crate) const MAX_CARD_BYTES: usize = 24_000;

/// The Workflows payload for any alert.
pub fn render(a: &Alert) -> Value {
    match a.kind {
        AlertKind::Finding(_) => finding_card(a),
        AlertKind::FirstRun => first_run_card(a),
        AlertKind::Digest => digest_card(a),
    }
}

/// The Workflows payload for one alert group. Shows up to 25 items; when the
/// card is still too big, fewer.
pub fn card(group: &AlertGroup) -> Value {
    render(&Alert::from_group(group))
}

/// The "Heimdall has opened his eyes" card: open findings by severity.
pub fn summary_card(realm: &str, counts: &[(Severity, i64)]) -> Value {
    render(&Alert::first_run(realm, counts))
}

fn finding_card(a: &Alert) -> Value {
    let mut card = Value::Null;
    for cap in [MAX_ROWS, 10, 5, 1] {
        card = finding_card_with(a, cap);
        if card.to_string().len() <= MAX_CARD_BYTES {
            break;
        }
    }
    card
}

/// The card showing at most `cap` items.
fn finding_card_with(a: &Alert, cap: usize) -> Value {
    let mut body = vec![title_block(&clip(&a.title), a.worst())];
    if let Some(s) = &a.summary {
        body.push(text_block(&clip(s), true));
    }
    if let Some(s) = &a.scores {
        body.push(text_block(s, true));
    }
    for e in a.entries.iter().take(cap) {
        body.push(json!({
            "type": "Container",
            "separator": true,
            "items": [
                {"type": "TextBlock", "text": clip(&e.heading()), "weight": "Bolder", "wrap": true},
                {"type": "FactSet", "facts": facts(&e.facts)},
            ],
        }));
    }
    if a.entries.len() > cap {
        body.push(text_block(
            &format!("and {} more", a.entries.len() - cap),
            true,
        ));
    }
    for s in &a.sections {
        let lines: Vec<String> = s.lines.iter().map(|l| format!("- {}", clip(l))).collect();
        if !lines.is_empty() {
            body.push(text_block(&format!("{}:", s.title), false));
            body.push(text_block(&lines.join("\n"), false));
        }
    }
    message(body, links(&a.links))
}

fn first_run_card(a: &Alert) -> Value {
    let note = |i: usize| a.notes.get(i).map(String::as_str).unwrap_or_default();
    let body = vec![
        title_block(&a.title, Severity::Unknown),
        text_block(note(0), false),
        json!({"type": "FactSet", "facts": facts(&a.facts)}),
        text_block(note(1), true),
    ];
    message(body, Vec::new())
}

/// The digest card, each section capped; rows are cut further if the card
/// is still too big for Teams.
fn digest_card(a: &Alert) -> Value {
    let mut card = Value::Null;
    for cap in [MAX_ROWS, 10, 5] {
        let mut body = vec![title_block(&a.title, Severity::Unknown)];
        for s in &a.sections {
            body.push(json!({"type": "TextBlock", "text": s.title,
                             "weight": "Bolder", "wrap": true, "spacing": "Medium"}));
            let mut lines: Vec<String> =
                s.lines.iter().take(cap).map(|r| format!("- {r}")).collect();
            if s.lines.len() > cap {
                lines.push(format!("- and {} more", s.lines.len() - cap));
            }
            body.push(text_block(&lines.join("\n"), false));
        }
        for n in &a.notes {
            body.push(text_block(n, true));
        }
        card = message(body, Vec::new());
        if card.to_string().len() <= MAX_CARD_BYTES {
            break;
        }
    }
    card
}

/// Wrap card body and actions in the Workflows webhook payload.
fn message(body: Vec<Value>, actions: Vec<Value>) -> Value {
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

fn title_block(text: &str, severity: Severity) -> Value {
    let color = match severity {
        Severity::Critical | Severity::High => "Attention",
        Severity::Medium => "Warning",
        _ => "Default",
    };
    json!({"type": "TextBlock", "text": text, "size": "Large", "weight": "Bolder",
           "color": color, "wrap": true})
}

fn text_block(text: &str, subtle: bool) -> Value {
    json!({"type": "TextBlock", "text": text, "wrap": true, "isSubtle": subtle})
}

fn facts(facts: &[Fact]) -> Vec<Value> {
    facts
        .iter()
        .map(|f| json!({"title": f.title, "value": clip(&f.value)}))
        .collect()
}

/// Buttons: the advisory, the release notes, the Kubernetes issue.
fn links(links: &[Link]) -> Vec<Value> {
    links
        .iter()
        .map(|l| json!({"type": "Action.OpenUrl", "title": l.title, "url": l.url}))
        .collect()
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

    #[test]
    fn huge_groups_stay_under_the_size_limit() {
        let long = format!("pkg:npm/{}@1.0.0", "x".repeat(2000));
        let items: Vec<AlertItem> = (0..500)
            .map(|i| {
                vuln_item(
                    &format!("service-{i:03}-{}", "s".repeat(200)),
                    &long,
                    false,
                    "nvd",
                )
            })
            .collect();
        let c = card(&group(FindingKind::Vuln, "GHSA-x", items));
        assert!(c.to_string().len() < 24_000, "{}", c.to_string().len());

        let services: Vec<String> = (0..500).map(|i| format!("svc{i:03}")).collect();
        let mut g = group(
            FindingKind::ReleaseNoteCve,
            "GHSA-abc",
            vec![item(
                1,
                FindingKind::ReleaseNoteCve,
                "",
                json!({"target": "pkg:npm/lib", "version": "1.2.3", "id": "CVE-2026-7",
                       "ids": vec!["CVE-2026-7"; 500], "advisory": "GHSA-abc",
                       "services": services}),
            )],
        );
        g.items[0].service = None;
        let c = card(&g);
        assert!(c.to_string().len() < 24_000, "{}", c.to_string().len());
        assert_eq!(
            c["attachments"][0]["content"]["body"][0]["text"],
            "pkg:npm/lib 1.2.3 release notes mention CVE-2026-7 (affects svc000, svc001, svc002 and 497 more)"
        );
    }
}
