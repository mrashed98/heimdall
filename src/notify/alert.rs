//! The neutral alert model: what one notification says, independent of
//! where it goes. Every channel formatter (`teams`, `channels::*`) renders
//! an [`Alert`]; this file builds them from alert groups, the first-run
//! summary and the weekly digest.

use std::collections::BTreeSet;

use serde::{Serialize, Serializer};
use serde_json::Value;

use super::AlertGroup;
use crate::model::{FindingKind, Severity};

/// Breaking-change lines quoted on a major release alert.
pub(crate) const MAX_BREAKING: usize = 5;
/// Longest advisory summary, fact or quoted line, in characters.
pub(crate) const MAX_TEXT: usize = 300;
/// Services named in a title before "and N more".
const TITLE_SERVICES: usize = 3;

/// What an alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// Findings of one kind about one advisory or release.
    Finding(FindingKind),
    /// "Heimdall has opened his eyes": a realm's open findings, once.
    FirstRun,
    /// The weekly digest.
    Digest,
}

impl AlertKind {
    /// `Vuln`, `FixAvailable`, ..., `FirstRun`, `Digest`: the Alertmanager
    /// `alertname` is `Heimdall` followed by this.
    pub fn name(self) -> &'static str {
        match self {
            AlertKind::Finding(k) => match k {
                FindingKind::Vuln => "Vuln",
                FindingKind::FixAvailable => "FixAvailable",
                FindingKind::MajorRelease => "MajorRelease",
                FindingKind::OathExpired => "OathExpired",
                FindingKind::Eol => "Eol",
                FindingKind::K8sCve => "K8sCve",
                FindingKind::ReleaseNoteCve => "ReleaseNoteCve",
            },
            AlertKind::FirstRun => "FirstRun",
            AlertKind::Digest => "Digest",
        }
    }

    /// The lowercase form (`vuln`, `fixavailable`, `firstrun`, `digest`), as
    /// findings store their kind.
    pub fn label(self) -> String {
        self.name().to_lowercase()
    }
}

impl Serialize for AlertKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fact {
    pub title: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Link {
    pub title: String,
    pub url: String,
}

/// A titled list of lines (breaking changes, a digest section).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Section {
    pub title: String,
    pub lines: Vec<Line>,
}

/// One line of a section: an optional link Heimdall made itself (a release's
/// notes), then text. The text may come from upstream (release notes, oath
/// reasons): formatters always render it as plain, escaped text, so a
/// Markdown link in it never becomes clickable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Line {
    pub link: Option<Link>,
    pub text: String,
}

impl Line {
    pub fn plain(text: impl Into<String>) -> Line {
        Line {
            link: None,
            text: text.into(),
        }
    }

    /// The line as plain text, the link written as `title <url>`.
    pub fn to_plain(&self) -> String {
        match &self.link {
            Some(l) => format!("{} <{}>{}", l.title, l.url, self.text),
            None => self.text.clone(),
        }
    }
}

/// One finding on an alert.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub finding_id: i64,
    pub realm: String,
    pub service: Option<String>,
    /// The finding's own severity.
    pub severity: Severity,
    pub facts: Vec<Fact>,
}

impl Entry {
    /// "prod / api", or "prod" without a service.
    pub fn heading(&self) -> String {
        match &self.service {
            Some(s) if !s.is_empty() => format!("{} / {s}", self.realm),
            _ => self.realm.clone(),
        }
    }
}

/// One notification, before any channel formats it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    /// Stable identity: the outbox group key (`alert|vuln|GHSA-…`,
    /// `first_run|prod`, `digest|2026-11-16`). PagerDuty dedups on it.
    pub key: String,
    pub kind: AlertKind,
    pub title: String,
    /// The severity routes compare against (`AlertGroup::routing_severity`);
    /// `unknown` for the summary and the digest.
    pub severity: Severity,
    /// The realm of a first-run summary; None otherwise (entries carry theirs).
    pub realm: Option<String>,
    /// The advisory id, for advisory kinds.
    pub advisory: Option<String>,
    pub summary: Option<String>,
    /// "OSV 7.5 · NVD 9.8".
    pub scores: Option<String>,
    /// Plain paragraphs (the first-run summary's text).
    pub notes: Vec<String>,
    /// Alert-level facts (the first-run counts by severity).
    pub facts: Vec<Fact>,
    pub entries: Vec<Entry>,
    pub sections: Vec<Section>,
    pub links: Vec<Link>,
}

impl Alert {
    fn new(key: String, kind: AlertKind, title: String, severity: Severity) -> Alert {
        Alert {
            key,
            kind,
            title,
            severity,
            realm: None,
            advisory: None,
            summary: None,
            scores: None,
            notes: Vec::new(),
            facts: Vec::new(),
            entries: Vec::new(),
            sections: Vec::new(),
            links: Vec::new(),
        }
    }

    /// The worst severity among the entries (`unknown` without entries).
    pub fn worst(&self) -> Severity {
        self.entries
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(Severity::Unknown)
    }

    /// The severity to show for one entry: a Vuln's own, the alert's
    /// routing severity for the other kinds (a release is High).
    pub fn entry_severity(&self, e: &Entry) -> Severity {
        match self.kind {
            AlertKind::Finding(FindingKind::Vuln) => e.severity,
            _ => self.severity,
        }
    }

    /// The alert of one group of findings.
    pub fn from_group(g: &AlertGroup) -> Alert {
        let mut a = Alert::new(
            format!("alert|{}", g.key()),
            AlertKind::Finding(g.kind),
            title(g),
            g.routing_severity(),
        );
        if matches!(
            g.kind,
            FindingKind::Vuln
                | FindingKind::FixAvailable
                | FindingKind::OathExpired
                | FindingKind::ReleaseNoteCve
                | FindingKind::K8sCve
        ) {
            a.advisory = Some(g.ref_id.clone());
        }
        a.summary = g
            .advisory
            .as_ref()
            .map(|x| x.summary.clone())
            .filter(|s| !s.is_empty());
        a.scores = scores(g);
        a.entries = g
            .items
            .iter()
            .map(|i| Entry {
                finding_id: i.finding_id,
                realm: i.realm.clone(),
                service: i.service.clone(),
                severity: i.severity,
                facts: facts(i.kind, &i.details),
            })
            .collect();
        if let Some(r) = &g.release {
            let lines: Vec<Line> = r
                .breaking
                .iter()
                .take(MAX_BREAKING)
                .map(|l| Line::plain(l.as_str()))
                .collect();
            if !lines.is_empty() {
                a.sections.push(Section {
                    title: "Breaking changes".to_string(),
                    lines,
                });
            }
        }
        a.links = links(g);
        a
    }

    /// The "Heimdall has opened his eyes" summary: open findings by severity.
    pub fn first_run(realm: &str, counts: &[(Severity, i64)]) -> Alert {
        let mut a = Alert::new(
            format!("first_run|{realm}"),
            AlertKind::FirstRun,
            "Heimdall has opened his eyes".to_string(),
            Severity::Unknown,
        );
        a.realm = Some(realm.to_string());
        a.notes = vec![
            format!("Realm {realm} is now watched. Open findings by severity:"),
            "Critical and high findings follow as separate cards; the rest come in the weekly digest."
                .to_string(),
        ];
        let order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Unknown,
        ];
        a.facts = order
            .iter()
            .map(|sev| {
                let n = counts
                    .iter()
                    .find(|(s, _)| s == sev)
                    .map(|(_, n)| *n)
                    .unwrap_or(0);
                Fact {
                    title: capitalized(*sev),
                    value: n.to_string(),
                }
            })
            .collect();
        a
    }

    /// The fixed alert a channel's test send delivers, shaped like the
    /// first-run summary.
    pub fn test() -> Alert {
        let mut a = Alert::new(
            "test|heimdall".to_string(),
            AlertKind::FirstRun,
            "Heimdall test alert".to_string(),
            Severity::Unknown,
        );
        a.notes = vec!["This is a test from Heimdall. No action is needed.".to_string()];
        a
    }

    /// The weekly digest for one channel: the sections with only the rows it
    /// receives; empty sections are left out.
    pub fn digest(today: &str, sections: Vec<Section>) -> Alert {
        let mut a = Alert::new(
            format!("digest|{today}"),
            AlertKind::Digest,
            format!("Heimdall weekly digest {today}"),
            Severity::Unknown,
        );
        a.sections = sections
            .into_iter()
            .filter(|s| !s.lines.is_empty())
            .collect();
        if a.sections.is_empty() {
            a.notes = vec!["Nothing to report this week.".to_string()];
        }
        a
    }

    /// Distinct realms of the entries (or the summary's realm).
    pub fn realms(&self) -> Vec<String> {
        let mut out: BTreeSet<String> = self.entries.iter().map(|e| e.realm.clone()).collect();
        out.extend(self.realm.clone());
        out.into_iter().collect()
    }

    /// Distinct services of the entries.
    pub fn services(&self) -> Vec<String> {
        let out: BTreeSet<String> = self
            .entries
            .iter()
            .filter_map(|e| e.service.clone())
            .filter(|s| !s.is_empty())
            .collect();
        out.into_iter().collect()
    }
}

/// Cut long text so one message stays well under the channels' size limits.
pub(crate) fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_TEXT {
        return s.to_string();
    }
    let cut: String = s.chars().take(MAX_TEXT).collect();
    format!("{cut}…")
}

/// Cut text to at most `max` characters, marking the cut with "…".
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max.saturating_sub(1)).collect();
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

pub(crate) fn capitalized(s: Severity) -> String {
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

/// "a, b, c and 7 more".
fn capped_list(names: &[String]) -> String {
    let shown = names
        .iter()
        .take(TITLE_SERVICES)
        .cloned()
        .collect::<Vec<_>>();
    let mut out = shown.join(", ");
    if names.len() > TITLE_SERVICES {
        out.push_str(&format!(" and {} more", names.len() - TITLE_SERVICES));
    }
    out
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
            format!(
                "Oath expired: {} on {}",
                g.ref_id,
                capped_list(&services(g))
            )
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
            capped_list(&services(g))
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

fn fact(title: &str, value: &str) -> Fact {
    Fact {
        title: title.to_string(),
        value: value.to_string(),
    }
}

/// The facts about one finding, by its kind.
fn facts(kind: FindingKind, d: &Value) -> Vec<Fact> {
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

/// Links: the advisory, the release notes, the Kubernetes issue.
fn links(g: &AlertGroup) -> Vec<Link> {
    let link = |title: &str, url: &str| Link {
        title: title.to_string(),
        url: url.to_string(),
    };
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

/// How a chat formatter marks text up.
pub(crate) struct Markup {
    pub escape: fn(&str) -> String,
    pub bold: fn(&str) -> String,
    /// (text, url), both unescaped.
    pub link: fn(&str, &str) -> String,
}

impl Markup {
    /// One section line: Heimdall's own link (if any), then the text,
    /// escaped, so nothing in it becomes a link.
    pub fn line(&self, line: &Line) -> String {
        let link = line
            .link
            .as_ref()
            .map(|l| (self.link)(&l.title, &l.url))
            .unwrap_or_default();
        format!("{link}{}", (self.escape)(&clip(&line.text)))
    }
}

/// The body of an alert as marked-up lines (no title, no links), each
/// self-contained so a formatter may stop after any of them. At most
/// `max_rows` entries and rows per section are shown, the rest counted.
pub(crate) fn body_lines(a: &Alert, m: &Markup, max_rows: usize) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = &a.summary {
        out.push((m.escape)(&clip(s)));
    }
    if let Some(s) = &a.scores {
        out.push((m.escape)(s));
    }
    for n in &a.notes {
        out.push((m.escape)(n));
    }
    for f in &a.facts {
        out.push(format!(
            "{} {}",
            (m.bold)(&format!("{}:", f.title)),
            (m.escape)(&clip(&f.value))
        ));
    }
    for e in a.entries.iter().take(max_rows) {
        out.push(String::new());
        out.push((m.bold)(&clip(&e.heading())));
        for f in &e.facts {
            out.push(format!(
                "{}: {}",
                (m.escape)(&f.title),
                (m.escape)(&clip(&f.value))
            ));
        }
    }
    if a.entries.len() > max_rows {
        out.push(String::new());
        out.push((m.escape)(&format!(
            "and {} more",
            a.entries.len() - max_rows
        )));
    }
    for s in &a.sections {
        out.push(String::new());
        out.push((m.bold)(&s.title));
        for l in s.lines.iter().take(max_rows) {
            out.push(format!("{} {}", (m.escape)("-"), m.line(l)));
        }
        if s.lines.len() > max_rows {
            out.push((m.escape)(&format!(
                "- and {} more",
                s.lines.len() - max_rows
            )));
        }
    }
    // No leading blank line.
    while out.first().is_some_and(|l| l.is_empty()) {
        out.remove(0);
    }
    out
}

/// Join lines into text of at most `max` characters, dropping whole lines
/// from the end (and saying so) rather than cutting markup in half.
pub(crate) fn join_capped(lines: &[String], max: usize, more: &str) -> String {
    let mut out = String::new();
    let mut used = 0;
    for (i, l) in lines.iter().enumerate() {
        let add = l.chars().count() + usize::from(i > 0);
        // Keep room for the "more" marker.
        if used + add + more.chars().count() + 1 > max {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(more);
            return out;
        }
        if i > 0 {
            out.push('\n');
        }
        out.push_str(l);
        used += add;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_links_only_heimdalls_own_link() {
        fn esc(s: &str) -> String {
            s.replace('<', "&lt;")
        }
        fn link(t: &str, u: &str) -> String {
            format!("<a href={u}>{t}</a>")
        }
        let m = Markup {
            escape: esc,
            bold: esc,
            link,
        };
        let l = Line {
            link: Some(Link {
                title: "pg 17.1".into(),
                url: "https://x.org/n".into(),
            }),
            text: ": see [click](https://evil.example) <b>".into(),
        };
        assert_eq!(
            m.line(&l),
            "<a href=https://x.org/n>pg 17.1</a>: see [click](https://evil.example) &lt;b>"
        );
        assert_eq!(
            l.to_plain(),
            "pg 17.1 <https://x.org/n>: see [click](https://evil.example) <b>"
        );
    }

    #[test]
    fn join_capped_drops_whole_lines() {
        let lines: Vec<String> = (0..100).map(|i| format!("<b>line {i}</b>")).collect();
        let t = join_capped(&lines, 100, "…");
        assert!(t.chars().count() <= 100, "{t}");
        assert!(t.ends_with('…'));
        assert!(t
            .lines()
            .all(|l| l == "…" || (l.starts_with("<b>") && l.ends_with("</b>"))));
    }

    #[test]
    fn digest_without_rows_says_nothing_to_report() {
        let a = Alert::digest(
            "2026-11-16",
            vec![Section {
                title: "x".into(),
                lines: vec![],
            }],
        );
        assert!(a.sections.is_empty());
        assert_eq!(a.notes, vec!["Nothing to report this week."]);
        assert_eq!(a.key, "digest|2026-11-16");
    }
}
