//! Tables and verdict lines as pure `fn -> String`.

use comfy_table::presets::{ASCII_FULL_CONDENSED, UTF8_FULL_CONDENSED};
use comfy_table::{Attribute, Cell, Color, Table};
use serde::Serialize;

use crate::auth::KeyInfo;
use crate::gate::{split_purl, CheckSource, GateFinding, GateResponse, Verdict};
use crate::model::Severity;
use crate::oath::Oath;
use crate::server::{FindingRow, RealmRow};

use super::{bold, dim, paint, Style};

const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Unknown,
];

/// The serde name of a unit enum ("high", "osv", "vuln"...).
fn label<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "?".into())
}

/// SGR code of a severity: critical is bold white on red.
fn severity_code(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "1;97;41",
        Severity::High => "31",
        Severity::Medium => "33",
        Severity::Low => "34",
        Severity::Unknown => "2",
    }
}

pub fn severity_badge(style: &Style, sev: Severity) -> String {
    let word = label(&sev).to_uppercase();
    paint(style, severity_code(sev), &word)
}

/// A table cell coloured like the severity badge.
fn severity_cell(style: &Style, sev: Severity) -> Cell {
    let word = label(&sev).to_uppercase();
    if !style.color {
        return Cell::new(word);
    }
    match sev {
        Severity::Critical => Cell::new(word)
            .fg(Color::White)
            .bg(Color::Red)
            .add_attribute(Attribute::Bold),
        Severity::High => Cell::new(word).fg(Color::Red),
        Severity::Medium => Cell::new(word).fg(Color::Yellow),
        Severity::Low => Cell::new(word).fg(Color::Blue),
        Severity::Unknown => Cell::new(word).add_attribute(Attribute::Dim),
    }
}

/// A cell in a plain colour, only when colour is on.
fn colored_cell(style: &Style, text: impl ToString, color: Color) -> Cell {
    let cell = Cell::new(text);
    if style.color {
        cell.fg(color)
    } else {
        cell
    }
}

/// A table with the preset that suits the style: rounded unicode or ASCII.
fn new_table(style: &Style, header: &[&str]) -> Table {
    let mut table = Table::new();
    if style.color {
        table.load_style(UTF8_FULL_CONDENSED.with_rounded_corners());
        // Styling is normally skipped when stdout is not a terminal (GitHub
        // Actions); the style decision was already made by `Style`.
        table.enforce_styling();
    } else {
        table.load_style(ASCII_FULL_CONDENSED);
    }
    let cells: Vec<Cell> = header
        .iter()
        .map(|h| {
            if style.color {
                Cell::new(h).add_attribute(Attribute::Bold)
            } else {
                Cell::new(h)
            }
        })
        .collect();
    table.set_header(cells);
    table
}

/// "✓ message" in colour, "OK message" without.
pub fn ok_line(style: &Style, msg: &str) -> String {
    let mark = if style.color { "✓" } else { "OK" };
    format!("{} {msg}\n", paint(style, "32", mark))
}

/// "! message" in colour, "!! message" without, for partial failures.
pub fn warn_line(style: &Style, msg: &str) -> String {
    let mark = if style.color { "!" } else { "!!" };
    format!("{} {msg}\n", paint(style, "33", mark))
}

fn arrow(style: &Style) -> &'static str {
    if style.color {
        "→"
    } else {
        "->"
    }
}

fn gate_table(style: &Style, findings: &[GateFinding]) -> Table {
    let header = format!("VERSION {} FIXED", arrow(style));
    let mut table = new_table(style, &["SEVERITY", "ADVISORY", "PACKAGE", &header, "OATH"]);
    for f in findings {
        let (package, current) = split_purl(&f.purl);
        let fixed = f.fixed.as_deref().unwrap_or("-");
        let oath = f.oath.map(|id| format!("#{id}")).unwrap_or("-".into());
        table.add_row(vec![
            severity_cell(style, f.severity),
            Cell::new(&f.advisory),
            Cell::new(package),
            Cell::new(format!("{current} {} {fixed}", arrow(style))),
            Cell::new(oath),
        ]);
    }
    table
}

/// "2 high, 1 medium", or "none".
fn severity_summary(style: &Style, findings: &[GateFinding]) -> String {
    let parts: Vec<String> = SEVERITIES
        .iter()
        .filter_map(|sev| {
            let n = findings.iter().filter(|f| f.severity == *sev).count();
            (n > 0).then(|| paint(style, severity_code(*sev), &format!("{n} {}", label(sev))))
        })
        .collect();
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(", ")
    }
}

fn verdict_word(style: &Style, v: Verdict) -> String {
    match v {
        Verdict::Pass => paint(style, "1;32", "PASS"),
        Verdict::Fail => paint(style, "1;31", "FAIL"),
        Verdict::Unverified => paint(style, "1;33", "UNVERIFIED"),
    }
}

pub fn gate_report(style: &Style, r: &GateResponse) -> String {
    let title = if style.color {
        "⚔ Hofund — CI gate"
    } else {
        ">> Hofund - CI gate"
    };
    let mut out = format!("{}\n", bold(style, title));
    if !r.findings.is_empty() {
        out.push_str(&format!("{}\n", gate_table(style, &r.findings)));
    }
    out.push_str(&format!(
        "findings: {}\n",
        severity_summary(style, &r.findings)
    ));
    for purl in &r.unverified {
        out.push_str(&format!("{} {purl}\n", paint(style, "33", "unverified:")));
    }
    let source = match r.source {
        CheckSource::Osv | CheckSource::Ghsa => label(&r.source),
    };
    out.push_str(&format!(
        "verdict: {} {}\n",
        verdict_word(style, r.verdict),
        dim(style, &format!("(checked against {source})"))
    ));
    out
}

/// The "nothing here" line shared by every list.
fn empty_state(style: &Style, msg: &str) -> String {
    ok_line(style, msg)
}

pub fn findings_table(
    style: &Style,
    rows: &[FindingRow],
    status: &str,
    realm: Option<&str>,
) -> String {
    if rows.is_empty() {
        let scope = realm.unwrap_or("all realms");
        return empty_state(style, &format!("No {status} findings in {scope}"));
    }
    let mut table = new_table(
        style,
        &["ID", "SEVERITY", "KIND", "REALM", "SERVICE", "REF", "PURL"],
    );
    for f in rows {
        table.add_row(vec![
            Cell::new(f.id),
            severity_cell(style, f.severity),
            Cell::new(label(&f.kind)),
            Cell::new(&f.realm),
            Cell::new(f.service.as_deref().unwrap_or("-")),
            Cell::new(f.ref_id.as_deref().unwrap_or("-")),
            Cell::new(f.purl.as_deref().unwrap_or("-")),
        ]);
    }
    format!("{table}\n")
}

pub fn oaths_table(style: &Style, oaths: &[Oath]) -> String {
    if oaths.is_empty() {
        return empty_state(style, "No oaths");
    }
    let mut table = new_table(
        style,
        &[
            "ID",
            "STATUS",
            "ADVISORY",
            "COMPONENT",
            "SERVICE",
            "REALM",
            "DUE",
            "REASON",
        ],
    );
    for o in oaths {
        let due = o
            .expires_at
            .or(o.review_at)
            .map(|d| d.date_naive().to_string())
            .unwrap_or_default();
        let color = match o.status.as_str() {
            "active" => Color::Green,
            "expired" => Color::Red,
            _ => Color::DarkGrey,
        };
        table.add_row(vec![
            Cell::new(o.id),
            colored_cell(style, &o.status, color),
            Cell::new(&o.advisory_id),
            Cell::new(&o.name_key),
            Cell::new(&o.service_name),
            Cell::new(o.realm.as_deref().unwrap_or("*")),
            Cell::new(due),
            Cell::new(&o.reason),
        ]);
    }
    format!("{table}\n")
}

pub fn keys_table(style: &Style, keys: &[KeyInfo]) -> String {
    if keys.is_empty() {
        return empty_state(style, "No API keys");
    }
    let mut table = new_table(style, &["NAME", "SCOPE", "CREATED"]);
    for k in keys {
        table.add_row(vec![
            Cell::new(&k.name),
            Cell::new(&k.scope),
            Cell::new(k.created_at.format("%Y-%m-%d %H:%M UTC")),
        ]);
    }
    format!("{table}\n")
}

pub fn realms_table(style: &Style, realms: &[RealmRow]) -> String {
    if realms.is_empty() {
        return empty_state(style, "No realms");
    }
    let mut table = new_table(style, &["REALM", "SERVICES", "OPEN FINDINGS"]);
    for r in realms {
        let color = if r.open_findings > 0 {
            Color::Red
        } else {
            Color::Green
        };
        table.add_row(vec![
            Cell::new(&r.name),
            Cell::new(r.services),
            colored_cell(style, r.open_findings, color),
        ]);
    }
    format!("{table}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{CheckSource, GateFinding, Verdict};

    fn finding(sev: Severity, adv: &str, oath: Option<i64>) -> GateFinding {
        GateFinding {
            advisory: adv.into(),
            severity: sev,
            purl: "pkg:npm/widget@1.2.0".into(),
            fixed: Some("1.9.1".into()),
            oath,
        }
    }

    #[test]
    fn gate_report_fail_lists_findings_and_verdict() {
        let r = GateResponse {
            verdict: Verdict::Fail,
            source: CheckSource::Osv,
            findings: vec![
                finding(Severity::Critical, "GHSA-aaaa-bbbb-cccc", None),
                finding(Severity::High, "CVE-2026-0001", Some(7)),
                finding(Severity::High, "CVE-2026-0002", None),
            ],
            unverified: vec![],
        };
        let out = gate_report(&Style::plain(), &r);
        assert!(!out.contains('\x1b'));
        assert!(out.contains("GHSA-aaaa-bbbb-cccc"));
        assert!(out.contains("widget"));
        assert!(out.contains("1.2.0 -> 1.9.1"));
        assert!(out.contains("#7"));
        assert!(out.contains("1 critical"));
        assert!(out.contains("2 high"));
        assert!(out.contains("FAIL"));
        assert!(out.contains("osv"));
        // Coloured output carries the same words plus ANSI.
        let c = gate_report(
            &Style {
                color: true,
                truecolor: false,
            },
            &r,
        );
        assert!(c.contains('\x1b') && c.contains("FAIL"));
    }

    #[test]
    fn gate_report_unverified_lists_purls() {
        let r = GateResponse {
            verdict: Verdict::Unverified,
            source: CheckSource::Ghsa,
            findings: vec![],
            unverified: vec!["pkg:deb/debian/libssl3@3.0.11".into()],
        };
        let out = gate_report(&Style::plain(), &r);
        assert!(out.contains("UNVERIFIED"));
        assert!(out.contains("pkg:deb/debian/libssl3@3.0.11"));
        assert!(out.contains("ghsa"));
    }

    #[test]
    fn findings_table_empty_state() {
        let out = findings_table(&Style::plain(), &[], "open", Some("dev-k3s"));
        assert!(out.contains("No open findings in dev-k3s"), "{out}");
        let out = findings_table(&Style::plain(), &[], "resolved", None);
        assert!(out.contains("No resolved findings in all realms"), "{out}");
    }

    #[test]
    fn severity_badge_plain_is_uppercase_word() {
        assert_eq!(severity_badge(&Style::plain(), Severity::High), "HIGH");
    }
}
