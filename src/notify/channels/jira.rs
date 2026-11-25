//! Jira formatter: one issue per alert, created with the REST API v2 (Jira
//! Cloud and Data Center both take it), with a wiki-markup description.
//! The project and issue type are added when sending (`request`), so a
//! changed project reaches issues still queued.

use serde_json::{json, Value};

use crate::notify::alert::{
    body_lines, join_capped, severity_name, truncate, Alert, AlertKind, Markup,
};

/// Entries and section rows shown before "and N more".
const MAX_ROWS: usize = 50;
/// A description may hold 32767 characters.
const DESCRIPTION_CHARS: usize = 30000;
/// A summary may hold 255 characters.
const SUMMARY_CHARS: usize = 255;
/// The issue type when the channel sets none.
pub const DEFAULT_ISSUE_TYPE: &str = "Task";

/// Backslash-escape every character wiki markup gives a meaning to.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '*'
                | '_'
                | '-'
                | '+'
                | '^'
                | '~'
                | '?'
                | '{'
                | '}'
                | '['
                | ']'
                | '|'
                | '!'
                | '#'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn bold(s: &str) -> String {
    format!("*{}*", escape(s))
}

fn link(text: &str, url: &str) -> String {
    // `|` and `]` would end the link early.
    format!(
        "[{}|{}]",
        escape(text),
        url.replace('|', "%7C").replace(']', "%5D")
    )
}

pub(crate) const MARKUP: Markup = Markup { escape, bold, link };

/// The issue's summary, description and labels; `request` adds the
/// project and issue type.
pub fn render(a: &Alert) -> Value {
    let mut lines = Vec::new();
    if matches!(a.kind, AlertKind::Finding(_)) {
        lines.push(format!("*Severity:* {}", severity_name(a.severity)));
    }
    let realms = a.realms();
    if !realms.is_empty() {
        lines.push(format!("*Realm:* {}", escape(&realms.join(", "))));
    }
    if !lines.is_empty() {
        lines.push(String::new());
    }
    lines.extend(body_lines(a, &MARKUP, MAX_ROWS));
    if !a.links.is_empty() {
        lines.push(String::new());
        lines.push(
            a.links
                .iter()
                .map(|l| link(&l.title, &l.url))
                .collect::<Vec<_>>()
                .join(" · "),
        );
    }
    let mut labels = vec!["heimdall".to_string()];
    if matches!(a.kind, AlertKind::Finding(_)) {
        labels.push(format!("severity-{}", severity_name(a.severity)));
    }
    // The summary is plain text: one line, no markup.
    let summary = a.title.replace(['\r', '\n'], " ");
    json!({
        "fields": {
            "summary": truncate(&summary, SUMMARY_CHARS),
            "description": join_capped(&lines, DESCRIPTION_CHARS, "…"),
            "labels": labels,
        }
    })
}
