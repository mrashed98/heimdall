//! Discord formatter: a webhook message with one embed.

use serde_json::{json, Value};

use crate::model::Severity;
use crate::notify::alert::{
    body_lines, join_capped, severity_name, truncate, Alert, AlertKind, Markup,
};

/// Entries and section rows shown before "and N more".
const MAX_ROWS: usize = 25;
/// An embed description may hold 4096 characters (and the whole embed 6000).
const DESCRIPTION_CHARS: usize = 4000;

/// Backslash-escape Discord Markdown.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '<' | '[' | ']' | '#' | '@'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn bold(s: &str) -> String {
    format!("**{}**", escape(s))
}

fn link(text: &str, url: &str) -> String {
    format!("[{}]({})", escape(text), url.replace(')', "%29"))
}

pub(crate) const MARKUP: Markup = Markup { escape, bold, link };

/// Embed colour by severity.
fn color(s: Severity) -> u32 {
    match s {
        Severity::Critical => 0xB71C1C,
        Severity::High => 0xE65100,
        Severity::Medium => 0xF9A825,
        Severity::Low => 0x1565C0,
        Severity::Unknown => 0x607D8B,
    }
}

pub fn render(a: &Alert) -> Value {
    let mut lines = body_lines(a, &MARKUP, MAX_ROWS);
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
    let mut fields = Vec::new();
    if matches!(a.kind, AlertKind::Finding(_)) {
        fields
            .push(json!({"name": "Severity", "value": severity_name(a.severity), "inline": true}));
    }
    let realms = a.realms();
    if !realms.is_empty() {
        fields.push(
            json!({"name": "Realm", "value": truncate(&escape(&realms.join(", ")), 1024),
                           "inline": true}),
        );
    }
    let mut embed = json!({
        "title": truncate(&a.title, 256),
        "description": join_capped(&lines, DESCRIPTION_CHARS, "…"),
        "color": color(a.severity),
        "fields": fields,
        "footer": {"text": "Heimdall"},
    });
    if let Some(l) = a.links.first() {
        embed["url"] = Value::String(l.url.clone());
    }
    json!({
        "username": "Heimdall",
        // Text from advisories must never ping anyone (@everyone and the like).
        "allowed_mentions": {"parse": []},
        "embeds": [embed],
    })
}
