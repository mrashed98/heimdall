//! Mattermost formatter: an incoming-webhook post with one attachment
//! (Mattermost's Slack-compatible message attachments, in Markdown).

use serde_json::{json, Value};

use crate::model::Severity;
use crate::notify::alert::{
    body_lines, join_capped, severity_name, truncate, Alert, AlertKind, Markup,
};

/// Entries and section rows shown before "and N more".
const MAX_ROWS: usize = 25;
/// A post may hold 16383 characters; leave room for the title and fields.
const TEXT_CHARS: usize = 15000;

/// Backslash-escape Markdown, and break an `@` that starts a word so text
/// from an advisory can never mention anyone (`@channel`, `@all`, a user).
/// An `@` inside a word (`pkg@v1.2`) mentions nobody and is left alone.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev: Option<char> = None;
    for c in s.chars() {
        match c {
            '@' if !prev.is_some_and(char::is_alphanumeric) => out.push_str("@\u{2060}"),
            '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '<' | '[' | ']' | '#' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
        prev = Some(c);
    }
    out
}

fn bold(s: &str) -> String {
    format!("**{}**", escape(s))
}

fn link(text: &str, url: &str) -> String {
    format!("[{}]({})", escape(text), url.replace(')', "%29"))
}

/// `s` with every word-initial `@` broken, and nothing else changed.
pub(crate) fn no_mentions(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev: Option<char> = None;
    for c in s.chars() {
        out.push(c);
        if c == '@' && !prev.is_some_and(char::is_alphanumeric) {
            out.push('\u{2060}');
        }
        prev = Some(c);
    }
    out
}

/// `title` escaped, cut so the escaped text fits in `max` characters without
/// splitting an escape (which would leave a stray backslash).
fn escaped_title(title: &str, max: usize) -> String {
    let mut keep = title.chars().count();
    loop {
        let cut: String = title.chars().take(keep).collect();
        let more = keep < title.chars().count();
        let esc = escape(&cut) + if more { "…" } else { "" };
        if esc.chars().count() <= max || keep == 0 {
            return esc;
        }
        keep -= 1;
    }
}

pub(crate) const MARKUP: Markup = Markup { escape, bold, link };

/// Attachment colour by severity.
fn color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#B71C1C",
        Severity::High => "#E65100",
        Severity::Medium => "#F9A825",
        Severity::Low => "#1565C0",
        Severity::Unknown => "#607D8B",
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
            .push(json!({"short": true, "title": "Severity", "value": severity_name(a.severity)}));
    }
    let realms = a.realms();
    if !realms.is_empty() {
        fields.push(json!({"short": true, "title": "Realm", "value": truncate(&escape(&realms.join(", ")), 1024)}));
    }
    // `fallback` feeds push and desktop notifications, which are plain text:
    // Markdown escapes would show as backslashes there. `title` stays
    // escaped, since the client may render Markdown links in it.
    let title = truncate(&a.title, 250);
    let mut attachment = json!({
        "fallback": no_mentions(&title),
        "color": color(a.severity),
        "title": escaped_title(&a.title, 250),
        "text": join_capped(&lines, TEXT_CHARS, "…"),
        "fields": fields,
        "footer": "Heimdall",
    });
    if let Some(l) = a.links.first() {
        attachment["title_link"] = Value::String(l.url.clone());
    }
    json!({"username": "Heimdall", "attachments": [attachment]})
}
