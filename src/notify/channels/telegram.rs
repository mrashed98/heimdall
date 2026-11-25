//! Telegram formatter: a Bot API `sendMessage` call in HTML parse mode.

use serde_json::{json, Value};

use crate::notify::alert::{body_lines, join_capped, severity_name, Alert, AlertKind, Markup};

pub(crate) const API_URL: &str = "https://api.telegram.org";
/// Entries and section rows shown before "and N more".
const MAX_ROWS: usize = 25;
/// A message may hold 4096 characters after entity parsing; the raw HTML is
/// longer than that, so capping it keeps the message within the limit.
const MESSAGE_CHARS: usize = 4000;

/// The three characters Telegram's HTML mode needs escaped, plus `"` for
/// attribute values.
pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn bold(s: &str) -> String {
    format!("<b>{}</b>", escape(s))
}

fn link(text: &str, url: &str) -> String {
    format!("<a href=\"{}\">{}</a>", escape(url), escape(text))
}

pub(crate) const MARKUP: Markup = Markup { escape, bold, link };

/// The message without its `chat_id`: `request` adds the channel's current
/// one at send time, so an edited `chat_id` reaches rows already queued.
pub fn render(a: &Alert) -> Value {
    let mut lines = vec![bold(&a.title)];
    if matches!(a.kind, AlertKind::Finding(_)) {
        lines.push(format!("Severity: {}", severity_name(a.severity)));
    }
    lines.push(String::new());
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
    json!({
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": true},
        "text": join_capped(&lines, MESSAGE_CHARS, "…"),
    })
}
