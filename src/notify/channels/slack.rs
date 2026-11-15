//! Slack formatter: an incoming-webhook message with Block Kit blocks.

use serde_json::{json, Value};

use crate::notify::alert::{body_lines, severity_name, truncate, Alert, AlertKind, Markup};

/// Entries and section rows shown before "and N more".
const MAX_ROWS: usize = 25;
/// A section block's text may hold 3000 characters.
const SECTION_CHARS: usize = 2900;
/// Slack allows 50 blocks; header, context and actions take three.
const MAX_SECTIONS: usize = 40;

/// `&`, `<` and `>` are the only characters mrkdwn needs escaped.
pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn bold(s: &str) -> String {
    format!("*{}*", escape(s))
}

fn link(text: &str, url: &str) -> String {
    // `|` and `>` would end the link early.
    format!(
        "<{}|{}>",
        url.replace('|', "%7C").replace('>', "%3E"),
        escape(text).replace('|', "¦")
    )
}

pub(crate) const MARKUP: Markup = Markup { escape, bold, link };

pub fn render(a: &Alert) -> Value {
    let mut blocks = vec![json!({
        "type": "header",
        "text": {"type": "plain_text", "text": truncate(&a.title, 150), "emoji": true},
    })];
    let mut context = Vec::new();
    if matches!(a.kind, AlertKind::Finding(_)) {
        context.push(format!("*Severity:* {}", severity_name(a.severity)));
    }
    let realms = a.realms();
    if !realms.is_empty() {
        context.push(format!("*Realm:* {}", escape(&realms.join(", "))));
    }
    if !context.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": context.join("  ·  ")}],
        }));
    }

    // Lines grouped into section blocks of at most SECTION_CHARS.
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in body_lines(a, &MARKUP, MAX_ROWS) {
        let line = truncate(&line, SECTION_CHARS);
        if !cur.is_empty() && cur.chars().count() + line.chars().count() + 1 > SECTION_CHARS {
            chunks.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(&line);
    }
    if !cur.trim().is_empty() {
        chunks.push(cur);
    }
    let total = chunks.len();
    for (i, text) in chunks.into_iter().enumerate() {
        if i == MAX_SECTIONS {
            blocks.push(json!({"type": "section", "text": {"type": "mrkdwn",
                "text": format!("and {} more blocks", total - MAX_SECTIONS)}}));
            break;
        }
        blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": text}}));
    }

    let buttons: Vec<Value> = a
        .links
        .iter()
        .take(5)
        .map(|l| {
            json!({"type": "button", "text": {"type": "plain_text", "text": truncate(&l.title, 75)},
                   "url": l.url})
        })
        .collect();
    if !buttons.is_empty() {
        blocks.push(json!({"type": "actions", "elements": buttons}));
    }
    // `text` is the notification and screen-reader fallback.
    json!({"text": truncate(&a.title, 150), "blocks": blocks})
}
