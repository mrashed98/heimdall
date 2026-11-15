//! Prometheus Alertmanager formatter: alerts for `POST /api/v2/alerts`.
//!
//! One Alertmanager alert per finding (labels realm, service, kind,
//! severity, advisory), so Alertmanager can route, group and silence on
//! them. Heimdall announces a finding once and does not track it afterwards,
//! so it never sends a resolution: each alert is sent once with `startsAt`
//! set to the delivery time and `endsAt` to the delivery time plus the
//! channel's `expire_after_hours`, after which Alertmanager expires it.
//! The times are added at send time (`with_times`), so a delayed delivery
//! does not arrive already expired.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Map, Value};

use crate::notify::alert::{
    body_lines, clip, join_capped, severity_name, truncate, Alert, AlertKind, Entry, Markup,
};

/// Findings sent as separate alerts; the rest are counted on the last one.
const MAX_ALERTS: usize = 100;
const DESCRIPTION_CHARS: usize = 4000;

fn plain(s: &str) -> String {
    s.to_string()
}

fn plain_link(text: &str, url: &str) -> String {
    format!("{text} ({url})")
}

const PLAIN: Markup = Markup {
    escape: plain,
    bold: plain,
    link: plain_link,
};

/// The queued payload: `{"alerts": [...]}` without times.
pub fn render(a: &Alert) -> Value {
    let mut alerts: Vec<Value> = if a.entries.is_empty() {
        vec![one(a, None)]
    } else {
        a.entries
            .iter()
            .take(MAX_ALERTS)
            .map(|e| one(a, Some(e)))
            .collect()
    };
    if a.entries.len() > MAX_ALERTS {
        if let Some(last) = alerts.last_mut() {
            last["annotations"]["more"] = json!(format!(
                "and {} more findings",
                a.entries.len() - MAX_ALERTS
            ));
        }
    }
    json!({"alerts": alerts})
}

fn one(a: &Alert, e: Option<&Entry>) -> Value {
    let mut labels = Map::new();
    labels.insert(
        "alertname".into(),
        json!(format!("Heimdall{}", a.kind.name())),
    );
    labels.insert("kind".into(), json!(a.kind.label()));
    let severity = match (a.kind, e) {
        (AlertKind::Finding(_), Some(e)) => severity_name(a.entry_severity(e)),
        (AlertKind::Finding(_), None) => severity_name(a.severity),
        _ => "info",
    };
    labels.insert("severity".into(), json!(severity));
    let realm = e.map(|e| e.realm.clone()).or(a.realm.clone());
    if let Some(r) = realm {
        labels.insert("realm".into(), json!(r));
    }
    if let Some(s) = e.and_then(|e| e.service.clone()).filter(|s| !s.is_empty()) {
        labels.insert("service".into(), json!(s));
    }
    if let Some(adv) = &a.advisory {
        labels.insert("advisory".into(), json!(adv));
    }

    let description = match e {
        // The alert's own finding: summary, scores and its facts.
        Some(e) => {
            let mut lines: Vec<String> = Vec::new();
            lines.extend(a.summary.as_deref().map(clip));
            lines.extend(a.scores.clone());
            lines.push(e.heading());
            lines.extend(
                e.facts
                    .iter()
                    .map(|f| format!("{}: {}", f.title, clip(&f.value))),
            );
            for s in &a.sections {
                lines.push(format!("{}:", s.title));
                lines.extend(s.lines.iter().map(|l| format!("- {}", clip(&l.to_plain()))));
            }
            join_capped(&lines, DESCRIPTION_CHARS, "…")
        }
        None => join_capped(&body_lines(a, &PLAIN, 25), DESCRIPTION_CHARS, "…"),
    };
    let mut annotations = Map::new();
    annotations.insert("summary".into(), json!(truncate(&a.title, 500)));
    annotations.insert("description".into(), json!(description));
    if !a.links.is_empty() {
        let links: Vec<&str> = a.links.iter().map(|l| l.url.as_str()).collect();
        annotations.insert("links".into(), json!(links.join("\n")));
    }
    let mut alert = json!({"labels": labels, "annotations": annotations});
    if let Some(l) = a.links.first() {
        alert["generatorURL"] = json!(l.url);
    }
    alert
}

/// The array Alertmanager takes, with `startsAt = now` and
/// `endsAt = now + expire_after_hours` on every alert.
pub fn with_times(
    payload: &Value,
    now: DateTime<Utc>,
    expire_after_hours: u32,
) -> anyhow::Result<Value> {
    let Some(alerts) = payload["alerts"].as_array() else {
        anyhow::bail!("not an Alertmanager payload");
    };
    let starts = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let ends = (now + Duration::hours(i64::from(expire_after_hours)))
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let out: Vec<Value> = alerts
        .iter()
        .map(|a| {
            let mut a = a.clone();
            a["startsAt"] = json!(starts);
            a["endsAt"] = json!(ends);
            a
        })
        .collect();
    Ok(Value::Array(out))
}
