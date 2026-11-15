//! PagerDuty formatter: an Events API v2 `trigger` event. The routing key is
//! added at send time, so it is never stored in the outbox.

use serde_json::{json, Map, Value};

use crate::model::Severity;
use crate::notify::alert::{truncate, Alert};

pub(crate) const EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";
/// Entries listed in `custom_details`.
const MAX_ROWS: usize = 25;

/// PagerDuty knows critical, error, warning and info.
fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "info",
    }
}

pub fn render(a: &Alert) -> Value {
    let mut details = Map::new();
    details.insert("kind".into(), json!(a.kind));
    if let Some(adv) = &a.advisory {
        details.insert("advisory".into(), json!(adv));
    }
    if let Some(s) = &a.summary {
        details.insert("summary".into(), json!(truncate(s, 1000)));
    }
    if let Some(s) = &a.scores {
        details.insert("scores".into(), json!(s));
    }
    for n in &a.notes {
        details.insert("note".into(), json!(n));
    }
    for f in &a.facts {
        details.insert(f.title.clone(), json!(f.value));
    }
    let findings: Vec<Value> = a
        .entries
        .iter()
        .take(MAX_ROWS)
        .map(|e| {
            let facts: Map<String, Value> = e
                .facts
                .iter()
                .map(|f| (f.title.clone(), json!(truncate(&f.value, 300))))
                .collect();
            json!({"realm": e.realm, "service": e.service,
                   "severity": a.entry_severity(e), "facts": facts})
        })
        .collect();
    if !findings.is_empty() {
        details.insert("findings".into(), json!(findings));
    }
    if a.entries.len() > MAX_ROWS {
        details.insert("more_findings".into(), json!(a.entries.len() - MAX_ROWS));
    }
    for s in &a.sections {
        let lines: Vec<String> = s
            .lines
            .iter()
            .take(MAX_ROWS)
            .map(|l| truncate(&l.to_plain(), 300))
            .collect();
        details.insert(s.title.clone(), json!(lines));
    }

    let mut payload = json!({
        "summary": truncate(&a.title, 1024),
        "source": "heimdall",
        "severity": severity(a.severity),
        "class": a.kind.label(),
        "custom_details": details,
    });
    let realms = a.realms();
    if !realms.is_empty() {
        payload["group"] = json!(realms.join(","));
    }
    let services = a.services();
    if !services.is_empty() {
        payload["component"] = json!(truncate(&services.join(","), 255));
    }
    let links: Vec<Value> = a
        .links
        .iter()
        .map(|l| json!({"href": l.url, "text": l.title}))
        .collect();
    json!({
        "event_action": "trigger",
        // The same advisory or release dedups into the open incident.
        "dedup_key": truncate(&a.key, 255),
        "client": "Heimdall",
        "payload": payload,
        "links": links,
    })
}
