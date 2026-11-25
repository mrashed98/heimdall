//! Alert channels: a formatter per type turns the neutral [`Alert`] into the
//! payload queued in the outbox, and `request` turns a queued payload into
//! what is sent, adding the secrets at send time: a UI channel's from the
//! decrypted [`Secrets`] map, a config channel's from the environment.

pub mod alertmanager;
pub mod discord;
pub mod email;
pub mod pagerduty;
pub mod slack;
pub mod telegram;
pub mod webhook;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::alert::Alert;
use super::teams;
use crate::config::ChannelConfig;

/// The payload queued for `ch`.
pub fn render(ch: &ChannelConfig, a: &Alert) -> Value {
    match ch {
        ChannelConfig::Teams(_) => teams::render(a),
        ChannelConfig::Slack(_) => slack::render(a),
        ChannelConfig::Discord(_) => discord::render(a),
        ChannelConfig::Telegram(_) => telegram::render(a),
        ChannelConfig::PagerDuty(_) => pagerduty::render(a),
        ChannelConfig::Alertmanager(_) => alertmanager::render(a),
        ChannelConfig::Webhook(_) => webhook::render(a),
        ChannelConfig::Email(_) => email::render(a),
    }
}

/// Decrypted UI channel secrets, keyed by their `ui:<name>:<field>` ref.
pub type Secrets = HashMap<String, String>;

/// The value of a `*_env` key at send time: from `secrets` (a UI channel's
/// ref), else the environment variable of that name. Empty counts as unset.
pub(crate) fn secret(var: &str, secrets: &Secrets) -> Option<String> {
    secrets
        .get(var)
        .cloned()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var(var).ok().filter(|v| !v.is_empty()))
}

/// The `*_env` values (variable names or UI refs) of every secret `ch` uses.
fn secret_vars(ch: &ChannelConfig) -> Vec<&str> {
    let mut required: Vec<&str> = Vec::new();
    match ch {
        ChannelConfig::Teams(c) => required.push(&c.webhook_env),
        ChannelConfig::Slack(c) | ChannelConfig::Discord(c) => required.push(&c.webhook_env),
        ChannelConfig::Telegram(c) => required.push(&c.bot_token_env),
        ChannelConfig::PagerDuty(c) => required.push(&c.routing_key_env),
        ChannelConfig::Alertmanager(c) => {
            required.extend(c.username_env.as_deref());
            required.extend(c.password_env.as_deref());
            required.extend(c.bearer_token_env.as_deref());
        }
        ChannelConfig::Webhook(c) => {
            required.push(&c.url_env);
            required.extend(c.secret_env.as_deref());
        }
        ChannelConfig::Email(c) => {
            required.extend(c.username_env.as_deref());
            required.extend(c.password_env.as_deref());
        }
    }
    required
}

/// The first required secret of `ch` that is not set, if any (its `*_env`
/// value: a variable name or a UI ref). A channel with one missing keeps its
/// rows queued.
pub fn missing_env(ch: &ChannelConfig, secrets: &Secrets) -> Option<String> {
    secret_vars(ch)
        .into_iter()
        .find(|v| secret(v, secrets).is_none())
        .map(str::to_string)
}

/// The values of every secret of `ch` that is set, to redact from errors.
pub fn secret_values(ch: &ChannelConfig, secrets: &Secrets) -> Vec<String> {
    secret_vars(ch)
        .into_iter()
        .filter_map(|v| secret(v, secrets))
        .collect()
}

/// HTTP authentication added to a request (never put in the URL).
#[derive(Debug, Clone, PartialEq)]
pub enum HttpAuth {
    Basic(String, String),
    Bearer(String),
}

/// What to send for one outbox row.
#[derive(Debug)]
pub enum Request {
    Http {
        url: String,
        body: Vec<u8>,
        headers: Vec<(&'static str, String)>,
        auth: Option<HttpAuth>,
        /// Secrets that must never appear in a logged or stored error: the
        /// URL when it is the credential (Teams, Slack, Discord, webhook),
        /// the Telegram token in the URL path, keys and passwords.
        redact: Vec<String>,
    },
    Email(Box<lettre::Message>),
}

/// Build the request for a queued `payload` of channel `ch`. Fails when a
/// secret is missing (the caller checked `missing_env` first) or the
/// payload does not fit the channel (it was queued for another type).
pub fn request(
    ch: &ChannelConfig,
    payload: &Value,
    now: DateTime<Utc>,
    secrets: &Secrets,
) -> anyhow::Result<Request> {
    let need = |var: &str| secret(var, secrets).ok_or_else(|| anyhow::anyhow!("{var} is not set"));
    let json = |v: &Value| serde_json::to_vec(v).expect("JSON values serialize");
    // The URL itself is the credential.
    let http = |url: String, body: Vec<u8>| Request::Http {
        redact: vec![url.clone()],
        url,
        body,
        headers: Vec::new(),
        auth: None,
    };
    Ok(match ch {
        ChannelConfig::Teams(c) => http(need(&c.webhook_env)?, json(payload)),
        ChannelConfig::Slack(c) | ChannelConfig::Discord(c) => {
            http(need(&c.webhook_env)?, json(payload))
        }
        ChannelConfig::Telegram(c) => {
            let token = need(&c.bot_token_env)?;
            let base = c
                .api_url
                .as_deref()
                .unwrap_or(telegram::API_URL)
                .trim_end_matches('/');
            let mut message = payload.clone();
            message["chat_id"] = Value::String(c.chat_id.as_string());
            Request::Http {
                url: format!("{base}/bot{token}/sendMessage"),
                body: json(&message),
                headers: Vec::new(),
                auth: None,
                redact: vec![token],
            }
        }
        ChannelConfig::PagerDuty(c) => {
            let key = need(&c.routing_key_env)?;
            let mut event = payload.clone();
            event["routing_key"] = Value::String(key.clone());
            Request::Http {
                url: c.url.clone().unwrap_or(pagerduty::EVENTS_URL.to_string()),
                body: json(&event),
                headers: Vec::new(),
                auth: None,
                redact: vec![key],
            }
        }
        ChannelConfig::Alertmanager(c) => {
            let alerts = alertmanager::with_times(payload, now, c.expire_after_hours)?;
            let auth = match (&c.username_env, &c.password_env, &c.bearer_token_env) {
                (Some(u), Some(p), _) => Some(HttpAuth::Basic(need(u)?, need(p)?)),
                (_, _, Some(t)) => Some(HttpAuth::Bearer(need(t)?)),
                _ => None,
            };
            let redact = match &auth {
                Some(HttpAuth::Basic(u, p)) => vec![u.clone(), p.clone()],
                Some(HttpAuth::Bearer(t)) => vec![t.clone()],
                None => Vec::new(),
            };
            Request::Http {
                url: format!("{}/api/v2/alerts", c.url.trim_end_matches('/')),
                body: json(&alerts),
                headers: Vec::new(),
                auth,
                redact,
            }
        }
        ChannelConfig::Webhook(c) => {
            let body = json(payload);
            let ts = now.timestamp();
            let mut headers = vec![(webhook::TIMESTAMP_HEADER, ts.to_string())];
            let url = need(&c.url_env)?;
            let mut redact = vec![url.clone()];
            if let Some(var) = &c.secret_env {
                let secret = need(var)?;
                headers.push((
                    webhook::SIGNATURE_HEADER,
                    webhook::signature(&secret, ts, &body),
                ));
                redact.push(secret);
            }
            Request::Http {
                url,
                body,
                headers,
                auth: None,
                redact,
            }
        }
        ChannelConfig::Email(c) => Request::Email(Box::new(email::message(c, payload)?)),
    })
}
