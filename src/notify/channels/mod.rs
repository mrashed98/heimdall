//! Alert channels: a formatter per type turns the neutral [`Alert`] into the
//! payload queued in the outbox, and `request` turns a queued payload into
//! what is sent, adding the secrets (read from the environment at send time,
//! never stored in the database).

pub mod alertmanager;
pub mod discord;
pub mod email;
pub mod pagerduty;
pub mod slack;
pub mod telegram;
pub mod webhook;

#[cfg(test)]
mod tests;

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
        ChannelConfig::Telegram(c) => telegram::render(a, &c.chat_id.as_string()),
        ChannelConfig::PagerDuty(_) => pagerduty::render(a),
        ChannelConfig::Alertmanager(_) => alertmanager::render(a),
        ChannelConfig::Webhook(_) => webhook::render(a),
        ChannelConfig::Email(_) => email::render(a),
    }
}

/// An environment variable read at send time; empty counts as unset.
fn env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.is_empty())
}

/// The first required environment variable of `ch` that is not set, if any.
/// A channel with one missing keeps its rows queued.
pub fn missing_env(ch: &ChannelConfig) -> Option<String> {
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
        .into_iter()
        .find(|v| env(v).is_none())
        .map(str::to_string)
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
        /// Secrets that must never appear in a logged error (the Telegram
        /// token sits in the URL path).
        redact: Vec<String>,
    },
    Email(Box<lettre::Message>),
}

/// Build the request for a queued `payload` of channel `ch`. Fails when a
/// secret is missing (the caller checked `missing_env` first) or the
/// payload does not fit the channel (it was queued for another type).
pub fn request(ch: &ChannelConfig, payload: &Value, now: DateTime<Utc>) -> anyhow::Result<Request> {
    let need = |var: &str| env(var).ok_or_else(|| anyhow::anyhow!("{var} is not set"));
    let json = |v: &Value| serde_json::to_vec(v).expect("JSON values serialize");
    let http = |url: String, body: Vec<u8>| Request::Http {
        url,
        body,
        headers: Vec::new(),
        auth: None,
        redact: Vec::new(),
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
            Request::Http {
                url: format!("{base}/bot{token}/sendMessage"),
                body: json(payload),
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
            Request::Http {
                url: format!("{}/api/v2/alerts", c.url.trim_end_matches('/')),
                body: json(&alerts),
                headers: Vec::new(),
                auth,
                redact: Vec::new(),
            }
        }
        ChannelConfig::Webhook(c) => {
            let body = json(payload);
            let mut headers = Vec::new();
            if let Some(var) = &c.secret_env {
                let secret = need(var)?;
                headers.push((
                    webhook::SIGNATURE_HEADER,
                    webhook::signature(&secret, &body),
                ));
            }
            Request::Http {
                url: need(&c.url_env)?,
                body,
                headers,
                auth: None,
                redact: Vec::new(),
            }
        }
        ChannelConfig::Email(c) => Request::Email(Box::new(email::message(c, payload)?)),
    })
}
