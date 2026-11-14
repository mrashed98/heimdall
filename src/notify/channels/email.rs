//! Email formatter and SMTP delivery (lettre, rustls only).
//!
//! The queued payload is `{"subject", "text", "html"}`; sender and
//! recipients come from the channel config when the message is built, and
//! SMTP credentials from the environment when it is sent.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::{json, Value};

use crate::config::{EmailChannel, SmtpSecurity};
use crate::notify::alert::{body_lines, severity_name, truncate, Alert, AlertKind, Markup};

/// Entries and section rows shown before "and N more".
const MAX_ROWS: usize = 50;
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

fn plain(s: &str) -> String {
    s.to_string()
}

fn plain_link(text: &str, url: &str) -> String {
    format!("{text} <{url}>")
}

const PLAIN: Markup = Markup {
    escape: plain,
    bold: plain,
    link: plain_link,
};

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_bold(s: &str) -> String {
    format!("<strong>{}</strong>", html_escape(s))
}

fn html_link(text: &str, url: &str) -> String {
    format!("<a href=\"{}\">{}</a>", html_escape(url), html_escape(text))
}

const HTML: Markup = Markup {
    escape: html_escape,
    bold: html_bold,
    link: html_link,
};

pub fn render(a: &Alert) -> Value {
    // One line, no control characters: it becomes a header.
    let title: String = a.title.chars().filter(|c| !c.is_control()).collect();
    let subject = truncate(&format!("[Heimdall] {title}"), 200);

    let mut text = vec![a.title.clone()];
    if matches!(a.kind, AlertKind::Finding(_)) {
        text.push(format!("Severity: {}", severity_name(a.severity)));
    }
    text.push(String::new());
    text.extend(body_lines(a, &PLAIN, MAX_ROWS));
    if !a.links.is_empty() {
        text.push(String::new());
        text.extend(a.links.iter().map(|l| format!("{}: {}", l.title, l.url)));
    }

    let mut html = format!(
        "<!DOCTYPE html>\n<html><body style=\"font-family: sans-serif;\">\n<h2>{}</h2>\n",
        html_escape(&a.title)
    );
    if matches!(a.kind, AlertKind::Finding(_)) {
        html.push_str(&format!(
            "<p>Severity: <strong>{}</strong></p>\n",
            severity_name(a.severity)
        ));
    }
    html.push_str("<p>\n");
    for l in body_lines(a, &HTML, MAX_ROWS) {
        if l.is_empty() {
            html.push_str("</p>\n<p>\n");
        } else {
            html.push_str(&l);
            html.push_str("<br>\n");
        }
    }
    html.push_str("</p>\n");
    if !a.links.is_empty() {
        let links: Vec<String> = a
            .links
            .iter()
            .map(|l| html_link(&l.title, &l.url))
            .collect();
        html.push_str(&format!("<p>{}</p>\n", links.join(" · ")));
    }
    html.push_str("</body></html>\n");

    json!({"subject": subject, "text": text.join("\n") + "\n", "html": html})
}

/// The message for a queued payload: multipart/alternative, plain text
/// first, HTML second.
pub fn message(ch: &EmailChannel, payload: &Value) -> anyhow::Result<Message> {
    let field = |k: &str| {
        payload[k]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("not an email payload: no `{k}`"))
    };
    let from: Mailbox = ch.from.parse()?;
    let mut b = Message::builder().from(from).subject(field("subject")?);
    for to in &ch.to {
        b = b.to(to.parse::<Mailbox>()?);
    }
    let body = MultiPart::alternative()
        .singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(field("text")?.to_string()),
        )
        .singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_HTML)
                .body(field("html")?.to_string()),
        );
    Ok(b.multipart(body)?)
}

/// Why a mail was not sent.
#[derive(Debug, Clone, PartialEq)]
pub enum MailError {
    /// Worth retrying: a 4xx reply, a network or TLS failure, a timeout.
    Transient(String),
    /// The server refused it for good (a 5xx reply): retrying would fail again.
    Permanent(String),
}

/// Sends mail. Behind a trait so the outbox can be tested without a server.
pub trait Mailer: Send + Sync {
    fn send<'a>(
        &'a self,
        ch: &'a EmailChannel,
        msg: Message,
    ) -> Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + 'a>>;
}

/// The real mailer: one SMTP connection per message (the outbox sends at
/// most one message every 2 s, so pooling buys nothing).
pub struct SmtpMailer;

impl Mailer for SmtpMailer {
    fn send<'a>(
        &'a self,
        ch: &'a EmailChannel,
        msg: Message,
    ) -> Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + 'a>> {
        Box::pin(async move {
            let transport = transport(ch).map_err(|e| MailError::Transient(e.to_string()))?;
            transport.send(msg).await.map(|_| ()).map_err(|e| {
                if e.is_permanent() {
                    MailError::Permanent(e.to_string())
                } else {
                    MailError::Transient(e.to_string())
                }
            })
        })
    }
}

fn transport(ch: &EmailChannel) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let mut b = match ch.security {
        // STARTTLS is required, never opportunistic: no silent downgrade.
        SmtpSecurity::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&ch.host)?,
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&ch.host)?,
        SmtpSecurity::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&ch.host),
    }
    .port(ch.port())
    .timeout(Some(SEND_TIMEOUT));
    if let (Some(u), Some(p)) = (&ch.username_env, &ch.password_env) {
        let user = std::env::var(u).map_err(|_| anyhow::anyhow!("{u} is not set"))?;
        let pass = std::env::var(p).map_err(|_| anyhow::anyhow!("{p} is not set"))?;
        b = b.credentials(Credentials::new(user, pass));
    }
    Ok(b.build())
}
