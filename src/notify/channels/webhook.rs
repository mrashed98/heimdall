//! Generic webhook: the neutral alert model as JSON, optionally signed.
//!
//! Every request carries `X-Heimdall-Timestamp: <unix seconds>`. With a
//! secret, it also carries `X-Heimdall-Signature: sha256=<hex>`, the
//! HMAC-SHA256 of `"{timestamp}.{raw body}"`, so a receiver can reject both
//! forged and replayed requests (by checking the timestamp is recent).

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::notify::alert::Alert;

pub(crate) const SIGNATURE_HEADER: &str = "X-Heimdall-Signature";
pub(crate) const TIMESTAMP_HEADER: &str = "X-Heimdall-Timestamp";

/// `{"version": 1, "alert": {...}}`.
pub fn render(a: &Alert) -> Value {
    json!({"version": 1, "alert": a})
}

/// Hex HMAC-SHA256 of `msg` keyed with `secret`.
pub fn hmac_hex(secret: &str, msg: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    mac.update(msg);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `sha256=<hex>` of the HMAC-SHA256 of `"{timestamp}.{body}"`.
pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut msg = format!("{timestamp}.").into_bytes();
    msg.extend_from_slice(body);
    format!("sha256={}", hmac_hex(secret, &msg))
}
