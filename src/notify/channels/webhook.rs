//! Generic webhook: the neutral alert model as JSON, optionally signed.
//!
//! With a secret, every request carries
//! `X-Heimdall-Signature: sha256=<hex HMAC-SHA256 of the raw body>`.

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::notify::alert::Alert;

pub(crate) const SIGNATURE_HEADER: &str = "X-Heimdall-Signature";

/// `{"version": 1, "alert": {...}}`.
pub fn render(a: &Alert) -> Value {
    json!({"version": 1, "alert": a})
}

/// `sha256=<hex>` of the HMAC-SHA256 of `body` keyed with `secret`.
pub fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256={hex}")
}
