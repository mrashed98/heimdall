//! AES-256-GCM sealing for secrets stored in Postgres (UI-entered alert
//! channel credentials). The key comes from `HEIMDALL_SECRET_KEY`: 32 bytes,
//! standard base64. A sealed value is a random 12-byte nonce followed by the
//! ciphertext and tag; the AAD binds it to where it is stored.

use anyhow::{anyhow, bail};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};

pub const ENV_VAR: &str = "HEIMDALL_SECRET_KEY";

/// The secret-sealing key. Deliberately has no `Debug` that prints the key.
pub struct SecretKey {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// Standard base64 of exactly 32 bytes. Errors never include the input.
    pub fn parse(b64: &str) -> anyhow::Result<SecretKey> {
        let bytes = STANDARD
            .decode(b64.trim())
            .map_err(|_| anyhow!("{ENV_VAR} is not valid standard base64"))?;
        if bytes.len() != 32 {
            bail!("{ENV_VAR} must decode to 32 bytes, got {}", bytes.len());
        }
        let unbound = UnboundKey::new(&AES_256_GCM, &bytes)
            .map_err(|_| anyhow!("{ENV_VAR} rejected by AES-256-GCM"))?;
        Ok(SecretKey {
            key: LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        })
    }

    /// Unset or empty → `None`; malformed → logged (without the value), `None`.
    pub fn from_env() -> Option<SecretKey> {
        let raw = std::env::var(ENV_VAR).ok()?;
        if raw.trim().is_empty() {
            return None;
        }
        match SecretKey::parse(&raw) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::error!(error = %e, "{ENV_VAR} is malformed; UI-managed channel secrets are disabled");
                None
            }
        }
    }

    /// Returns nonce || ciphertext || tag.
    pub fn seal(&self, aad: &str, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce)
            .expect("system RNG failed to produce a nonce");
        let mut buf = plain.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_bytes()),
                &mut buf,
            )
            .expect("AES-GCM seal cannot fail for in-range input");
        let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        out
    }

    pub fn open(&self, aad: &str, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + AES_256_GCM.tag_len() {
            bail!("sealed secret is too short");
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow!("bad nonce"))?;
        let mut buf = ct.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf)
            .map_err(|_| anyhow!("sealed secret failed to decrypt (wrong key or context)"))?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::parse(&STANDARD.encode([byte; 32])).unwrap()
    }

    #[test]
    fn seal_open_round_trip() {
        let k = key(1);
        let sealed = k.seal("alert_channels:a", b"x");
        assert_eq!(k.open("alert_channels:a", &sealed).unwrap(), b"x");
    }

    #[test]
    fn open_fails_with_other_aad() {
        let k = key(1);
        let sealed = k.seal("alert_channels:a", b"x");
        assert!(k.open("alert_channels:b", &sealed).is_err());
    }

    #[test]
    fn open_fails_with_other_key() {
        let sealed = key(1).seal("alert_channels:a", b"x");
        assert!(key(2).open("alert_channels:a", &sealed).is_err());
    }

    #[test]
    fn seal_uses_fresh_nonce() {
        let k = key(1);
        assert_ne!(k.seal("aad", b"same"), k.seal("aad", b"same"));
    }

    #[test]
    fn parse_rejects_wrong_length_and_bad_base64() {
        assert!(SecretKey::parse(&STANDARD.encode([0u8; 31])).is_err());
        assert!(SecretKey::parse("not base64!").is_err());
        assert!(SecretKey::parse(&STANDARD.encode([0u8; 32])).is_ok());
    }
}
