//! HTTP client used by the CLI subcommands to talk to the server.

use anyhow::{bail, Context};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct Client {
    base: String,
    key: String,
    http: reqwest::Client,
}

impl Client {
    /// Reads `HEIMDALL_URL` and `HEIMDALL_API_KEY`.
    pub fn from_env() -> anyhow::Result<Client> {
        let base = std::env::var("HEIMDALL_URL")
            .context("HEIMDALL_URL is not set (e.g. http://heimdall.internal:8080)")?;
        let key = std::env::var("HEIMDALL_API_KEY").context("HEIMDALL_API_KEY is not set")?;
        Ok(Client {
            base: base.trim_end_matches('/').to_string(),
            key,
            http: reqwest::Client::new(),
        })
    }

    /// A client for an explicit server URL (e.g. Sight's `--push`).
    pub fn new(base: &str, key: String) -> Client {
        Client {
            base: base.trim_end_matches('/').to_string(),
            key,
            http: reqwest::Client::new(),
        }
    }

    /// Bound every request made through this client (connect to body).
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> anyhow::Result<Client> {
        self.http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("building http client")?;
        Ok(self)
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let req = self.http.get(self.url(path));
        self.send(req).await
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        let req = self.http.post(self.url(path)).json(body);
        self.send(req).await
    }

    /// Percent-encode one path segment so names cannot alter the route.
    pub fn encode_segment(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    pub async fn delete(&self, path: &str) -> anyhow::Result<()> {
        let req = self.http.delete(self.url(path));
        let _: serde_json::Value = self.send(req).await?;
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn send<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> anyhow::Result<T> {
        let resp = req
            .bearer_auth(&self.key)
            .send()
            .await
            .context("calling the Heimdall server")?;
        let status = resp.status();
        if !status.is_success() {
            // The server sends {"error": "..."}; fall back to the raw text.
            let text = resp.text().await.unwrap_or_default();
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(String::from))
                .unwrap_or(text);
            bail!("server returned {status}: {msg}");
        }
        resp.json().await.context("decoding server response")
    }
}
