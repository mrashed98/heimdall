use std::sync::Arc;

pub mod admin;
pub mod auth;
mod channels_api;
pub mod client;
pub mod config;
pub mod db;
pub mod egress;
pub mod error;
pub mod gate;
pub mod ingest;
pub mod inventory;
pub mod local_auth;
pub mod matcher;
pub mod meters;
pub mod model;
pub mod notify;
pub mod oath;
pub mod oidc;
pub mod purl;
pub mod retention;
pub mod scan_images;
pub mod scheduler;
pub mod secrets;
pub mod server;
pub mod telemetry;
pub mod trends;
pub mod ui;
pub mod version;
pub mod vuln;
pub mod watchers;

/// Uploads (SBOM ingest, image SBOM ingest, gate) handled at once. Each one
/// holds a parsed SBOM in memory; more wait their turn, so a burst of CI jobs
/// cannot push the 1 GB container out of memory.
pub const MAX_CONCURRENT_UPLOADS: usize = 2;

/// Shared state for every HTTP handler (axum router state).
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub cfg: Arc<config::HeimdallConfig>,
    pub http: reqwest::Client,
    /// `MAX_CONCURRENT_UPLOADS` permits; an upload handler holds one while
    /// it works. Shared by every clone of the state.
    pub uploads: Arc<tokio::sync::Semaphore>,
    pub grants_cache: Arc<local_auth::GrantCache>,
    pub oidc_rate:
        Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<std::time::Instant>>>>,
    pub oidc_metadata: Arc<tokio::sync::RwLock<Option<openidconnect::core::CoreProviderMetadata>>>,
    /// Seals UI-entered channel secrets; `None` when `HEIMDALL_SECRET_KEY`
    /// is unset or malformed.
    pub secret_key: Option<Arc<secrets::SecretKey>>,
    pub channel_tests: Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    /// The time handlers read. Tests fix it with `Clock::fixed`, so a result
    /// that depends on today does not change at midnight.
    pub clock: Clock,
}

/// Where handlers get the current time: the system clock, or a fixed
/// instant in tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct Clock(Option<chrono::DateTime<chrono::Utc>>);

impl Clock {
    pub fn fixed(at: chrono::DateTime<chrono::Utc>) -> Clock {
        Clock(Some(at))
    }
    pub fn now(self) -> chrono::DateTime<chrono::Utc> {
        #[allow(clippy::disallowed_methods)] // The one place the real clock is read.
        self.0.unwrap_or_else(chrono::Utc::now)
    }
}

impl AppState {
    pub fn new(
        pool: sqlx::PgPool,
        cfg: Arc<config::HeimdallConfig>,
        http: reqwest::Client,
    ) -> AppState {
        Self::with_grant_cache_ttl(pool, cfg, http, std::time::Duration::from_secs(30))
    }

    pub fn with_grant_cache_ttl(
        pool: sqlx::PgPool,
        cfg: Arc<config::HeimdallConfig>,
        http: reqwest::Client,
        ttl: std::time::Duration,
    ) -> AppState {
        AppState {
            pool,
            cfg,
            http,
            uploads: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
            grants_cache: Arc::new(local_auth::GrantCache::new(ttl)),
            oidc_rate: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            oidc_metadata: Arc::new(tokio::sync::RwLock::new(None)),
            secret_key: secrets::SecretKey::from_env().map(Arc::new),
            channel_tests: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            clock: Clock::default(),
        }
    }
}
