use std::sync::Arc;

pub mod auth;
pub mod client;
pub mod config;
pub mod db;
pub mod error;
pub mod gate;
pub mod ingest;
pub mod inventory;
pub mod matcher;
pub mod meters;
pub mod model;
pub mod notify;
pub mod oath;
pub mod purl;
pub mod retention;
pub mod scan_images;
pub mod scheduler;
pub mod server;
pub mod telemetry;
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
}

impl AppState {
    pub fn new(
        pool: sqlx::PgPool,
        cfg: Arc<config::HeimdallConfig>,
        http: reqwest::Client,
    ) -> AppState {
        AppState {
            pool,
            cfg,
            http,
            uploads: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPLOADS)),
        }
    }
}
