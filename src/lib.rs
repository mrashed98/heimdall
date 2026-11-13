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
pub mod model;
pub mod oath;
pub mod purl;
pub mod server;
pub mod version;
pub mod vuln;
pub mod watchers;

/// Shared state for every HTTP handler (axum router state).
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub cfg: Arc<config::HeimdallConfig>,
    pub http: reqwest::Client,
}
