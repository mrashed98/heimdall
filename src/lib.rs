use std::sync::Arc;

pub mod auth;
pub mod client;
pub mod config;
pub mod db;
pub mod error;
pub mod ingest;
pub mod inventory;
pub mod model;
pub mod purl;
pub mod server;
pub mod version;

/// Shared state for every HTTP handler (axum router state).
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub cfg: Arc<config::HeimdallConfig>,
    pub http: reqwest::Client,
}
