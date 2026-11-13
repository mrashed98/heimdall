//! The HTTP router. Later tasks add their routes here.

use axum::Router;

use crate::{auth, ingest, AppState};

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(auth::routes())
        .merge(ingest::api::routes())
        .with_state(state)
}
