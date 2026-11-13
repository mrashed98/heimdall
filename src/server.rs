//! The HTTP router. Later tasks add their routes here.

use axum::Router;

use crate::{auth, ingest, oath, AppState};

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(auth::routes())
        .merge(ingest::api::routes())
        .merge(oath::routes())
        .with_state(state)
}
