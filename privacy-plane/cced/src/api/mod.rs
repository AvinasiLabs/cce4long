pub mod error;
pub mod upload;

use axum::routing::post;
use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/datasets/{dataset_id}/upload", post(upload::upload_dataset))
        .with_state(state)
}
