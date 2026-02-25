pub mod error;
pub mod request_keys;
pub mod upload;

use axum::routing::post;
use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/datasets/{dataset_id}/upload", post(upload::upload_dataset))
        .route("/v1/keys/request", post(request_keys::request_keys))
        .with_state(state)
}
