pub mod auth;
pub mod create_job;
pub mod error;
pub mod finalize;
pub mod get_result;
pub mod request_keys;
pub mod submit_result;
pub mod upload;

use axum::Router;
use axum::routing::post;
use std::sync::Arc;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/upload-token", post(auth::issue_upload_token))
        .route(
            "/v1/datasets/{dataset_id}/upload/{*path}",
            post(upload::upload_dataset),
        )
        .route(
            "/v1/datasets/{dataset_id}/finalize",
            post(finalize::finalize_dataset),
        )
        .route("/v1/keys/request", post(request_keys::request_keys))
        .route("/v1/results/submit", post(submit_result::submit_result))
        .route("/v1/results/{job_id}", post(get_result::get_result))
        .route("/v1/jobs/create", post(create_job::create_job))
        .with_state(state)
}
