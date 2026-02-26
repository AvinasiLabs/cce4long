use std::sync::Arc;

use cced::state::AppState;
use cced::storage::LocalStorage;

use tee_agent::lifecycle::Agent;
use tee_agent::{DevAttester, PpClient};

fn dev_state(dir: &str) -> Arc<AppState> {
    let storage = Box::new(LocalStorage::new(dir));
    Arc::new(AppState::dev(storage))
}

/// Start an in-process HTTP server on a random port, return the base URL.
async fn start_pp_server(state: Arc<AppState>) -> String {
    let app = cced::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Helper to build an Agent for key-acquisition-only tests.
fn key_agent(
    pp_url: &str,
    credential: compute_controller::JobCredential,
    dataset_ids: Vec<u64>,
) -> Agent<
    tee_agent::DevAttester,
    decrypt_fs::DevMountBackend,
    executor::DevRunner,
> {
    Agent::new(
        DevAttester,
        PpClient::new(pp_url),
        credential,
        dataset_ids,
        "/tmp/data".to_string(),
        "/tmp/output".to_string(),
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        executor::JobSpec {
            image: "true".to_string(),
            args: vec![],
            limits: executor::ResourceLimits::default(),
        },
    )
}

#[tokio::test]
async fn acquire_keys_success() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let credential = state.credential_service.issue("job-42", "alice", vec![1, 2]);
    let agent = key_agent(&pp_url, credential, vec![1, 2]);

    let keys = agent.acquire_keys().await.unwrap();

    assert_eq!(keys.deks.len(), 2);
    let expected_dek1 = state.key_manager.derive_dek(1).unwrap();
    let expected_dek2 = state.key_manager.derive_dek(2).unwrap();
    assert_eq!(keys.deks[&1].0, expected_dek1.0);
    assert_eq!(keys.deks[&2].0, expected_dek2.0);

    let expected_rek = state.key_manager.derive_rek("job-42").unwrap();
    assert_eq!(keys.rek.0, expected_rek.0);
}

#[tokio::test]
async fn acquire_keys_dek_values_consistent_with_pp() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let credential = state
        .credential_service
        .issue("job-single", "alice", vec![42]);
    let agent = key_agent(&pp_url, credential, vec![42]);

    let keys = agent.acquire_keys().await.unwrap();
    assert_eq!(keys.deks.len(), 1);

    let expected = state.key_manager.derive_dek(42).unwrap();
    assert_eq!(keys.deks[&42].0, expected.0);
}

#[tokio::test]
async fn acquire_keys_rek_matches_job_id() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let credential = state
        .credential_service
        .issue("my-special-job", "alice", vec![1]);
    let agent = key_agent(&pp_url, credential, vec![1]);

    let keys = agent.acquire_keys().await.unwrap();
    let expected_rek = state.key_manager.derive_rek("my-special-job").unwrap();
    assert_eq!(keys.rek.0, expected_rek.0);
}

#[tokio::test]
async fn acquire_keys_invalid_credential_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let mut credential = state.credential_service.issue("job-1", "alice", vec![1]);
    credential.job_id = "tampered".to_string();

    let agent = key_agent(&pp_url, credential, vec![1]);
    let err = agent.acquire_keys().await.unwrap_err();
    assert!(err.to_string().contains("PP returned"));
}

#[tokio::test]
async fn acquire_keys_unauthorized_dataset_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let credential = state.credential_service.issue("job-1", "alice", vec![1, 2]);
    let agent = key_agent(&pp_url, credential, vec![1, 99]);

    let err = agent.acquire_keys().await.unwrap_err();
    assert!(err.to_string().contains("PP returned"));
}

#[tokio::test]
async fn acquire_keys_expired_credential_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let mut credential = state.credential_service.issue("job-1", "alice", vec![1]);
    credential.expires_at = 0;

    let agent = key_agent(&pp_url, credential, vec![1]);
    let err = agent.acquire_keys().await.unwrap_err();
    assert!(err.to_string().contains("PP returned"));
}

#[tokio::test]
async fn acquire_keys_error_propagation() {
    let agent = key_agent(
        "http://127.0.0.1:1",
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "job_id": "j",
            "user": "u",
            "datasets": [1],
            "nonce": "00000000000000000000000000000000",
            "issued_at": 1000000,
            "expires_at": 9999999999u64,
            "signature": "aa"
        }))
        .unwrap(),
        vec![1],
    );

    let err = agent.acquire_keys().await.unwrap_err();
    assert!(err.to_string().contains("PP request failed"));
}
