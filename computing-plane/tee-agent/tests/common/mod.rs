#![allow(dead_code)]

use std::sync::Arc;

use key_manager::DatasetId;
use cced::dataset_store::InMemoryDatasetStore;
use cced::state::AppState;

use tee_agent::lifecycle::Agent;
use tee_agent::{CocoAttester, PpClient};

pub fn dev_root_key() -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, b"cce4long-dev-root-key");
    let mut key = [0u8; 32];
    hk.expand(b"dev-root", &mut key).expect("valid length");
    key
}

pub fn dev_state() -> Arc<AppState> {
    Arc::new(
        AppState::new(
            &dev_root_key(),
            Box::new(InMemoryDatasetStore::new()),
            tee_verifier::TeeVerifier::new()
                .register(tee_verifier::TeeType::Sample, tee_verifier::SampleVerifier),
        )
        .unwrap(),
    )
}

pub fn test_id(val: u8) -> DatasetId {
    DatasetId::from([val; 20])
}

pub async fn start_pp_server(state: Arc<AppState>) -> String {
    let app = cced::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

pub fn key_agent(
    pp_url: &str,
    credential: compute_controller::JobCredential,
    dataset_ids: Vec<DatasetId>,
) -> Agent<
    CocoAttester,
    decrypt_fs::InPlaceDecryptBackend,
    executor::SubprocessRunner,
> {
    let submit_credential = serde_json::from_value(serde_json::json!({
        "version": 1,
        "job_id": "unused",
        "user": "unused",
        "datasets": [],
        "nonce": "00000000000000000000000000000000",
        "issued_at": 1000000,
        "expires_at": 9999999999u64,
        "signature": "aa"
    })).unwrap();

    Agent::new(
        CocoAttester::new().unwrap(),
        PpClient::new(pp_url),
        credential,
        submit_credential,
        dataset_ids,
        "/tmp/data".to_string(),
        "/tmp/output".to_string(),
        decrypt_fs::InPlaceDecryptBackend,
        executor::SubprocessRunner,
        executor::JobSpec {
            image: "true".to_string(),
            args: vec![],
            limits: executor::ResourceLimits::default(),
        },
    )
}
