use std::sync::Arc;

use cced::state::AppState;
use cced::storage::LocalStorage;

use tee_agent::lifecycle::Agent;
use tee_agent::{DevAttester, PpClient};

fn dev_state(dir: &str) -> Arc<AppState> {
    let storage = Box::new(LocalStorage::new(dir));
    Arc::new(AppState::dev(storage))
}

async fn start_pp_server(state: Arc<AppState>) -> String {
    let app = cced::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Upload test data via PP, then run the full agent lifecycle.
#[tokio::test]
async fn full_lifecycle_success() {
    let tmp_storage = tempfile::tempdir().unwrap();
    let state = dev_state(tmp_storage.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    // 1. Upload test data to PP → creates .avin encrypted files
    let test_data = b"col1,col2\nfoo,42\nbar,99";
    let app = cced::api::router(state.clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/datasets/1/upload")
        .body(axum::body::Body::from(test_data.to_vec()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // 2. Set up data_dir pointing to PP's storage (where .avin files live)
    let data_dir = tempfile::tempdir().unwrap();
    let dataset_dir = data_dir.path().join("1");
    std::fs::create_dir_all(&dataset_dir).unwrap();

    // Copy the .avin file from PP storage to agent's data dir
    let avin_path = tmp_storage.path().join("1.avin");
    std::fs::copy(&avin_path, dataset_dir.join("1.avin")).unwrap();

    // 3. Set up output_dir
    let output_dir = tempfile::tempdir().unwrap();

    // 4. Issue credentials (separate nonces for key request and submit)
    let credential = state.credential_service.issue("job-e2e", "alice", vec![1]);
    let submit_credential = state.credential_service.issue("job-e2e", "alice", vec![1]);

    // 5. Build and run agent
    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![1],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        executor::JobSpec {
            image: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "echo 'computation complete' > $OUTPUT_DIR/result.txt".to_string(),
            ],
            limits: executor::ResourceLimits::default(),
        },
    );

    let result = agent.run().await.unwrap();

    // 6. Verify execution succeeded
    assert_eq!(result.execution.exit_code, 0);

    // 7. Verify encrypted output is valid
    assert_eq!(result.encrypted_files.len(), 1);
    assert_eq!(result.encrypted_files[0].filename, "result.txt");

    // 8. Verify REK can decrypt the output
    let rek = state.key_manager.derive_rek("job-e2e").unwrap();
    let decrypted =
        decrypt_fs::decrypt_avin(&rek, &result.encrypted_files[0].data).unwrap();
    let output_text = String::from_utf8(decrypted).unwrap();
    assert!(output_text.contains("computation complete"));

    // 9. Verify result was submitted and approved
    assert_eq!(result.submit_status, "approved");
}

#[tokio::test]
async fn lifecycle_key_failure_aborts() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    // Tampered credential → key acquisition fails
    let mut credential = state.credential_service.issue("job-1", "alice", vec![1]);
    credential.job_id = "tampered".to_string();
    let submit_credential = state.credential_service.issue("job-1", "alice", vec![1]);

    let output_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();

    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![1],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        executor::JobSpec {
            image: "echo".to_string(),
            args: vec!["should-not-run".to_string()],
            limits: executor::ResourceLimits::default(),
        },
    );

    let err = agent.run().await.unwrap_err();
    assert!(err.to_string().contains("PP returned"));

    // Verify algorithm was never executed (no output files)
    assert!(std::fs::read_dir(output_dir.path()).unwrap().count() == 0);
}

#[tokio::test]
async fn lifecycle_execution_failure_aborts() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let credential = state.credential_service.issue("job-fail", "alice", vec![1]);
    let submit_credential = state.credential_service.issue("job-fail", "alice", vec![1]);
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data_dir.path().join("1")).unwrap();
    let output_dir = tempfile::tempdir().unwrap();

    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![1],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        executor::JobSpec {
            image: "/nonexistent/command/xyzzy".to_string(),
            args: vec![],
            limits: executor::ResourceLimits::default(),
        },
    );

    let err = agent.run().await.unwrap_err();
    assert!(err.to_string().contains("execution failed"));
}

#[tokio::test]
async fn lifecycle_result_encryption_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    let credential = state.credential_service.issue("job-enc", "alice", vec![1]);
    let submit_credential = state.credential_service.issue("job-enc", "alice", vec![1]);
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data_dir.path().join("1")).unwrap();
    let output_dir = tempfile::tempdir().unwrap();

    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![1],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        executor::JobSpec {
            image: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "echo secret_result > $OUTPUT_DIR/out.txt".to_string(),
            ],
            limits: executor::ResourceLimits::default(),
        },
    );

    let result = agent.run().await.unwrap();
    assert!(!result.encrypted_files.is_empty());

    // Encrypted file should NOT be readable as plaintext
    let raw = &result.encrypted_files[0].data;
    assert!(raw.starts_with(b"AVIN"));

    // But should be decryptable with the correct REK
    let rek = state.key_manager.derive_rek("job-enc").unwrap();
    let decrypted = decrypt_fs::decrypt_avin(&rek, raw).unwrap();
    assert!(String::from_utf8_lossy(&decrypted).contains("secret_result"));

    // Wrong key should fail
    let wrong_key = key_manager::Key([0xFF; 32]);
    assert!(decrypt_fs::decrypt_avin(&wrong_key, raw).is_err());
}

/// Full end-to-end lifecycle with submit → get_result → ECDHE unwrap REK → decrypt → verify
#[tokio::test]
async fn full_lifecycle_with_submit() {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let tmp_storage = tempfile::tempdir().unwrap();
    let state = dev_state(tmp_storage.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    // 1. Upload test data
    let app = cced::api::router(state.clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/datasets/1/upload")
        .body(axum::body::Body::from(b"test data".to_vec()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // 2. Set up data dir
    let data_dir = tempfile::tempdir().unwrap();
    let dataset_dir = data_dir.path().join("1");
    std::fs::create_dir_all(&dataset_dir).unwrap();
    let avin_path = tmp_storage.path().join("1.avin");
    std::fs::copy(&avin_path, dataset_dir.join("1.avin")).unwrap();

    // 3. Set up output dir
    let output_dir = tempfile::tempdir().unwrap();

    // 4. Issue credentials
    let credential = state.credential_service.issue("job-submit", "alice", vec![1]);
    let submit_credential = state.credential_service.issue("job-submit", "alice", vec![1]);

    // 5. Run agent lifecycle (includes submit)
    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![1],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        executor::JobSpec {
            image: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "echo 'hello from TEE' > $OUTPUT_DIR/result.txt".to_string(),
            ],
            limits: executor::ResourceLimits::default(),
        },
    );

    let result = agent.run().await.unwrap();
    assert_eq!(result.submit_status, "approved");

    // 6. Consumer: get_result via PP
    let user_secret = StaticSecret::random_from_rng(OsRng);
    let user_pk = PublicKey::from(&user_secret);

    let get_body = serde_json::json!({
        "user_eph_pk": hex::encode(user_pk.as_bytes()),
    });

    let app = cced::api::router(state.clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/results/job-submit")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&get_body).unwrap()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // 7. Parse response
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp_json["status"].as_str().unwrap(), "approved");
    assert!(!resp_json["result_hash"].as_str().unwrap().is_empty());

    // 8. Unwrap REK via ECDHE
    let ciphertext = hex::decode(resp_json["encrypted_rek"].as_str().unwrap()).unwrap();
    let nonce_bytes = hex::decode(resp_json["nonce"].as_str().unwrap()).unwrap();
    let pp_pk_bytes = hex::decode(resp_json["pp_pk"].as_str().unwrap()).unwrap();

    let bundle = key_manager::ecdhe::WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes.try_into().unwrap(),
        pp_pk: pp_pk_bytes.try_into().unwrap(),
    };

    let (deks, rek) = key_manager::ecdhe::unwrap_keys(&bundle, &user_secret).unwrap();
    assert_eq!(deks.len(), 0); // No DEKs, only REK

    // 9. Verify REK matches what PP would derive
    let expected_rek = state.key_manager.derive_rek("job-submit").unwrap();
    assert_eq!(rek.0, expected_rek.0);

    // 10. Decrypt the encrypted output with the REK
    let encrypted = &result.encrypted_files[0].data;
    let decrypted = decrypt_fs::decrypt_avin(&rek, encrypted).unwrap();
    let text = String::from_utf8(decrypted).unwrap();
    assert!(text.contains("hello from TEE"));
}
