mod common;

use tee_agent::lifecycle::Agent;
use tee_agent::{CocoAttester, PpClient};

use common::{dev_state, start_pp_server, test_id};

#[tokio::test]
async fn full_lifecycle_success() {
    let state = dev_state();
    let pp_url = start_pp_server(state.clone()).await;

    let ds = test_id(0x01);
    let wallet = test_id(0xAA);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);
    let test_data = b"col1,col2\nfoo,42\nbar,99";
    let app = cced::api::router(state.clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(axum::body::Body::from(test_data.to_vec()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let data_dir = tempfile::tempdir().unwrap();
    let dataset_dir = data_dir.path().join(ds.to_string());
    std::fs::create_dir_all(&dataset_dir).unwrap();

    let avin_data = state
        .dataset_store
        .get_file(&ds, "data.csv.avin")
        .await
        .unwrap();
    std::fs::write(dataset_dir.join("data.csv.avin"), &avin_data).unwrap();

    let output_dir = tempfile::tempdir().unwrap();

    let credential = state.credential_service.issue("job-e2e", "alice", vec![ds]);
    let submit_credential = state.credential_service.issue("job-e2e", "alice", vec![ds]);

    let attester = CocoAttester::new().unwrap();
    let mut agent = Agent::new(
        attester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![ds],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::InPlaceDecryptBackend,
        executor::SubprocessRunner,
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

    assert_eq!(result.execution.exit_code, 0);

    assert_eq!(result.encrypted_files.len(), 1);
    assert_eq!(result.encrypted_files[0].filename, "result.txt");

    let rek = state.key_manager.derive_rek("job-e2e").unwrap();
    let decrypted = decrypt_fs::decrypt_avin(&rek, &result.encrypted_files[0].data).unwrap();
    let output_text = String::from_utf8(decrypted).unwrap();
    assert!(output_text.contains("computation complete"));

    assert_eq!(result.submit_status, "approved");
}

#[tokio::test]
async fn lifecycle_key_failure_aborts() {
    let state = dev_state();
    let pp_url = start_pp_server(state.clone()).await;

    let ds = test_id(0x01);

    let mut credential = state.credential_service.issue("job-1", "alice", vec![ds]);
    credential.job_id = "tampered".to_string();
    let submit_credential = state.credential_service.issue("job-1", "alice", vec![ds]);

    let output_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();

    let attester = CocoAttester::new().unwrap();
    let mut agent = Agent::new(
        attester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![ds],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::InPlaceDecryptBackend,
        executor::SubprocessRunner,
        executor::JobSpec {
            image: "echo".to_string(),
            args: vec!["should-not-run".to_string()],
            limits: executor::ResourceLimits::default(),
        },
    );

    let err = agent.run().await.unwrap_err();
    assert!(err.to_string().contains("PP returned"));

    assert!(std::fs::read_dir(output_dir.path()).unwrap().count() == 0);
}

#[tokio::test]
async fn lifecycle_execution_failure_aborts() {
    let state = dev_state();
    let pp_url = start_pp_server(state.clone()).await;

    let ds = test_id(0x01);
    let credential = state
        .credential_service
        .issue("job-fail", "alice", vec![ds]);
    let submit_credential = state
        .credential_service
        .issue("job-fail", "alice", vec![ds]);
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data_dir.path().join(ds.to_string())).unwrap();
    let output_dir = tempfile::tempdir().unwrap();

    let attester = CocoAttester::new().unwrap();
    let mut agent = Agent::new(
        attester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![ds],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::InPlaceDecryptBackend,
        executor::SubprocessRunner,
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
    let state = dev_state();
    let pp_url = start_pp_server(state.clone()).await;

    let ds = test_id(0x01);
    let credential = state.credential_service.issue("job-enc", "alice", vec![ds]);
    let submit_credential = state.credential_service.issue("job-enc", "alice", vec![ds]);
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data_dir.path().join(ds.to_string())).unwrap();
    let output_dir = tempfile::tempdir().unwrap();

    let attester = CocoAttester::new().unwrap();
    let mut agent = Agent::new(
        attester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![ds],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::InPlaceDecryptBackend,
        executor::SubprocessRunner,
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

    let raw = &result.encrypted_files[0].data;
    assert!(raw.starts_with(b"AVIN"));

    let rek = state.key_manager.derive_rek("job-enc").unwrap();
    let decrypted = decrypt_fs::decrypt_avin(&rek, raw).unwrap();
    assert!(String::from_utf8_lossy(&decrypted).contains("secret_result"));

    let wrong_key = key_manager::Key([0xFF; 32]);
    assert!(decrypt_fs::decrypt_avin(&wrong_key, raw).is_err());
}

#[tokio::test]
async fn full_lifecycle_with_submit() {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let state = dev_state();
    let pp_url = start_pp_server(state.clone()).await;

    let ds = test_id(0x01);
    let wallet = test_id(0xAA);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);
    let app = cced::api::router(state.clone());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(axum::body::Body::from(b"test data".to_vec()))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let data_dir = tempfile::tempdir().unwrap();
    let dataset_dir = data_dir.path().join(ds.to_string());
    std::fs::create_dir_all(&dataset_dir).unwrap();

    let avin_data = state
        .dataset_store
        .get_file(&ds, "data.csv.avin")
        .await
        .unwrap();
    std::fs::write(dataset_dir.join("data.csv.avin"), &avin_data).unwrap();

    let output_dir = tempfile::tempdir().unwrap();

    let credential = state
        .credential_service
        .issue("job-submit", "alice", vec![ds]);
    let submit_credential = state
        .credential_service
        .issue("job-submit", "alice", vec![ds]);

    let attester = CocoAttester::new().unwrap();
    let mut agent = Agent::new(
        attester,
        PpClient::new(&pp_url),
        credential,
        submit_credential,
        vec![ds],
        data_dir.path().to_str().unwrap().to_string(),
        output_dir.path().to_str().unwrap().to_string(),
        decrypt_fs::InPlaceDecryptBackend,
        executor::SubprocessRunner,
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
        .body(axum::body::Body::from(
            serde_json::to_vec(&get_body).unwrap(),
        ))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp_json["status"].as_str().unwrap(), "approved");
    assert!(!resp_json["result_hash"].as_str().unwrap().is_empty());

    let ciphertext = hex::decode(resp_json["encrypted_rek"].as_str().unwrap()).unwrap();
    let nonce_bytes = hex::decode(resp_json["nonce"].as_str().unwrap()).unwrap();
    let pp_pk_bytes = hex::decode(resp_json["pp_pk"].as_str().unwrap()).unwrap();

    let bundle = key_manager::ecdhe::WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes.try_into().unwrap(),
        pp_pk: pp_pk_bytes.try_into().unwrap(),
    };

    let (deks, rek) = key_manager::ecdhe::unwrap_keys(&bundle, &user_secret).unwrap();
    assert_eq!(deks.len(), 0);

    let expected_rek = state.key_manager.derive_rek("job-submit").unwrap();
    assert_eq!(rek.0, expected_rek.0);

    let encrypted = &result.encrypted_files[0].data;
    let decrypted = decrypt_fs::decrypt_avin(&rek, encrypted).unwrap();
    let text = String::from_utf8(decrypted).unwrap();
    assert!(text.contains("hello from TEE"));
}
