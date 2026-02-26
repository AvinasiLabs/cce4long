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

    // 4. Issue credential
    let credential = state.credential_service.issue("job-e2e", "alice", vec![1]);

    // 5. Build and run agent
    // The algorithm script reads data and writes output
    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
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
}

#[tokio::test]
async fn lifecycle_key_failure_aborts() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());
    let pp_url = start_pp_server(state.clone()).await;

    // Tampered credential → key acquisition fails
    let mut credential = state.credential_service.issue("job-1", "alice", vec![1]);
    credential.job_id = "tampered".to_string();

    let output_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();

    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
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
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data_dir.path().join("1")).unwrap();
    let output_dir = tempfile::tempdir().unwrap();

    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
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
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data_dir.path().join("1")).unwrap();
    let output_dir = tempfile::tempdir().unwrap();

    let mut agent = Agent::new(
        DevAttester,
        PpClient::new(&pp_url),
        credential,
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
