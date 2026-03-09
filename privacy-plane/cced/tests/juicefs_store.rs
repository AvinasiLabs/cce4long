//! Integration tests for JuiceFsDatasetStore using real JuiceFS Gateway + Redis
//! via testcontainers.
//!
//! Tests auto-skip when Docker is unavailable — no manual `--ignored` needed.
//! Just run: cargo test -p cced --test juicefs_store

mod common;

use key_manager::DatasetId;
use std::time::Duration;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use cced::dataset_store::{
    DatasetMeta, DatasetReceipt, DatasetStatus, DatasetStore, DatasetStoreError, FileEntry,
    JuiceFsDatasetStore,
};

/// Check if Docker is available by pinging the daemon.
fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Skip the test (pass) if Docker is not available.
macro_rules! require_docker {
    () => {
        if !docker_available() {
            eprintln!("skipped: Docker not available");
            return;
        }
    };
}

struct JuiceFsTestEnv {
    store: JuiceFsDatasetStore,
    // Keep containers alive — they stop on drop.
    _redis: testcontainers::ContainerAsync<GenericImage>,
    _gateway: testcontainers::ContainerAsync<GenericImage>,
}

impl JuiceFsTestEnv {
    async fn start() -> Self {
        // 1. Start Redis
        //    GenericImage methods (with_exposed_port, with_wait_for, with_entrypoint)
        //    must be called before ImageExt methods (with_env_var, with_cmd) because
        //    ImageExt methods consume self and return ContainerRequest<I>.
        let redis = GenericImage::new("redis", "7-alpine")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await
            .expect("failed to start Redis container");

        let redis_host = redis.get_host().await.unwrap();
        let redis_port = redis.get_host_port_ipv4(6379).await.unwrap();
        let redis_url = format!("redis://{}:{}/1", redis_host, redis_port);

        // 2. Start JuiceFS Gateway
        //    Gateway runs inside a container and needs to reach Redis on the host.
        //    testcontainers maps ports to the host, so Gateway must use
        //    host.docker.internal (Docker Desktop) to connect back.
        //    Using ce-v1.2.1 for arm64 (Apple Silicon) support.
        let format_and_gateway = format!(
            "juicefs format redis://host.docker.internal:{}/1 test-vol 2>/dev/null; \
             juicefs gateway redis://host.docker.internal:{}/1 0.0.0.0:9000",
            redis_port, redis_port
        );

        let gateway = GenericImage::new("juicedata/mount", "ce-v1.2.1")
            .with_entrypoint("/bin/sh")
            .with_exposed_port(9000.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Endpoint:"))
            .with_env_var("MINIO_ROOT_USER", "testadmin")
            .with_env_var("MINIO_ROOT_PASSWORD", "testpassword")
            .with_cmd(vec!["-c".to_string(), format_and_gateway])
            .with_startup_timeout(Duration::from_secs(60))
            .start()
            .await
            .expect("failed to start JuiceFS Gateway container");

        let gw_host = gateway.get_host().await.unwrap();
        let gw_port = gateway.get_host_port_ipv4(9000).await.unwrap();
        let endpoint = format!("http://{}:{}", gw_host, gw_port);

        // 3. Build JuiceFsDatasetStore
        let store = JuiceFsDatasetStore::new(
            "test-vol", // bucket = volume name
            "us-east-1",
            &endpoint,
            "testadmin",
            "testpassword",
            &redis_url,
            serde_json::json!({"test": true}),
        )
        .await
        .expect("failed to create JuiceFsDatasetStore");

        Self {
            store,
            _redis: redis,
            _gateway: gateway,
        }
    }
}

fn test_id(val: u8) -> DatasetId {
    DatasetId::from([val; 20])
}

// --- Tests ---

#[tokio::test]
async fn put_and_get_file() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0xAA);
    let data = b"hello, juicefs!";

    env.store.put_file(&id, "test.txt", data).await.unwrap();
    let got = env.store.get_file(&id, "test.txt").await.unwrap();

    assert_eq!(got, data);
}

#[tokio::test]
async fn get_file_not_found() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0xBB);

    let err = env.store.get_file(&id, "nonexistent.txt").await.unwrap_err();
    assert!(
        matches!(err, DatasetStoreError::NotFound(_)),
        "expected NotFound, got: {err}"
    );
}

#[tokio::test]
async fn list_files_empty() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0xCC);

    let files = env.store.list_files(&id).await.unwrap();
    assert!(files.is_empty());
}

#[tokio::test]
async fn list_files_multiple() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0xDD);

    env.store.put_file(&id, "a.csv", b"a").await.unwrap();
    env.store.put_file(&id, "b.csv", b"b").await.unwrap();
    env.store.put_file(&id, "sub/c.csv", b"c").await.unwrap();

    let files = env.store.list_files(&id).await.unwrap();
    assert_eq!(files, vec!["a.csv", "b.csv", "sub/c.csv"]);
}

#[tokio::test]
async fn list_files_isolation_between_datasets() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id1 = test_id(0x01);
    let id2 = test_id(0x02);

    env.store.put_file(&id1, "file1.txt", b"1").await.unwrap();
    env.store.put_file(&id2, "file2.txt", b"2").await.unwrap();

    let files1 = env.store.list_files(&id1).await.unwrap();
    let files2 = env.store.list_files(&id2).await.unwrap();

    assert_eq!(files1, vec!["file1.txt"]);
    assert_eq!(files2, vec!["file2.txt"]);
}

#[tokio::test]
async fn set_and_get_meta() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0xEE);

    let meta = DatasetMeta {
        status: DatasetStatus::Uploading,
        receipt: None,
    };
    env.store.set_meta(&id, &meta).await.unwrap();

    let got = env.store.get_meta(&id).await.unwrap().unwrap();
    assert_eq!(got.status, DatasetStatus::Uploading);
    assert!(got.receipt.is_none());
}

#[tokio::test]
async fn meta_not_found_returns_none() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0xFF);

    let got = env.store.get_meta(&id).await.unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn meta_update_with_receipt() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0x11);

    // Set uploading
    let meta1 = DatasetMeta {
        status: DatasetStatus::Uploading,
        receipt: None,
    };
    env.store.set_meta(&id, &meta1).await.unwrap();

    // Update to ready with receipt
    let meta2 = DatasetMeta {
        status: DatasetStatus::Ready,
        receipt: Some(DatasetReceipt {
            dataset_id: id,
            files: vec![FileEntry {
                path: "data.csv".into(),
                size: 100,
                hash: "abc123".into(),
            }],
            total_size: 100,
            content_hash: "def456".into(),
        }),
    };
    env.store.set_meta(&id, &meta2).await.unwrap();

    let got = env.store.get_meta(&id).await.unwrap().unwrap();
    assert_eq!(got.status, DatasetStatus::Ready);
    let receipt = got.receipt.unwrap();
    assert_eq!(receipt.files.len(), 1);
    assert_eq!(receipt.total_size, 100);
}

#[tokio::test]
async fn put_overwrite() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0x22);

    env.store.put_file(&id, "f.txt", b"version1").await.unwrap();
    env.store.put_file(&id, "f.txt", b"version2").await.unwrap();

    let got = env.store.get_file(&id, "f.txt").await.unwrap();
    assert_eq!(got, b"version2");
}

#[tokio::test]
async fn large_file_roundtrip() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let id = test_id(0x33);

    // 1MB of data
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    env.store.put_file(&id, "large.bin", &data).await.unwrap();

    let got = env.store.get_file(&id, "large.bin").await.unwrap();
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
}

#[tokio::test]
async fn storage_access_config_returns_configured_value() {
    require_docker!();
    let env = JuiceFsTestEnv::start().await;
    let config = env.store.storage_access_config();
    assert_eq!(config, serde_json::json!({"test": true}));
}
