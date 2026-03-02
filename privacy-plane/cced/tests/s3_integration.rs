use cced::storage::{S3Storage, Storage};

fn s3_env() -> Option<(String, String, String, String, String)> {
    let bucket = std::env::var("CCED_S3_BUCKET").ok()?;
    let access_key = std::env::var("CCED_S3_ACCESS_KEY").ok()?;
    let secret_key = std::env::var("CCED_S3_SECRET_KEY").ok()?;
    let region = std::env::var("CCED_S3_REGION").unwrap_or_else(|_| "auto".into());
    let endpoint = std::env::var("CCED_S3_ENDPOINT")
        .unwrap_or_else(|_| "https://storage.googleapis.com".into());
    Some((bucket, region, endpoint, access_key, secret_key))
}

#[tokio::test]
async fn put_object_to_gcs() {
    let Some((bucket, region, endpoint, access_key, secret_key)) = s3_env() else {
        eprintln!("skipping S3 integration test: CCED_S3_BUCKET / CCED_S3_ACCESS_KEY / CCED_S3_SECRET_KEY not set");
        return;
    };

    let storage = S3Storage::new(&bucket, &region, &endpoint, &access_key, &secret_key)
        .expect("S3Storage::new");

    let key = format!("integration-test-{}.txt", std::process::id());
    let data = b"hello from cced integration test";

    let uri = storage.put(&key, data).await.expect("put should succeed");

    assert!(uri.starts_with("s3://"), "expected s3:// URI, got: {}", uri);
    assert!(uri.contains(&key), "URI should contain key: {}", uri);

    eprintln!("uploaded: {}", uri);
}
