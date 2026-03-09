macro_rules! require_env {
    ($name:expr) => {
        match std::env::var($name) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("skipped: {} not set", $name);
                return;
            }
        }
    };
}

use key_manager::{DatasetId, DstackRootKeyProvider, KeyManager, RootKeyProvider};

#[tokio::test]
async fn dstack_root_key_deterministic() {
    let endpoint = require_env!("DSTACK_SIMULATOR_ENDPOINT");

    let p1 = DstackRootKeyProvider::init(Some(&endpoint))
        .await
        .unwrap();
    let p2 = DstackRootKeyProvider::init(Some(&endpoint))
        .await
        .unwrap();
    assert_eq!(p1.root_key(), p2.root_key());

    let km = KeyManager::from_provider(&p1);
    let dataset_id = DatasetId::from([0x42; 20]);
    let dek1 = km.derive_dek(&dataset_id).unwrap();
    let dek2 = km.derive_dek(&dataset_id).unwrap();
    assert_eq!(dek1.as_bytes(), dek2.as_bytes());
}
