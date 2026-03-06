pub mod ecdhe;

mod dataset_id;
pub use dataset_id::{DatasetId, DatasetIdError};

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("HKDF expand failed")]
    DerivationFailed,
    #[error("ECDHE wrap failed: {0}")]
    WrapFailed(String),
    #[error("ECDHE unwrap failed: {0}")]
    UnwrapFailed(String),
    #[error("root key derivation failed: {0}")]
    RootKeyDerivation(String),
}

pub trait RootKeyProvider: Send + Sync {
    fn root_key(&self) -> &[u8; 32];
}

pub struct KeyManager {
    root_key: [u8; 32],
}

impl KeyManager {
    pub fn from_provider(provider: &dyn RootKeyProvider) -> Self {
        Self {
            root_key: *provider.root_key(),
        }
    }

    pub fn from_root_key(key: &[u8; 32]) -> Self {
        Self { root_key: *key }
    }

    /// Derive a Data Encryption Key for the given dataset.
    /// HKDF-SHA256(ikm=root_key, salt=dataset_id(20 bytes), info="dataset-encryption")
    pub fn derive_dek(&self, dataset_id: &DatasetId) -> Result<Key, KeyError> {
        let salt = dataset_id.as_ref();
        let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &self.root_key);
        let mut dek = [0u8; 32];
        hk.expand(b"dataset-encryption", &mut dek)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(Key(dek))
    }

    /// Derive an HMAC signing key for upload tokens.
    /// HKDF-SHA256(ikm=root_key, info="upload-token-signing")
    pub fn derive_upload_hmac_key(&self) -> Result<[u8; 32], KeyError> {
        let hk = Hkdf::<Sha256>::new(None, &self.root_key);
        let mut hmac_key = [0u8; 32];
        hk.expand(b"upload-token-signing", &mut hmac_key)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(hmac_key)
    }

    /// Derive a Result Encryption Key for the given job.
    /// HKDF-SHA256(ikm=root_key, salt=job_id.as_bytes(), info="result-encryption")
    /// Domain-separated from DEK by different info string.
    pub fn derive_rek(&self, job_id: &str) -> Result<Key, KeyError> {
        let hk = Hkdf::<Sha256>::new(Some(job_id.as_bytes()), &self.root_key);
        let mut rek = [0u8; 32];
        hk.expand(b"result-encryption", &mut rek)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(Key(rek))
    }
}

pub struct DstackRootKeyProvider {
    key: [u8; 32],
}

impl DstackRootKeyProvider {
    /// Connect to dstack and derive the root key via `GetKey` (recommended API).
    /// endpoint: None = `/var/run/dstack.sock`, Some(path) = Unix socket path,
    /// Some("http://...") = HTTP endpoint.
    pub async fn init(endpoint: Option<&str>) -> Result<Self, KeyError> {
        use dstack_sdk::dstack_client::DstackClient;

        let client = DstackClient::new(endpoint);
        let resp = client
            .get_key(
                Some("avinasi/root-key".into()),
                Some("privacy-plane".into()),
            )
            .await
            .map_err(|e| KeyError::RootKeyDerivation(e.to_string()))?;

        let key_bytes = resp
            .decode_key()
            .map_err(|e| KeyError::RootKeyDerivation(e.to_string()))?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        Ok(Self { key })
    }
}

impl RootKeyProvider for DstackRootKeyProvider {
    fn root_key(&self) -> &[u8; 32] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedKeyProvider([u8; 32]);
    impl RootKeyProvider for FixedKeyProvider {
        fn root_key(&self) -> &[u8; 32] {
            &self.0
        }
    }

    fn test_dataset_id(val: u8) -> DatasetId {
        DatasetId::from([val; 20])
    }

    #[test]
    fn derive_dek_is_deterministic() {
        let km = KeyManager::from_provider(&FixedKeyProvider([0xAA; 32]));
        let id = test_dataset_id(0x01);
        let k1 = km.derive_dek(&id).unwrap();
        let k2 = km.derive_dek(&id).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_dataset_ids_produce_different_deks() {
        let km = KeyManager::from_provider(&FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_dek(&test_dataset_id(0x01)).unwrap();
        let k2 = km.derive_dek(&test_dataset_id(0x02)).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn dek_is_32_bytes() {
        let km = KeyManager::from_provider(&FixedKeyProvider([0xBB; 32]));
        let k = km.derive_dek(&test_dataset_id(0x42)).unwrap();
        assert_eq!(k.0.len(), 32);
    }

    #[test]
    fn derive_rek_is_deterministic() {
        let km = KeyManager::from_provider(&FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_rek("job-1").unwrap();
        let k2 = km.derive_rek("job-1").unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_job_ids_produce_different_reks() {
        let km = KeyManager::from_provider(&FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_rek("job-1").unwrap();
        let k2 = km.derive_rek("job-2").unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn rek_and_dek_domain_separation() {
        // Even if the salt bytes happen to be the same, different info strings
        // must produce different keys.
        let km = KeyManager::from_provider(&FixedKeyProvider([0xCC; 32]));
        let dek = km.derive_dek(&test_dataset_id(0x01)).unwrap();
        let rek = km.derive_rek("job-1").unwrap();
        assert_ne!(dek.0, rek.0);
    }

    #[test]
    fn derive_upload_hmac_key_is_deterministic() {
        let km = KeyManager::from_provider(&FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_upload_hmac_key().unwrap();
        let k2 = km.derive_upload_hmac_key().unwrap();
        assert_eq!(k1, k2);
    }

    #[tokio::test]
    async fn dstack_root_key_deterministic() {
        let Ok(endpoint) = std::env::var("DSTACK_SIMULATOR_ENDPOINT") else {
            eprintln!("skipped: DSTACK_SIMULATOR_ENDPOINT not set");
            return;
        };
        let p1 = super::DstackRootKeyProvider::init(Some(&endpoint))
            .await
            .unwrap();
        let p2 = super::DstackRootKeyProvider::init(Some(&endpoint))
            .await
            .unwrap();
        assert_eq!(p1.root_key(), p2.root_key());

        let km = KeyManager::from_provider(&p1);
        let dataset_id = DatasetId::from([0x42; 20]);
        let dek1 = km.derive_dek(&dataset_id).unwrap();
        let dek2 = km.derive_dek(&dataset_id).unwrap();
        assert_eq!(dek1.as_bytes(), dek2.as_bytes());
    }
}
