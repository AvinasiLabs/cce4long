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
}

pub trait RootKeyProvider: Send + Sync {
    fn root_key(&self) -> &[u8; 32];
}

/// Dev-only root key provider. Reads CCE_ROOT_KEY env var (hex),
/// falls back to a deterministic dev seed.
pub struct DevRootKeyProvider {
    key: [u8; 32],
}

impl DevRootKeyProvider {
    pub fn new() -> Self {
        let key = match std::env::var("CCE_ROOT_KEY") {
            Ok(hex) => {
                let bytes = hex::decode(&hex).expect("CCE_ROOT_KEY must be valid hex");
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Err(_) => {
                // Deterministic dev seed — NOT for production
                let hk = Hkdf::<Sha256>::new(None, b"cce4long-dev-root-key");
                let mut key = [0u8; 32];
                hk.expand(b"dev-root", &mut key).expect("valid length");
                key
            }
        };
        Self { key }
    }
}

impl Default for DevRootKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RootKeyProvider for DevRootKeyProvider {
    fn root_key(&self) -> &[u8; 32] {
        &self.key
    }
}

pub struct KeyManager<R: RootKeyProvider> {
    root: R,
}

impl<R: RootKeyProvider> KeyManager<R> {
    pub fn new(root: R) -> Self {
        Self { root }
    }

    /// Derive a Data Encryption Key for the given dataset.
    /// HKDF-SHA256(ikm=root_key, salt=dataset_id.to_be_bytes(), info="dataset-encryption")
    pub fn derive_dek(&self, dataset_id: u64) -> Result<Key, KeyError> {
        let salt = dataset_id.to_be_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&salt), self.root.root_key());
        let mut dek = [0u8; 32];
        hk.expand(b"dataset-encryption", &mut dek)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(Key(dek))
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

    #[test]
    fn derive_dek_is_deterministic() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_dek(1).unwrap();
        let k2 = km.derive_dek(1).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_dataset_ids_produce_different_deks() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_dek(1).unwrap();
        let k2 = km.derive_dek(2).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn dek_is_32_bytes() {
        let km = KeyManager::new(FixedKeyProvider([0xBB; 32]));
        let k = km.derive_dek(42).unwrap();
        assert_eq!(k.0.len(), 32);
    }

    #[test]
    fn dev_root_key_provider_works() {
        let provider = DevRootKeyProvider::new();
        let key = provider.root_key();
        assert_eq!(key.len(), 32);
        // Should be deterministic when no env var
        let provider2 = DevRootKeyProvider::new();
        assert_eq!(provider.root_key(), provider2.root_key());
    }
}
