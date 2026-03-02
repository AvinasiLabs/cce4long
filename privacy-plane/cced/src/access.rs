use async_trait::async_trait;
use key_manager::DatasetId;

/// Unified access verification trait.
///
/// Routes access checks to the correct contract type (RentalOnly vs IDO)
/// by querying the Factory's Dataset Registry on-chain.
#[async_trait]
pub trait AccessVerifier: Send + Sync {
    /// Check if `user` has active access to `dataset_id`.
    async fn has_access(&self, dataset_id: &DatasetId, user: &[u8; 20]) -> anyhow::Result<bool>;

    /// Check if `user` is the owner of `dataset_id`.
    async fn is_owner(&self, dataset_id: &DatasetId, user: &[u8; 20]) -> anyhow::Result<bool>;
}

/// Dev-mode access verifier that always returns true.
pub struct DevAccessVerifier;

#[async_trait]
impl AccessVerifier for DevAccessVerifier {
    async fn has_access(&self, _dataset_id: &DatasetId, _user: &[u8; 20]) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_owner(&self, _dataset_id: &DatasetId, _user: &[u8; 20]) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id() -> DatasetId {
        DatasetId::from([0x42; 20])
    }

    #[tokio::test]
    async fn dev_verifier_always_grants_access() {
        let verifier = DevAccessVerifier;
        let user = [0xAA; 20];
        assert!(verifier.has_access(&test_id(), &user).await.unwrap());
        assert!(verifier.is_owner(&test_id(), &user).await.unwrap());
    }
}
