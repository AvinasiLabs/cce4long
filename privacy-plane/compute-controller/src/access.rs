use async_trait::async_trait;

use crate::error::ControllerError;

#[async_trait]
pub trait AccessChecker: Send + Sync {
    async fn check_access(
        &self,
        user: &str,
        dataset_ids: &[u64],
    ) -> Result<(), ControllerError>;
}

