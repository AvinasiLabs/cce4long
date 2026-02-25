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

/// Dev-only access checker: always allows access.
pub struct DevAccessChecker;

#[async_trait]
impl AccessChecker for DevAccessChecker {
    async fn check_access(
        &self,
        _user: &str,
        _dataset_ids: &[u64],
    ) -> Result<(), ControllerError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dev_access_checker_allows_all() {
        let checker = DevAccessChecker;
        assert!(checker.check_access("alice", &[1, 2, 3]).await.is_ok());
    }

    #[tokio::test]
    async fn dev_access_checker_allows_empty() {
        let checker = DevAccessChecker;
        assert!(checker.check_access("bob", &[]).await.is_ok());
    }
}
