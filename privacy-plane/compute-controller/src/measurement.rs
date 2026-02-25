use async_trait::async_trait;

#[async_trait]
pub trait MeasurementRegistry: Send + Sync {
    async fn is_trusted(&self, measurement: &str) -> bool;
}

/// Dev-only measurement registry: trusts all measurements.
pub struct DevMeasurementRegistry;

#[async_trait]
impl MeasurementRegistry for DevMeasurementRegistry {
    async fn is_trusted(&self, _measurement: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dev_registry_trusts_all() {
        let reg = DevMeasurementRegistry;
        assert!(reg.is_trusted("anything").await);
        assert!(reg.is_trusted("").await);
    }
}
