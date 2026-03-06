use async_trait::async_trait;

#[async_trait]
pub trait MeasurementRegistry: Send + Sync {
    async fn is_trusted(&self, measurement: &str) -> bool;
}

/// Measurement registry that trusts all measurements.
pub struct AllowAllMeasurements;

#[async_trait]
impl MeasurementRegistry for AllowAllMeasurements {
    async fn is_trusted(&self, _measurement: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dev_registry_trusts_all() {
        let reg = AllowAllMeasurements;
        assert!(reg.is_trusted("anything").await);
        assert!(reg.is_trusted("").await);
    }
}
