use async_trait::async_trait;

use crate::types::{ResultRecord, ResultStatus};

/// Review decision returned by a ReviewPolicy.
pub type ReviewDecision = ResultStatus;

/// Policy that decides whether a submitted result is approved.
#[async_trait]
pub trait ReviewPolicy: Send + Sync {
    async fn review(&self, record: &ResultRecord) -> ReviewDecision;
}

/// Dev-mode policy: auto-approve everything.
pub struct DevReviewPolicy;

#[async_trait]
impl ReviewPolicy for DevReviewPolicy {
    async fn review(&self, _record: &ResultRecord) -> ReviewDecision {
        ResultStatus::Approved
    }
}
