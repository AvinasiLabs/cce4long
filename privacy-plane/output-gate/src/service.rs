use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::OutputGateError;
use crate::review::ReviewPolicy;
use crate::types::{ResultRecord, ResultStatus};

/// Output gate service — stores submitted results and runs review policy.
pub struct OutputGateService<P: ReviewPolicy> {
    records: Mutex<HashMap<String, ResultRecord>>,
    review_policy: P,
}

impl<P: ReviewPolicy> OutputGateService<P> {
    pub fn new(review_policy: P) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            review_policy,
        }
    }

    /// Submit a result for review.
    pub async fn submit(
        &self,
        job_id: &str,
        result_path: &str,
        result_hash: [u8; 32],
    ) -> Result<ResultStatus, OutputGateError> {
        // Check for duplicate submission
        {
            let records = self.records.lock().unwrap();
            if records.contains_key(job_id) {
                return Err(OutputGateError::AlreadySubmitted(job_id.to_string()));
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut record = ResultRecord {
            job_id: job_id.to_string(),
            result_path: result_path.to_string(),
            result_hash,
            status: ResultStatus::PendingReview,
            submitted_at: now,
        };

        // Run review policy
        let decision = self.review_policy.review(&record).await;
        record.status = decision.clone();

        let status = record.status.clone();
        self.records.lock().unwrap().insert(job_id.to_string(), record);

        Ok(status)
    }

    /// Get the record for a submitted result.
    pub fn get(&self, job_id: &str) -> Result<ResultRecord, OutputGateError> {
        let records = self.records.lock().unwrap();
        records
            .get(job_id)
            .cloned()
            .ok_or_else(|| OutputGateError::JobNotFound(job_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::DevReviewPolicy;

    #[tokio::test]
    async fn submit_and_get() {
        let svc = OutputGateService::new(DevReviewPolicy);
        let hash = [0xAA; 32];
        let status = svc.submit("job-1", "/output/result", hash).await.unwrap();
        assert_eq!(status, ResultStatus::Approved);

        let record = svc.get("job-1").unwrap();
        assert_eq!(record.job_id, "job-1");
        assert_eq!(record.result_path, "/output/result");
        assert_eq!(record.result_hash, hash);
        assert_eq!(record.status, ResultStatus::Approved);
    }

    #[tokio::test]
    async fn duplicate_submit_rejected() {
        let svc = OutputGateService::new(DevReviewPolicy);
        svc.submit("job-1", "/output/a", [0; 32]).await.unwrap();
        let err = svc.submit("job-1", "/output/b", [1; 32]).await.unwrap_err();
        assert!(err.to_string().contains("already submitted"));
    }

    #[tokio::test]
    async fn get_missing_job() {
        let svc = OutputGateService::new(DevReviewPolicy);
        let err = svc.get("nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
