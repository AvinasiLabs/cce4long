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
        // Reserve the slot atomically: check + insert in one lock scope to prevent TOCTOU.
        {
            let mut records = self.records.lock().unwrap();
            use std::collections::hash_map::Entry;
            match records.entry(job_id.to_string()) {
                Entry::Occupied(_) => {
                    return Err(OutputGateError::AlreadySubmitted(job_id.to_string()));
                }
                Entry::Vacant(slot) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    slot.insert(ResultRecord {
                        job_id: job_id.to_string(),
                        result_path: result_path.to_string(),
                        result_hash,
                        status: ResultStatus::PendingReview,
                        submitted_at: now,
                    });
                }
            }
        }

        // Run review policy outside the lock.
        let record_snapshot = {
            let records = self.records.lock().unwrap();
            records.get(job_id).cloned().unwrap()
        };
        let decision = self.review_policy.review(&record_snapshot).await;

        // Update status with the decision.
        let status = {
            let mut records = self.records.lock().unwrap();
            if let Some(rec) = records.get_mut(job_id) {
                rec.status = decision.clone();
            }
            decision
        };

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

    #[tokio::test]
    async fn concurrent_submit_same_job_exactly_one_succeeds() {
        use std::sync::Arc;

        let svc = Arc::new(OutputGateService::new(DevReviewPolicy));
        let n = 20;
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let svc = Arc::clone(&svc);
            handles.push(tokio::spawn(async move {
                svc.submit("dup-job", &format!("/output/{i}"), [i as u8; 32]).await
            }));
        }

        let mut ok_count = 0usize;
        let mut dup_count = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(_) => ok_count += 1,
                Err(OutputGateError::AlreadySubmitted(_)) => dup_count += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(ok_count, 1, "exactly one submit should succeed");
        assert_eq!(dup_count, n - 1);
    }
}
