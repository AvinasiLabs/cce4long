use serde::{Deserialize, Serialize};

/// Status of a submitted result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ResultStatus {
    PendingReview,
    Approved,
    Rejected { reason: String },
}

/// Internal record for a submitted result.
#[derive(Debug, Clone)]
pub struct ResultRecord {
    pub job_id: String,
    pub result_path: String,
    pub result_hash: [u8; 32],
    pub status: ResultStatus,
    pub submitted_at: u64,
}

/// Manifest returned to consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultManifest {
    pub job_id: String,
    pub result_path: String,
    pub result_hash: String,
    pub status: ResultStatus,
}
