use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutputGateError {
    #[error("job not found: {0}")]
    JobNotFound(String),
    #[error("result already submitted for job: {0}")]
    AlreadySubmitted(String),
    #[error("result not approved for job: {0}")]
    NotApproved(String),
    #[error("internal error: {0}")]
    Internal(String),
}
