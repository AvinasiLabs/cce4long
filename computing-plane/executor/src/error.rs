use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("execution timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("command not found: {0}")]
    CommandNotFound(String),

    #[error("process spawn failed: {0}")]
    SpawnFailed(String),

    #[error("I/O error: {0}")]
    Io(String),
}
