use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("key error: {0}")]
    Key(#[from] key_manager::KeyError),

    #[error("verifier error: {0}")]
    Verifier(#[from] tee_verifier::VerifierError),

    #[error("controller error: {0}")]
    Controller(#[from] compute_controller::ControllerError),

    #[error("config error: {0}")]
    Config(String),

    #[error("PP request failed: {0}")]
    PpRequest(String),

    #[error("invalid response from PP: {0}")]
    PpResponse(String),

    #[error("hex decode error: {0}")]
    HexDecode(String),

    #[error("mount failed: {0}")]
    Mount(String),

    #[error("execution failed: {0}")]
    Execution(String),
}
