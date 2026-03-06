//! Output review and approval gate.

pub mod error;
pub mod review;
pub mod service;
pub mod types;

pub use error::OutputGateError;
pub use review::{AutoApprovePolicy, ReviewPolicy};
pub use service::OutputGateService;
pub use types::{ResultManifest, ResultRecord, ResultStatus};
