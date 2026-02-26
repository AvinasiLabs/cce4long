use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Describes the algorithm to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    /// In dev mode: local command path. In prod mode: container image reference.
    pub image: String,
    /// Command-line arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Resource limits.
    #[serde(default)]
    pub limits: ResourceLimits,
}

/// Resource limits for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum execution time.
    #[serde(with = "duration_secs", default = "default_timeout")]
    pub timeout: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
        }
    }
}

fn default_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes
}

/// Result of algorithm execution.
#[derive(Debug)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub usage: ResourceUsage,
}

/// Resource usage metrics collected after execution.
#[derive(Debug, Default)]
pub struct ResourceUsage {
    pub wall_time: Duration,
}

mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}
