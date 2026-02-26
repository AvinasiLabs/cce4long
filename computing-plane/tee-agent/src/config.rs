use compute_controller::JobCredential;

use crate::error::AgentError;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub pp_url: String,
    pub credential: JobCredential,
    pub dataset_ids: Vec<u64>,
    pub data_dir: String,
    pub output_dir: String,
}

impl AgentConfig {
    /// Load config from environment variables.
    ///
    /// Required:
    /// - `TEE_AGENT_PP_URL`: URL of the privacy plane (e.g. "http://localhost:3000")
    /// - `TEE_AGENT_CREDENTIAL`: JSON-serialized JobCredential
    /// - `TEE_AGENT_DATASET_IDS`: comma-separated dataset IDs (e.g. "1,2,3")
    ///
    /// Optional (with defaults):
    /// - `TEE_AGENT_DATA_DIR`: directory for encrypted data (default: "/data")
    /// - `TEE_AGENT_OUTPUT_DIR`: directory for computation output (default: "/output")
    pub fn from_env() -> Result<Self, AgentError> {
        let pp_url = required_env("TEE_AGENT_PP_URL")?;

        let credential_json = required_env("TEE_AGENT_CREDENTIAL")?;
        let credential: JobCredential = serde_json::from_str(&credential_json)
            .map_err(|e| AgentError::Config(format!("invalid credential JSON: {e}")))?;

        let dataset_ids_str = required_env("TEE_AGENT_DATASET_IDS")?;
        let dataset_ids = parse_dataset_ids(&dataset_ids_str)?;

        let data_dir =
            std::env::var("TEE_AGENT_DATA_DIR").unwrap_or_else(|_| "/data".to_string());
        let output_dir =
            std::env::var("TEE_AGENT_OUTPUT_DIR").unwrap_or_else(|_| "/output".to_string());

        Ok(Self {
            pp_url,
            credential,
            dataset_ids,
            data_dir,
            output_dir,
        })
    }
}

fn required_env(name: &str) -> Result<String, AgentError> {
    std::env::var(name)
        .map_err(|_| AgentError::Config(format!("missing environment variable: {name}")))
}

fn parse_dataset_ids(s: &str) -> Result<Vec<u64>, AgentError> {
    s.split(',')
        .map(|part| {
            part.trim()
                .parse::<u64>()
                .map_err(|e| AgentError::Config(format!("invalid dataset ID '{part}': {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env-mutating tests
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env() {
        for var in [
            "TEE_AGENT_PP_URL",
            "TEE_AGENT_CREDENTIAL",
            "TEE_AGENT_DATASET_IDS",
            "TEE_AGENT_DATA_DIR",
            "TEE_AGENT_OUTPUT_DIR",
        ] {
            unsafe { std::env::remove_var(var) };
        }
    }

    fn sample_credential_json() -> String {
        serde_json::json!({
            "version": 1,
            "job_id": "job-1",
            "user": "alice",
            "datasets": [1, 2],
            "nonce": "00000000000000000000000000000000",
            "issued_at": 1000000,
            "expires_at": 2000000,
            "signature": "deadbeef"
        })
        .to_string()
    }

    #[test]
    fn from_env_success() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        unsafe {
            std::env::set_var("TEE_AGENT_PP_URL", "http://localhost:3000");
            std::env::set_var("TEE_AGENT_CREDENTIAL", sample_credential_json());
            std::env::set_var("TEE_AGENT_DATASET_IDS", "1,2,3");
            std::env::set_var("TEE_AGENT_DATA_DIR", "/tmp/data");
            std::env::set_var("TEE_AGENT_OUTPUT_DIR", "/tmp/output");
        }

        let config = AgentConfig::from_env().unwrap();
        assert_eq!(config.pp_url, "http://localhost:3000");
        assert_eq!(config.credential.job_id, "job-1");
        assert_eq!(config.dataset_ids, vec![1, 2, 3]);
        assert_eq!(config.data_dir, "/tmp/data");
        assert_eq!(config.output_dir, "/tmp/output");

        clear_env();
    }

    #[test]
    fn from_env_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        unsafe {
            std::env::set_var("TEE_AGENT_PP_URL", "http://localhost:3000");
            std::env::set_var("TEE_AGENT_CREDENTIAL", sample_credential_json());
            std::env::set_var("TEE_AGENT_DATASET_IDS", "42");
        }

        let config = AgentConfig::from_env().unwrap();
        assert_eq!(config.data_dir, "/data");
        assert_eq!(config.output_dir, "/output");
        assert_eq!(config.dataset_ids, vec![42]);

        clear_env();
    }

    #[test]
    fn missing_pp_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        unsafe {
            std::env::set_var("TEE_AGENT_CREDENTIAL", sample_credential_json());
            std::env::set_var("TEE_AGENT_DATASET_IDS", "1");
        }

        let err = AgentConfig::from_env().unwrap_err();
        assert!(err.to_string().contains("TEE_AGENT_PP_URL"));

        clear_env();
    }

    #[test]
    fn missing_credential() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        unsafe {
            std::env::set_var("TEE_AGENT_PP_URL", "http://localhost:3000");
            std::env::set_var("TEE_AGENT_DATASET_IDS", "1");
        }

        let err = AgentConfig::from_env().unwrap_err();
        assert!(err.to_string().contains("TEE_AGENT_CREDENTIAL"));

        clear_env();
    }

    #[test]
    fn invalid_credential_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        unsafe {
            std::env::set_var("TEE_AGENT_PP_URL", "http://localhost:3000");
            std::env::set_var("TEE_AGENT_CREDENTIAL", "not-json");
            std::env::set_var("TEE_AGENT_DATASET_IDS", "1");
        }

        let err = AgentConfig::from_env().unwrap_err();
        assert!(err.to_string().contains("invalid credential JSON"));

        clear_env();
    }

    #[test]
    fn invalid_dataset_ids() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        unsafe {
            std::env::set_var("TEE_AGENT_PP_URL", "http://localhost:3000");
            std::env::set_var("TEE_AGENT_CREDENTIAL", sample_credential_json());
            std::env::set_var("TEE_AGENT_DATASET_IDS", "1,abc,3");
        }

        let err = AgentConfig::from_env().unwrap_err();
        assert!(err.to_string().contains("abc"));

        clear_env();
    }

    #[test]
    fn parse_dataset_ids_valid() {
        assert_eq!(parse_dataset_ids("1,2,3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_dataset_ids("42").unwrap(), vec![42]);
        assert_eq!(parse_dataset_ids(" 1 , 2 ").unwrap(), vec![1, 2]);
    }
}
