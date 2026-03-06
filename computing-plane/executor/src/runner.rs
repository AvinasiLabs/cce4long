use std::time::Instant;

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::ExecutorError;
use crate::types::{ExecutionResult, JobSpec, ResourceUsage};

/// Executes an algorithm job.
#[async_trait]
pub trait Runner: Send + Sync {
    async fn run(
        &self,
        spec: &JobSpec,
        data_dir: &str,
        output_dir: &str,
    ) -> Result<ExecutionResult, ExecutorError>;
}

/// Runner that executes jobs as local subprocesses.
pub struct SubprocessRunner;

#[async_trait]
impl Runner for SubprocessRunner {
    async fn run(
        &self,
        spec: &JobSpec,
        data_dir: &str,
        output_dir: &str,
    ) -> Result<ExecutionResult, ExecutorError> {
        let start = Instant::now();

        let mut cmd = Command::new(&spec.image);
        cmd.args(&spec.args)
            .env("DATA_DIR", data_dir)
            .env("OUTPUT_DIR", output_dir);

        let child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ExecutorError::CommandNotFound(spec.image.clone())
                } else {
                    ExecutorError::SpawnFailed(e.to_string())
                }
            })?;

        let timeout_result =
            tokio::time::timeout(spec.limits.timeout, child.wait_with_output()).await;

        match timeout_result {
            Ok(Ok(output)) => {
                let duration = start.elapsed();
                Ok(ExecutionResult {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    duration,
                    usage: ResourceUsage {
                        wall_time: duration,
                    },
                })
            }
            Ok(Err(e)) => Err(ExecutorError::Io(e.to_string())),
            Err(_) => Err(ExecutorError::Timeout(spec.limits.timeout)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::types::ResourceLimits;

    fn echo_spec(msg: &str) -> JobSpec {
        JobSpec {
            image: "echo".to_string(),
            args: vec![msg.to_string()],
            limits: ResourceLimits::default(),
        }
    }

    #[tokio::test]
    async fn successful_execution() {
        let runner = SubprocessRunner;
        let spec = echo_spec("hello from executor");
        let result = runner.run(&spec, "/tmp", "/tmp").await.unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello from executor"));
        assert!(result.duration.as_secs() < 10);
    }

    #[tokio::test]
    async fn nonzero_exit_code() {
        let runner = SubprocessRunner;
        let spec = JobSpec {
            image: "sh".to_string(),
            args: vec!["-c".to_string(), "exit 42".to_string()],
            limits: ResourceLimits::default(),
        };
        let result = runner.run(&spec, "/tmp", "/tmp").await.unwrap();
        assert_eq!(result.exit_code, 42);
    }

    #[tokio::test]
    async fn timeout_kills_process() {
        let runner = SubprocessRunner;
        let spec = JobSpec {
            image: "sleep".to_string(),
            args: vec!["60".to_string()],
            limits: ResourceLimits {
                timeout: Duration::from_millis(100),
            },
        };
        let err = runner.run(&spec, "/tmp", "/tmp").await.unwrap_err();
        assert!(matches!(err, ExecutorError::Timeout(_)));
    }

    #[tokio::test]
    async fn command_not_found() {
        let runner = SubprocessRunner;
        let spec = JobSpec {
            image: "/nonexistent/command/xyzzy".to_string(),
            args: vec![],
            limits: ResourceLimits::default(),
        };
        let err = runner.run(&spec, "/tmp", "/tmp").await.unwrap_err();
        assert!(matches!(err, ExecutorError::CommandNotFound(_)));
    }

    #[tokio::test]
    async fn env_vars_passed() {
        let runner = SubprocessRunner;
        let spec = JobSpec {
            image: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "echo DATA=$DATA_DIR OUTPUT=$OUTPUT_DIR".to_string(),
            ],
            limits: ResourceLimits::default(),
        };
        let result = runner.run(&spec, "/my/data", "/my/output").await.unwrap();
        assert!(result.stdout.contains("DATA=/my/data"));
        assert!(result.stdout.contains("OUTPUT=/my/output"));
    }

    #[tokio::test]
    async fn output_dir_file_collection() {
        let tmp = tempfile::tempdir().unwrap();
        let output_dir = tmp.path().to_str().unwrap();

        let runner = SubprocessRunner;
        let spec = JobSpec {
            image: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "echo result > $OUTPUT_DIR/result.txt".to_string(),
            ],
            limits: ResourceLimits::default(),
        };
        let result = runner.run(&spec, "/tmp", output_dir).await.unwrap();
        assert_eq!(result.exit_code, 0);

        // Verify the file was created in output_dir
        let content = std::fs::read_to_string(tmp.path().join("result.txt")).unwrap();
        assert!(content.contains("result"));
    }

    #[tokio::test]
    async fn resource_usage_recorded() {
        let runner = SubprocessRunner;
        let spec = echo_spec("quick");
        let result = runner.run(&spec, "/tmp", "/tmp").await.unwrap();
        assert!(result.usage.wall_time.as_millis() > 0);
        assert_eq!(result.usage.wall_time, result.duration);
    }
}
