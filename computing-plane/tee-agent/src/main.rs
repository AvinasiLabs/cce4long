//! TEE Agent - runs inside the CVM, manages computation lifecycle.

use tee_agent::error::AgentError;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::level_filters::LevelFilter::INFO.into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("agent failed: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), AgentError> {
    tracing::info!("tee-agent starting");

    let config = tee_agent::AgentConfig::from_env()?;
    tracing::info!(pp_url = %config.pp_url, "config loaded");

    // Parse job spec from TEE_AGENT_JOB_SPEC env var (JSON)
    let job_spec_json = std::env::var("TEE_AGENT_JOB_SPEC")
        .map_err(|_| AgentError::Config("missing TEE_AGENT_JOB_SPEC".into()))?;
    let job_spec: executor::JobSpec = serde_json::from_str(&job_spec_json)
        .map_err(|e| AgentError::Config(format!("invalid job spec JSON: {e}")))?;

    #[cfg(feature = "coco")]
    let attester = tee_agent::CocoAttester::new()?;
    #[cfg(not(feature = "coco"))]
    let attester = tee_agent::DevAttester;

    let mut agent = tee_agent::Agent::new(
        attester,
        tee_agent::PpClient::new(&config.pp_url),
        config.credential,
        config.submit_credential,
        config.dataset_ids,
        config.data_dir,
        config.output_dir,
        decrypt_fs::DevMountBackend,
        executor::DevRunner,
        job_spec,
    );

    let result = agent.run().await?;

    tracing::info!(
        exit_code = result.execution.exit_code,
        duration = ?result.execution.duration,
        encrypted_files = result.encrypted_files.len(),
        "tee-agent finished"
    );

    Ok(())
}
