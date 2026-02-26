use std::collections::HashMap;

use rand::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use compute_controller::JobCredential;
use key_manager::Key;

use crate::attester::Attester;
use crate::error::AgentError;
use crate::pp_client::PpClient;
use crate::result::{EncryptedFile, encrypt_output};

/// Acquired keys from the privacy plane.
#[derive(Debug)]
pub struct AcquiredKeys {
    /// DEKs mapped by dataset_id.
    pub deks: HashMap<u64, Key>,
    /// Result encryption key.
    pub rek: Key,
}

/// Full lifecycle result.
#[derive(Debug)]
pub struct AgentResult {
    pub execution: executor::ExecutionResult,
    pub encrypted_files: Vec<EncryptedFile>,
}

/// TEE Agent — one-shot orchestrator for the computation lifecycle.
pub struct Agent<A: Attester, M: decrypt_fs::MountBackend, R: executor::Runner> {
    attester: A,
    pp_client: PpClient,
    credential: JobCredential,
    dataset_ids: Vec<u64>,
    data_dir: String,
    output_dir: String,
    decrypt_fs: decrypt_fs::DecryptFs<M>,
    runner: R,
    job_spec: executor::JobSpec,
}

impl<A: Attester, M: decrypt_fs::MountBackend, R: executor::Runner> Agent<A, M, R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attester: A,
        pp_client: PpClient,
        credential: JobCredential,
        dataset_ids: Vec<u64>,
        data_dir: String,
        output_dir: String,
        backend: M,
        runner: R,
        job_spec: executor::JobSpec,
    ) -> Self {
        Self {
            attester,
            pp_client,
            credential,
            dataset_ids,
            data_dir,
            output_dir,
            decrypt_fs: decrypt_fs::DecryptFs::new(backend),
            runner,
            job_spec,
        }
    }

    /// Run the complete agent lifecycle:
    /// acquire_keys → mount_data → execute → encrypt_results → cleanup
    pub async fn run(&mut self) -> Result<AgentResult, AgentError> {
        let keys = self.acquire_keys().await?;
        self.mount_data(&keys).await?;
        let execution = self.execute().await?;
        let encrypted_files = self.encrypt_results(&keys.rek)?;
        self.cleanup().await;
        Ok(AgentResult {
            execution,
            encrypted_files,
        })
    }

    /// Acquire DEKs + REK from the privacy plane via RequestKeys.
    pub async fn acquire_keys(&self) -> Result<AcquiredKeys, AgentError> {
        // 1. ECDHE keypair
        let cvm_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let cvm_pk = PublicKey::from(&cvm_secret);

        // 2. Random request_id
        let mut request_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut request_id);

        // 3. reportdata = SHA512(eph_pk || request_id)
        let mut hasher = Sha512::new();
        hasher.update(cvm_pk.as_bytes());
        hasher.update(request_id);
        let reportdata: [u8; 64] = hasher.finalize().into();

        // 4. TEE quote
        let quote = self.attester.generate_quote(&reportdata).await?;

        // 5. Request keys from PP
        let bundle = self
            .pp_client
            .request_keys(
                &self.credential,
                &request_id,
                &quote,
                cvm_pk.as_bytes(),
                &self.dataset_ids,
            )
            .await?;

        // 6. Unwrap ECDHE
        let (deks, rek) = crate::pp_client::unwrap_keys(&bundle, &cvm_secret)?;

        // 7. Map DEKs to dataset_ids
        if deks.len() != self.dataset_ids.len() {
            return Err(AgentError::PpResponse(format!(
                "expected {} DEKs, got {}",
                self.dataset_ids.len(),
                deks.len()
            )));
        }
        let dek_map: HashMap<u64, Key> = self.dataset_ids.iter().copied().zip(deks).collect();

        Ok(AcquiredKeys { deks: dek_map, rek })
    }

    /// Mount datasets for decryption using acquired DEKs.
    async fn mount_data(&mut self, keys: &AcquiredKeys) -> Result<(), AgentError> {
        for (&dataset_id, dek) in &keys.deks {
            let dir = format!("{}/{dataset_id}", self.data_dir);
            self.decrypt_fs
                .mount(dataset_id, dek.clone(), dir)
                .await
                .map_err(|e| AgentError::Mount(e.to_string()))?;
        }
        Ok(())
    }

    /// Execute the algorithm.
    async fn execute(&self) -> Result<executor::ExecutionResult, AgentError> {
        self.runner
            .run(&self.job_spec, &self.data_dir, &self.output_dir)
            .await
            .map_err(|e| AgentError::Execution(e.to_string()))
    }

    /// Encrypt output files with REK.
    fn encrypt_results(&self, rek: &Key) -> Result<Vec<EncryptedFile>, AgentError> {
        encrypt_output(rek, &self.output_dir)
    }

    /// Clean up mounted datasets.
    async fn cleanup(&mut self) {
        self.decrypt_fs.cleanup().await;
    }
}
