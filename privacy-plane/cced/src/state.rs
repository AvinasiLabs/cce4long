use std::collections::HashSet;
use std::sync::Mutex;

use compute_controller::{
    CredentialService, DevMeasurementRegistry, MeasurementRegistry,
};
use key_manager::{DevRootKeyProvider, KeyManager, RootKeyProvider};
use output_gate::{DevReviewPolicy, OutputGateService};
use tee_verifier::{SampleVerifier, TeeType, TeeVerifier};

use crate::access::{AccessVerifier, DevAccessVerifier};
use crate::storage::{S3Storage, Storage};

/// JuiceFS volume configuration — distributed to CVMs via `/v1/keys/request`.
#[derive(Clone, serde::Serialize)]
pub struct JuiceFsConfig {
    /// Metadata server URL (e.g. "redis://host:6379/1").
    pub meta_url: String,
    /// Data backend (e.g. GCS).
    pub backend: JuiceFsBackend,
}

#[derive(Clone, serde::Serialize)]
pub struct JuiceFsBackend {
    pub storage_type: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

pub struct AppState {
    pub key_manager: KeyManager,
    pub storage: Box<dyn Storage>,
    pub credential_service: CredentialService,
    pub tee_verifier: TeeVerifier,
    pub measurement_registry: Box<dyn MeasurementRegistry>,
    pub request_id_tracker: Mutex<HashSet<[u8; 16]>>,
    pub output_gate: OutputGateService<DevReviewPolicy>,
    pub upload_hmac_key: [u8; 32],
    pub access_verifier: Box<dyn AccessVerifier>,
    pub jfs: JuiceFsConfig,
}

impl AppState {
    /// For tests — inject storage (LocalStorage), use dummy JuiceFS config.
    pub fn dev(storage: Box<dyn Storage>) -> Self {
        let jfs = JuiceFsConfig {
            meta_url: "redis://localhost:6379/1".to_string(),
            backend: JuiceFsBackend {
                storage_type: "gs".to_string(),
                bucket: String::new(),
                access_key: String::new(),
                secret_key: String::new(),
            },
        };
        Self::build_dev(storage, jfs)
    }

    /// Production dev-mode — creates S3Storage internally (→ JuiceFS Gateway sidecar).
    pub fn new(jfs: JuiceFsConfig) -> Self {
        let storage = Box::new(
            S3Storage::new("avinasi", "auto", "http://localhost:9000", "admin", "changeme123")
                .expect("failed to initialize S3Storage"),
        );
        Self::build_dev(storage, jfs)
    }

    fn build_dev(storage: Box<dyn Storage>, jfs: JuiceFsConfig) -> Self {
        let root = DevRootKeyProvider::new();
        let credential_service =
            CredentialService::from_root_key(root.root_key()).expect("credential key derivation");
        let key_manager = KeyManager::from_provider(&root);
        let upload_hmac_key = key_manager
            .derive_upload_hmac_key()
            .expect("HMAC key derivation");
        Self {
            key_manager,
            storage,
            credential_service,
            tee_verifier: TeeVerifier::new().register(TeeType::Sample, SampleVerifier),
            measurement_registry: Box::new(DevMeasurementRegistry),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(DevReviewPolicy),
            upload_hmac_key,
            access_verifier: Box::new(DevAccessVerifier),
            jfs,
        }
    }

    #[cfg(all(feature = "dstack", feature = "dcap"))]
    pub async fn production(
        dstack_endpoint: Option<&str>,
        pccs_url: &str,
        jfs: JuiceFsConfig,
    ) -> Result<Self, anyhow::Error> {
        let storage = Box::new(
            S3Storage::new("avinasi", "auto", "http://localhost:9000", "admin", "changeme123")?,
        );
        let root = key_manager::DstackRootKeyProvider::init(dstack_endpoint).await?;
        let credential_service = CredentialService::from_root_key(root.root_key())?;
        let key_manager = KeyManager::from_provider(&root);
        let upload_hmac_key = key_manager.derive_upload_hmac_key()?;
        Ok(Self {
            key_manager,
            storage,
            credential_service,
            tee_verifier: TeeVerifier::new()
                .register(
                    TeeType::Tdx,
                    tee_verifier::DcapVerifier::new(pccs_url.to_string()),
                )
                .register(TeeType::Sample, SampleVerifier),
            measurement_registry: Box::new(DevMeasurementRegistry),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(DevReviewPolicy),
            upload_hmac_key,
            access_verifier: Box::new(DevAccessVerifier),
            jfs,
        })
    }

    #[cfg(feature = "dstack")]
    pub async fn dstack(
        dstack_endpoint: Option<&str>,
        jfs: JuiceFsConfig,
    ) -> Result<Self, anyhow::Error> {
        let storage = Box::new(
            S3Storage::new("avinasi", "auto", "http://localhost:9000", "admin", "changeme123")?,
        );
        let root = key_manager::DstackRootKeyProvider::init(dstack_endpoint).await?;
        let credential_service = CredentialService::from_root_key(root.root_key())?;
        let key_manager = KeyManager::from_provider(&root);
        let upload_hmac_key = key_manager.derive_upload_hmac_key()?;
        Ok(Self {
            key_manager,
            storage,
            credential_service,
            tee_verifier: TeeVerifier::new().register(TeeType::Sample, SampleVerifier),
            measurement_registry: Box::new(DevMeasurementRegistry),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(DevReviewPolicy),
            upload_hmac_key,
            access_verifier: Box::new(DevAccessVerifier),
            jfs,
        })
    }
}
