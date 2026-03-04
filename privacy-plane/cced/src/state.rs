use std::collections::HashSet;
use std::sync::Mutex;

use compute_controller::{
    CredentialService, DevMeasurementRegistry, MeasurementRegistry,
};
use key_manager::{DevRootKeyProvider, KeyManager, RootKeyProvider};
use output_gate::{DevReviewPolicy, OutputGateService};
use tee_verifier::{DevVerifier, TeeVerifier};

use crate::access::{AccessVerifier, DevAccessVerifier};
use crate::storage::Storage;

pub struct AppState {
    pub key_manager: KeyManager,
    pub storage: Box<dyn Storage>,
    pub credential_service: CredentialService,
    pub tee_verifier: Box<dyn TeeVerifier>,
    pub measurement_registry: Box<dyn MeasurementRegistry>,
    pub request_id_tracker: Mutex<HashSet<[u8; 16]>>,
    pub output_gate: OutputGateService<DevReviewPolicy>,
    pub upload_hmac_key: [u8; 32],
    pub access_verifier: Box<dyn AccessVerifier>,
}

impl AppState {
    pub fn dev(storage: Box<dyn Storage>) -> Self {
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
            tee_verifier: Box::new(DevVerifier),
            measurement_registry: Box::new(DevMeasurementRegistry),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(DevReviewPolicy),
            upload_hmac_key,
            access_verifier: Box::new(DevAccessVerifier),
        }
    }

    #[cfg(feature = "dstack")]
    pub async fn dstack(
        storage: Box<dyn Storage>,
        dstack_endpoint: Option<&str>,
    ) -> Result<Self, anyhow::Error> {
        let root = key_manager::DstackRootKeyProvider::init(dstack_endpoint).await?;
        let credential_service = CredentialService::from_root_key(root.root_key())?;
        let key_manager = KeyManager::from_provider(&root);
        let upload_hmac_key = key_manager.derive_upload_hmac_key()?;
        Ok(Self {
            key_manager,
            storage,
            credential_service,
            tee_verifier: Box::new(DevVerifier),
            measurement_registry: Box::new(DevMeasurementRegistry),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(DevReviewPolicy),
            upload_hmac_key,
            access_verifier: Box::new(DevAccessVerifier),
        })
    }
}
