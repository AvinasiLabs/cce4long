use std::collections::HashSet;
use std::sync::Mutex;

use compute_controller::{AllowAllMeasurements, CredentialService, MeasurementRegistry};
use key_manager::KeyManager;
use output_gate::{AutoApprovePolicy, OutputGateService};
use tee_verifier::TeeVerifier;

use crate::access::{AccessVerifier, AllowAllAccessVerifier};
use crate::dataset_store::DatasetStore;

pub struct AppState {
    pub key_manager: KeyManager,
    pub dataset_store: Box<dyn DatasetStore>,
    pub credential_service: CredentialService,
    pub tee_verifier: TeeVerifier,
    pub measurement_registry: Box<dyn MeasurementRegistry>,
    pub request_id_tracker: Mutex<HashSet<[u8; 16]>>,
    pub output_gate: OutputGateService<AutoApprovePolicy>,
    pub upload_hmac_key: [u8; 32],
    pub access_verifier: Box<dyn AccessVerifier>,
}

impl AppState {
    pub fn new(
        root_key: &[u8; 32],
        dataset_store: Box<dyn DatasetStore>,
        tee_verifier: TeeVerifier,
    ) -> Result<Self, anyhow::Error> {
        let key_manager = KeyManager::from_root_key(root_key);
        let credential_service = CredentialService::from_root_key(root_key)?;
        let upload_hmac_key = key_manager.derive_upload_hmac_key()?;
        Ok(Self {
            key_manager,
            dataset_store,
            credential_service,
            tee_verifier,
            measurement_registry: Box::new(AllowAllMeasurements),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(AutoApprovePolicy),
            upload_hmac_key,
            access_verifier: Box::new(AllowAllAccessVerifier),
        })
    }
}
