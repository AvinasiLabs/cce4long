use std::collections::HashSet;
use std::sync::Mutex;

use compute_controller::{
    CredentialService, DevMeasurementRegistry, MeasurementRegistry,
};
use key_manager::{DevRootKeyProvider, KeyManager, RootKeyProvider};
use output_gate::{DevReviewPolicy, OutputGateService};
use tee_verifier::{DevVerifier, TeeVerifier};

use crate::storage::Storage;

pub struct AppState {
    pub key_manager: KeyManager<DevRootKeyProvider>,
    pub storage: Box<dyn Storage>,
    pub credential_service: CredentialService,
    pub tee_verifier: Box<dyn TeeVerifier>,
    pub measurement_registry: Box<dyn MeasurementRegistry>,
    pub request_id_tracker: Mutex<HashSet<[u8; 16]>>,
    pub output_gate: OutputGateService<DevReviewPolicy>,
}

impl AppState {
    pub fn dev(storage: Box<dyn Storage>) -> Self {
        let root = DevRootKeyProvider::new();
        let credential_service =
            CredentialService::from_root_key(root.root_key()).expect("credential key derivation");
        let key_manager = KeyManager::new(root);
        Self {
            key_manager,
            storage,
            credential_service,
            tee_verifier: Box::new(DevVerifier),
            measurement_registry: Box::new(DevMeasurementRegistry),
            request_id_tracker: Mutex::new(HashSet::new()),
            output_gate: OutputGateService::new(DevReviewPolicy),
        }
    }
}
