use key_manager::{DevRootKeyProvider, KeyManager};

use crate::storage::Storage;

pub struct AppState {
    pub key_manager: KeyManager<DevRootKeyProvider>,
    pub storage: Box<dyn Storage>,
}

impl AppState {
    pub fn dev(storage: Box<dyn Storage>) -> Self {
        Self {
            key_manager: KeyManager::new(DevRootKeyProvider::new()),
            storage,
        }
    }
}
