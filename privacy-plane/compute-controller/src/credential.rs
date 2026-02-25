use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::ControllerError;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCredential {
    pub version: u8,
    pub job_id: String,
    pub user: String,
    pub datasets: Vec<u64>,
    #[serde(with = "hex_bytes_16")]
    pub nonce: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Hex serde for [u8; 16]
mod hex_bytes_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

/// Hex serde for Vec<u8>
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

pub struct CredentialService {
    signing_key: [u8; 32],
    used_nonces: Mutex<HashSet<[u8; 16]>>,
}

impl CredentialService {
    /// Derive signing key from root key using HKDF.
    pub fn from_root_key(root_key: &[u8; 32]) -> Result<Self, ControllerError> {
        let hk = Hkdf::<Sha256>::new(None, root_key);
        let mut signing_key = [0u8; 32];
        hk.expand(b"credential-signing", &mut signing_key)
            .map_err(|_| ControllerError::KeyDerivationFailed)?;
        Ok(Self {
            signing_key,
            used_nonces: Mutex::new(HashSet::new()),
        })
    }

    /// Issue a credential for a job.
    pub fn issue(
        &self,
        job_id: &str,
        user: &str,
        datasets: Vec<u64>,
    ) -> JobCredential {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = now + 600; // 10 minutes

        let mut cred = JobCredential {
            version: 1,
            job_id: job_id.to_string(),
            user: user.to_string(),
            datasets,
            nonce,
            issued_at: now,
            expires_at,
            signature: Vec::new(),
        };
        cred.signature = self.sign(&cred);
        cred
    }

    /// Verify and consume a credential. Returns Ok(()) if valid.
    /// Consumes the nonce to prevent replay.
    pub fn verify_and_consume(&self, cred: &JobCredential) -> Result<(), ControllerError> {
        // Verify signature
        let expected_sig = self.sign(cred);
        if cred.signature != expected_sig {
            return Err(ControllerError::InvalidSignature);
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > cred.expires_at {
            return Err(ControllerError::Expired);
        }

        // Consume nonce (replay protection)
        let mut nonces = self.used_nonces.lock().unwrap();
        if !nonces.insert(cred.nonce) {
            return Err(ControllerError::NonceReused);
        }

        Ok(())
    }

    /// Canonical HMAC-SHA256 signature.
    /// message = version || job_id || user || datasets(each u64 BE) || nonce || issued_at || expires_at
    fn sign(&self, cred: &JobCredential) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC accepts any key size");
        mac.update(&[cred.version]);
        mac.update(cred.job_id.as_bytes());
        mac.update(cred.user.as_bytes());
        for &ds in &cred.datasets {
            mac.update(&ds.to_be_bytes());
        }
        mac.update(&cred.nonce);
        mac.update(&cred.issued_at.to_be_bytes());
        mac.update(&cred.expires_at.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> CredentialService {
        CredentialService::from_root_key(&[0xAA; 32]).unwrap()
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let svc = test_service();
        let cred = svc.issue("job-1", "alice", vec![1, 2]);
        assert!(svc.verify_and_consume(&cred).is_ok());
    }

    #[test]
    fn tampered_job_id_fails() {
        let svc = test_service();
        let mut cred = svc.issue("job-1", "alice", vec![1]);
        cred.job_id = "job-2".to_string();
        assert!(matches!(
            svc.verify_and_consume(&cred),
            Err(ControllerError::InvalidSignature)
        ));
    }

    #[test]
    fn tampered_datasets_fails() {
        let svc = test_service();
        let mut cred = svc.issue("job-1", "alice", vec![1, 2]);
        cred.datasets = vec![1, 2, 3];
        assert!(matches!(
            svc.verify_and_consume(&cred),
            Err(ControllerError::InvalidSignature)
        ));
    }

    #[test]
    fn tampered_user_fails() {
        let svc = test_service();
        let mut cred = svc.issue("job-1", "alice", vec![1]);
        cred.user = "bob".to_string();
        assert!(matches!(
            svc.verify_and_consume(&cred),
            Err(ControllerError::InvalidSignature)
        ));
    }

    #[test]
    fn expired_credential_rejected() {
        let svc = test_service();
        let mut cred = svc.issue("job-1", "alice", vec![1]);
        // Force expiration in the past
        cred.expires_at = 0;
        // Re-sign with correct expiration
        cred.signature = svc.sign(&cred);
        assert!(matches!(
            svc.verify_and_consume(&cred),
            Err(ControllerError::Expired)
        ));
    }

    #[test]
    fn nonce_replay_rejected() {
        let svc = test_service();
        let cred = svc.issue("job-1", "alice", vec![1]);
        assert!(svc.verify_and_consume(&cred).is_ok());
        assert!(matches!(
            svc.verify_and_consume(&cred),
            Err(ControllerError::NonceReused)
        ));
    }

    #[test]
    fn two_issues_have_different_nonces() {
        let svc = test_service();
        let c1 = svc.issue("job-1", "alice", vec![1]);
        let c2 = svc.issue("job-1", "alice", vec![1]);
        assert_ne!(c1.nonce, c2.nonce);
    }

    #[test]
    fn serde_json_roundtrip() {
        let svc = test_service();
        let cred = svc.issue("job-1", "alice", vec![1, 2]);
        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: JobCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.job_id, deserialized.job_id);
        assert_eq!(cred.nonce, deserialized.nonce);
        assert_eq!(cred.signature, deserialized.signature);
        // Verify deserialized credential is still valid
        assert!(svc.verify_and_consume(&deserialized).is_ok());
    }

    #[test]
    fn different_root_key_cannot_verify() {
        let svc1 = CredentialService::from_root_key(&[0xAA; 32]).unwrap();
        let svc2 = CredentialService::from_root_key(&[0xBB; 32]).unwrap();
        let cred = svc1.issue("job-1", "alice", vec![1]);
        assert!(matches!(
            svc2.verify_and_consume(&cred),
            Err(ControllerError::InvalidSignature)
        ));
    }
}
