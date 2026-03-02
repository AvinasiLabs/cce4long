use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use key_manager::DatasetId;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadTokenPayload {
    pub v: u8,
    pub wallet: DatasetId,
    pub dataset_id: DatasetId,
    pub exp: u64,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidFormat,
    InvalidPayload(String),
    InvalidSignature,
    Expired,
    DatasetMismatch,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidFormat => write!(f, "invalid token format"),
            AuthError::InvalidPayload(e) => write!(f, "invalid token payload: {e}"),
            AuthError::InvalidSignature => write!(f, "invalid token signature"),
            AuthError::Expired => write!(f, "token expired"),
            AuthError::DatasetMismatch => write!(f, "token dataset_id mismatch"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Extract Bearer token from an Authorization header.
pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<&str, AuthError> {
    let auth = headers
        .get("authorization")
        .ok_or(AuthError::InvalidFormat)?
        .to_str()
        .map_err(|_| AuthError::InvalidFormat)?;
    auth.strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidFormat)
}

/// Issue an upload token binding a wallet to a specific dataset.
pub fn issue_token(
    wallet: DatasetId,
    dataset_id: DatasetId,
    hmac_key: &[u8; 32],
    ttl_secs: u64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = UploadTokenPayload {
        v: 1,
        wallet,
        dataset_id,
        exp: now + ttl_secs,
    };

    let payload_json = serde_json::to_vec(&payload).unwrap();
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key size");
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    format!("{}.{}", payload_b64, sig_b64)
}

/// Verify an upload token. Returns the payload if valid.
pub fn verify_token(token: &str, hmac_key: &[u8; 32]) -> Result<UploadTokenPayload, AuthError> {
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(AuthError::InvalidFormat)?;

    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key size");
    mac.update(payload_b64.as_bytes());
    let expected_sig = mac.finalize().into_bytes();

    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AuthError::InvalidFormat)?;

    if expected_sig.as_slice() != provided_sig.as_slice() {
        return Err(AuthError::InvalidSignature);
    }

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AuthError::InvalidFormat)?;
    let payload: UploadTokenPayload =
        serde_json::from_slice(&payload_bytes).map_err(|e| AuthError::InvalidPayload(e.to_string()))?;

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > payload.exp {
        return Err(AuthError::Expired);
    }

    Ok(payload)
}

/// Verify token and also check that the token's dataset_id matches the request.
pub fn verify_token_for_dataset(
    token: &str,
    hmac_key: &[u8; 32],
    expected_dataset_id: &DatasetId,
) -> Result<UploadTokenPayload, AuthError> {
    let payload = verify_token(token, hmac_key)?;
    if &payload.dataset_id != expected_dataset_id {
        return Err(AuthError::DatasetMismatch);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAA; 32]
    }

    fn test_wallet() -> DatasetId {
        DatasetId::from([0x11; 20])
    }

    fn test_dataset() -> DatasetId {
        DatasetId::from([0x22; 20])
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let token = issue_token(test_wallet(), test_dataset(), &test_key(), 3600);
        let payload = verify_token(&token, &test_key()).unwrap();
        assert_eq!(payload.v, 1);
        assert_eq!(payload.wallet, test_wallet());
        assert_eq!(payload.dataset_id, test_dataset());
    }

    #[test]
    fn expired_token_rejected() {
        let token = issue_token(test_wallet(), test_dataset(), &test_key(), 0);
        // Wait a tiny bit to ensure expiration
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let err = verify_token(&token, &test_key()).unwrap_err();
        assert!(matches!(err, AuthError::Expired));
    }

    #[test]
    fn tampered_token_rejected() {
        let mut token = issue_token(test_wallet(), test_dataset(), &test_key(), 3600);
        // Tamper with one character in the payload
        unsafe { token.as_bytes_mut()[5] ^= 0xFF; }
        let err = verify_token(&token, &test_key()).unwrap_err();
        // Could be InvalidSignature or InvalidFormat depending on where we tampered
        assert!(matches!(
            err,
            AuthError::InvalidSignature | AuthError::InvalidFormat | AuthError::InvalidPayload(_)
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let token = issue_token(test_wallet(), test_dataset(), &test_key(), 3600);
        let wrong_key = [0xBB; 32];
        let err = verify_token(&token, &wrong_key).unwrap_err();
        assert!(matches!(err, AuthError::InvalidSignature));
    }

    #[test]
    fn dataset_mismatch_rejected() {
        let token = issue_token(test_wallet(), test_dataset(), &test_key(), 3600);
        let other_dataset = DatasetId::from([0x99; 20]);
        let err = verify_token_for_dataset(&token, &test_key(), &other_dataset).unwrap_err();
        assert!(matches!(err, AuthError::DatasetMismatch));
    }

    #[test]
    fn dataset_match_succeeds() {
        let token = issue_token(test_wallet(), test_dataset(), &test_key(), 3600);
        let payload = verify_token_for_dataset(&token, &test_key(), &test_dataset()).unwrap();
        assert_eq!(payload.dataset_id, test_dataset());
    }

    #[test]
    fn invalid_format() {
        let err = verify_token("no-dot-separator", &test_key()).unwrap_err();
        assert!(matches!(err, AuthError::InvalidFormat));
    }
}
