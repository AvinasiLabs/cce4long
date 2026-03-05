use axum::extract::State;
use axum::Json;
use key_manager::DatasetId;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;
use crate::upload_token::issue_token;

use super::error::ApiError;

/// EIP-191 personal_sign message prefix.
const EIP191_PREFIX: &str = "\x19Ethereum Signed Message:\n";

/// Default upload token TTL: 1 hour.
const DEFAULT_TTL_SECS: u64 = 3600;

#[derive(Deserialize)]
pub struct UploadTokenRequest {
    pub wallet_address: DatasetId,
    pub dataset_id: DatasetId,
    /// Hex-encoded signature (65 bytes: r[32] || s[32] || v[1])
    pub signature: String,
    /// The challenge message that was signed.
    pub message: String,
}

#[derive(Serialize)]
pub struct UploadTokenResponse {
    pub token: String,
    pub expires_in: u64,
}

/// Recover the signer address from an EIP-191 personal_sign signature.
pub(crate) fn recover_address(message: &str, sig_hex: &str) -> Result<[u8; 20], String> {
    let sig_bytes = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(sig_hex))
        .map_err(|e| format!("invalid signature hex: {e}"))?;

    if sig_bytes.len() != 65 {
        return Err(format!(
            "signature must be 65 bytes, got {}",
            sig_bytes.len()
        ));
    }

    // EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
    let prefixed = format!("{}{}{}", EIP191_PREFIX, message.len(), message);
    let hash = keccak256(prefixed.as_bytes());

    // Parse r, s, v
    let r_s = &sig_bytes[..64];
    let v = sig_bytes[64];
    // v is either 0/1 or 27/28
    let recovery_id = match v {
        0 | 27 => RecoveryId::new(false, false),
        1 | 28 => RecoveryId::new(true, false),
        _ => return Err(format!("invalid recovery id: {v}")),
    };

    let signature =
        Signature::from_slice(r_s).map_err(|e| format!("invalid signature bytes: {e}"))?;

    let recovered_key =
        VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)
            .map_err(|e| format!("ecrecover failed: {e}"))?;

    // Verify the signature is actually valid
    recovered_key
        .verify_prehash(&hash, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))?;

    // Derive Ethereum address: keccak256(uncompressed_pubkey[1..]) -> last 20 bytes
    let pubkey_bytes = recovered_key
        .to_encoded_point(false);
    let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..]; // skip 0x04 prefix
    let addr_hash = keccak256(pubkey_uncompressed);
    let mut address = [0u8; 20];
    address.copy_from_slice(&addr_hash[12..]);

    Ok(address)
}

/// Keccak-256 hash (Ethereum uses keccak, not SHA3-256).
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest as Sha3Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// POST /v1/upload-token
///
/// Verifies wallet signature, checks dataset ownership, and issues an upload token.
pub async fn issue_upload_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UploadTokenRequest>,
) -> Result<Json<UploadTokenResponse>, ApiError> {
    // 1. Recover signer address from EIP-191 signature
    let recovered = recover_address(&body.message, &body.signature)
        .map_err(ApiError::SignatureRecoveryFailed)?;

    // 2. Compare recovered address with claimed wallet_address
    let claimed: [u8; 20] = body.wallet_address.into();
    if recovered != claimed {
        return Err(ApiError::SignatureRecoveryFailed(
            "recovered address does not match wallet_address".into(),
        ));
    }

    // 3. Check that the wallet is the owner of the dataset
    let is_owner = state
        .access_verifier
        .is_owner(&body.dataset_id, &recovered)
        .await
        .map_err(|e| ApiError::VerifierError(e.to_string()))?;
    if !is_owner {
        return Err(ApiError::DatasetNotAuthorized(
            "wallet is not the dataset owner".into(),
        ));
    }

    // 4. Issue upload token bound to wallet + dataset_id
    let token = issue_token(
        body.wallet_address,
        body.dataset_id,
        &state.upload_hmac_key,
        DEFAULT_TTL_SECS,
    );

    Ok(Json(UploadTokenResponse {
        token,
        expires_in: DEFAULT_TTL_SECS,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_known_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = keccak256(b"");
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
