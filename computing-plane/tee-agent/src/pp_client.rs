use compute_controller::JobCredential;
use key_manager::ecdhe::WrappedKeyBundle;
use key_manager::Key;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

use crate::error::AgentError;

#[derive(Serialize)]
struct RequestKeysBody {
    credential: JobCredential,
    request_id: String,
    quote: String,
    eph_pk: String,
    dataset_ids: Vec<u64>,
}

#[derive(Deserialize)]
struct RequestKeysResponse {
    encrypted_keys: String,
    nonce: String,
    pp_pk: String,
}

pub struct PpClient {
    base_url: String,
    http: reqwest::Client,
}

impl PpClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Send a RequestKeys request to the PP and return the wrapped key bundle.
    pub async fn request_keys(
        &self,
        credential: &JobCredential,
        request_id: &[u8; 16],
        quote: &[u8],
        eph_pk: &[u8; 32],
        dataset_ids: &[u64],
    ) -> Result<WrappedKeyBundle, AgentError> {
        let body = RequestKeysBody {
            credential: credential.clone(),
            request_id: hex::encode(request_id),
            quote: hex::encode(quote),
            eph_pk: hex::encode(eph_pk),
            dataset_ids: dataset_ids.to_vec(),
        };

        let url = format!("{}/v1/keys/request", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::PpRequest(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(AgentError::PpResponse(format!(
                "PP returned {status}: {body}"
            )));
        }

        let resp_body: RequestKeysResponse = resp
            .json()
            .await
            .map_err(|e| AgentError::PpResponse(format!("failed to parse response: {e}")))?;

        parse_key_bundle(&resp_body)
    }
}

/// Unwrap the ECDHE key bundle into DEKs + REK.
pub fn unwrap_keys(
    bundle: &WrappedKeyBundle,
    cvm_secret: &StaticSecret,
) -> Result<(Vec<Key>, Key), AgentError> {
    key_manager::ecdhe::unwrap_keys(bundle, cvm_secret).map_err(AgentError::Key)
}

fn parse_key_bundle(resp: &RequestKeysResponse) -> Result<WrappedKeyBundle, AgentError> {
    let ciphertext = hex::decode(&resp.encrypted_keys)
        .map_err(|e| AgentError::HexDecode(format!("encrypted_keys: {e}")))?;

    let nonce_bytes = hex::decode(&resp.nonce)
        .map_err(|e| AgentError::HexDecode(format!("nonce: {e}")))?;
    let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|v: Vec<u8>| {
        AgentError::PpResponse(format!("nonce: expected 12 bytes, got {}", v.len()))
    })?;

    let pp_pk_bytes = hex::decode(&resp.pp_pk)
        .map_err(|e| AgentError::HexDecode(format!("pp_pk: {e}")))?;
    let pp_pk: [u8; 32] = pp_pk_bytes.try_into().map_err(|v: Vec<u8>| {
        AgentError::PpResponse(format!("pp_pk: expected 32 bytes, got {}", v.len()))
    })?;

    Ok(WrappedKeyBundle {
        ciphertext,
        nonce,
        pp_pk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_serializes_hex() {
        let body = RequestKeysBody {
            credential: serde_json::from_value(serde_json::json!({
                "version": 1,
                "job_id": "job-1",
                "user": "alice",
                "datasets": [1],
                "nonce": "00000000000000000000000000000000",
                "issued_at": 1000000,
                "expires_at": 2000000,
                "signature": "aabb"
            }))
            .unwrap(),
            request_id: hex::encode([0x01; 16]),
            quote: hex::encode([0x02; 128]),
            eph_pk: hex::encode([0x03; 32]),
            dataset_ids: vec![1, 2],
        };

        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["request_id"], hex::encode([0x01; 16]));
        assert_eq!(json["eph_pk"], hex::encode([0x03; 32]));
        assert_eq!(json["dataset_ids"], serde_json::json!([1, 2]));
    }

    #[test]
    fn parse_key_bundle_valid() {
        let resp = RequestKeysResponse {
            encrypted_keys: hex::encode([0xAA; 64]),
            nonce: hex::encode([0xBB; 12]),
            pp_pk: hex::encode([0xCC; 32]),
        };

        let bundle = parse_key_bundle(&resp).unwrap();
        assert_eq!(bundle.ciphertext, vec![0xAA; 64]);
        assert_eq!(bundle.nonce, [0xBB; 12]);
        assert_eq!(bundle.pp_pk, [0xCC; 32]);
    }

    #[test]
    fn parse_key_bundle_invalid_nonce_length() {
        let resp = RequestKeysResponse {
            encrypted_keys: hex::encode([0xAA; 64]),
            nonce: hex::encode([0xBB; 8]), // wrong length
            pp_pk: hex::encode([0xCC; 32]),
        };

        let err = parse_key_bundle(&resp).err().expect("should fail");
        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn parse_key_bundle_invalid_pp_pk_length() {
        let resp = RequestKeysResponse {
            encrypted_keys: hex::encode([0xAA; 64]),
            nonce: hex::encode([0xBB; 12]),
            pp_pk: hex::encode([0xCC; 16]), // wrong length
        };

        let err = parse_key_bundle(&resp).err().expect("should fail");
        assert!(err.to_string().contains("pp_pk"));
    }

    #[test]
    fn parse_key_bundle_invalid_hex() {
        let resp = RequestKeysResponse {
            encrypted_keys: "not-valid-hex!".to_string(),
            nonce: hex::encode([0xBB; 12]),
            pp_pk: hex::encode([0xCC; 32]),
        };

        let err = parse_key_bundle(&resp).err().expect("should fail");
        assert!(err.to_string().contains("encrypted_keys"));
    }

    #[test]
    fn unwrap_keys_roundtrip() {
        use rand::rngs::OsRng;
        use x25519_dalek::PublicKey;

        let cvm_secret = StaticSecret::random_from_rng(OsRng);
        let cvm_pk = PublicKey::from(&cvm_secret);

        let dek = Key([0x11; 32]);
        let rek = Key([0x22; 32]);

        let bundle =
            key_manager::ecdhe::wrap_keys(&[dek], &rek, cvm_pk.as_bytes()).unwrap();
        let (deks, got_rek) = unwrap_keys(&bundle, &cvm_secret).unwrap();

        assert_eq!(deks.len(), 1);
        assert_eq!(deks[0].0, [0x11; 32]);
        assert_eq!(got_rek.0, [0x22; 32]);
    }

    #[test]
    fn pp_client_url_normalization() {
        let client = PpClient::new("http://localhost:3000/");
        assert_eq!(client.base_url, "http://localhost:3000");

        let client = PpClient::new("http://localhost:3000");
        assert_eq!(client.base_url, "http://localhost:3000");
    }
}
