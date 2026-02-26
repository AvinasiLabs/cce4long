use async_trait::async_trait;

/// Generates a TEE attestation quote binding the given reportdata.
#[async_trait]
pub trait Attester: Send + Sync {
    async fn generate_quote(&self, reportdata: &[u8; 64]) -> Result<Vec<u8>, crate::error::AgentError>;
}

/// Dev-mode attester. Produces quotes compatible with `tee_verifier::DevVerifier`.
pub struct DevAttester;

#[async_trait]
impl Attester for DevAttester {
    async fn generate_quote(&self, reportdata: &[u8; 64]) -> Result<Vec<u8>, crate::error::AgentError> {
        Ok(tee_verifier::build_dev_quote(reportdata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha512};

    fn test_reportdata() -> [u8; 64] {
        let mut rd = [0u8; 64];
        for (i, byte) in rd.iter_mut().enumerate() {
            *byte = i as u8;
        }
        rd
    }

    #[tokio::test]
    async fn dev_attester_produces_valid_quote() {
        let attester = DevAttester;
        let rd = test_reportdata();
        let quote = attester.generate_quote(&rd).await.unwrap();

        // Quote should be 128 bytes (64 reportdata + 64 padding)
        assert_eq!(quote.len(), 128);
        // First 64 bytes should be the reportdata
        assert_eq!(&quote[..64], &rd[..]);
    }

    #[tokio::test]
    async fn dev_attester_reportdata_binding() {
        let attester = DevAttester;

        let rd1 = [0xAA; 64];
        let rd2 = [0xBB; 64];

        let q1 = attester.generate_quote(&rd1).await.unwrap();
        let q2 = attester.generate_quote(&rd2).await.unwrap();

        // Different reportdata → different quotes
        assert_ne!(q1, q2);
        // Each quote embeds its own reportdata
        assert_eq!(&q1[..64], &rd1[..]);
        assert_eq!(&q2[..64], &rd2[..]);
    }

    #[tokio::test]
    async fn dev_attester_compatible_with_dev_verifier() {
        let attester = DevAttester;
        let verifier = tee_verifier::DevVerifier;

        // Simulate the real flow: SHA512(eph_pk || request_id)
        let mut hasher = Sha512::new();
        hasher.update([0x42; 32]); // fake eph_pk
        hasher.update([0x01; 16]); // fake request_id
        let reportdata: [u8; 64] = hasher.finalize().into();

        let quote = attester.generate_quote(&reportdata).await.unwrap();

        use tee_verifier::TeeVerifier;
        let result = verifier.verify(&quote, &reportdata).await.unwrap();
        assert_eq!(result.reportdata, reportdata);
    }
}
