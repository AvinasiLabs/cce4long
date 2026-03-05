use async_trait::async_trait;
use tee_verifier::TeeType;

/// Generates TEE attestation evidence binding the given reportdata.
#[async_trait]
pub trait Attester: Send + Sync {
    fn tee_type(&self) -> TeeType;
    async fn get_evidence(
        &self,
        reportdata: &[u8; 64],
    ) -> Result<serde_json::Value, crate::error::AgentError>;
}

/// CoCo-based attester using confidential-containers guest-components.
/// Auto-detects TEE type (TDX, SEV-SNP, CCA, etc.) at construction time.
/// On macOS / non-TEE environments, falls back to Sample attester.
pub struct CocoAttester {
    tee_type: TeeType,
    inner: attester::BoxedAttester,
}

impl CocoAttester {
    /// Auto-detect TEE type and create the appropriate attester.
    /// Detection order: TDX → SGX → SNP → CCA → SE → Sample (dev fallback).
    pub fn new() -> Result<Self, crate::error::AgentError> {
        use kbs_types::Tee;

        let tee = attester::detect_tee_type();
        tracing::info!(?tee, "detected TEE type");

        let tee_type = match tee {
            Tee::Tdx => TeeType::Tdx,
            Tee::Snp => TeeType::Snp,
            _ => TeeType::Sample,
        };

        let inner = attester::BoxedAttester::try_from(tee)
            .map_err(|e| crate::error::AgentError::Config(format!("CoCo attester init: {e}")))?;
        Ok(Self { tee_type, inner })
    }
}

#[async_trait]
impl Attester for CocoAttester {
    fn tee_type(&self) -> TeeType {
        self.tee_type
    }

    async fn get_evidence(
        &self,
        reportdata: &[u8; 64],
    ) -> Result<serde_json::Value, crate::error::AgentError> {
        let evidence = self
            .inner
            .get_evidence(reportdata.to_vec())
            .await
            .map_err(|e| crate::error::AgentError::Config(format!("CoCo get_evidence: {e}")))?;

        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn coco_attester_sample_mode() {
        let attester = CocoAttester::new().unwrap();
        // On macOS / non-TEE, should detect Sample
        assert_eq!(attester.tee_type(), TeeType::Sample);

        let rd = [0x42u8; 64];
        let evidence = attester.get_evidence(&rd).await.unwrap();

        // Sample evidence should contain report_data
        assert!(evidence["report_data"].is_string());
    }

    #[tokio::test]
    async fn coco_attester_evidence_verifiable() {
        let attester = CocoAttester::new().unwrap();
        let rd: [u8; 64] = {
            let mut buf = [0u8; 64];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            buf
        };

        let evidence = attester.get_evidence(&rd).await.unwrap();
        let verifier = tee_verifier::SampleVerifier;

        use tee_verifier::Verifier;
        let result = verifier.verify(&evidence, &rd).await.unwrap();
        assert_eq!(result.reportdata, rd);
        assert_eq!(result.tee_type, TeeType::Sample);
    }
}
