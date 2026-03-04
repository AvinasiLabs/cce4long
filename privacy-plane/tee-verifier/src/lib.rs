//! TEE quote verification service.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TeeType {
    TDX,
    SEVSNP,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub tee_type: TeeType,
    pub measurement: String,
    pub reportdata: [u8; 64],
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("quote too short: expected at least {expected} bytes, got {actual}")]
    QuoteTooShort { expected: usize, actual: usize },
    #[error("reportdata mismatch")]
    ReportdataMismatch,
    #[error("invalid quote format: {0}")]
    InvalidFormat(String),
}

#[async_trait]
pub trait TeeVerifier: Send + Sync {
    async fn verify(
        &self,
        quote: &[u8],
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError>;
}

/// Dev-only verifier. Does NOT verify TEE signatures, but DOES check
/// that reportdata in the quote matches expected_reportdata.
///
/// Dev quote format: first 64 bytes = reportdata, remaining bytes = padding.
pub struct DevVerifier;

impl DevVerifier {
    /// Fixed measurement string for dev mode.
    pub fn dev_measurement() -> &'static str {
        "dev-measurement-000000000000000000000000000000000000000000000000"
    }
}

/// Build a dev quote from reportdata. First 64 bytes = reportdata, rest = zero padding.
pub fn build_dev_quote(reportdata: &[u8; 64]) -> Vec<u8> {
    let mut quote = Vec::with_capacity(128);
    quote.extend_from_slice(reportdata);
    quote.extend_from_slice(&[0u8; 64]); // padding
    quote
}

#[async_trait]
impl TeeVerifier for DevVerifier {
    async fn verify(
        &self,
        quote: &[u8],
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError> {
        if quote.len() < 64 {
            return Err(VerifierError::QuoteTooShort {
                expected: 64,
                actual: quote.len(),
            });
        }

        let actual_reportdata: [u8; 64] = quote[..64]
            .try_into()
            .map_err(|_| VerifierError::InvalidFormat("failed to extract reportdata".into()))?;

        if actual_reportdata != *expected_reportdata {
            return Err(VerifierError::ReportdataMismatch);
        }

        Ok(VerificationResult {
            tee_type: TeeType::TDX,
            measurement: DevVerifier::dev_measurement().to_string(),
            reportdata: actual_reportdata,
        })
    }
}

/// DCAP-based verifier using dcap-qvl. Supports TDX (and SGX structurally).
/// Fetches collateral from Intel PCCS and verifies quote signature + cert chain.
#[cfg(feature = "dcap")]
pub struct DcapVerifier {
    pccs_url: String,
}

#[cfg(feature = "dcap")]
impl DcapVerifier {
    pub fn new(pccs_url: String) -> Self {
        Self { pccs_url }
    }
}

#[cfg(feature = "dcap")]
#[async_trait]
impl TeeVerifier for DcapVerifier {
    async fn verify(
        &self,
        quote: &[u8],
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError> {
        use dcap_qvl::quote::Report;

        // 1. Fetch collateral from Intel PCCS
        let collateral = dcap_qvl::collateral::get_collateral(&self.pccs_url, quote)
            .await
            .map_err(|e| VerifierError::InvalidFormat(format!("collateral fetch: {e}")))?;

        // 2. Verify quote signature + cert chain
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let verified = dcap_qvl::verify::verify(quote, &collateral, now)
            .map_err(|e| VerifierError::InvalidFormat(format!("quote verification: {e}")))?;

        tracing::info!(status = %verified.status, "DCAP quote verified");

        // 3. Extract reportdata, measurement, and TEE type from the verified report
        let (tee_type, measurement, reportdata) = match &verified.report {
            Report::TD10(td) => (
                TeeType::TDX,
                hex::encode(td.mr_td),
                td.report_data,
            ),
            Report::TD15(td) => (
                TeeType::TDX,
                hex::encode(td.base.mr_td),
                td.base.report_data,
            ),
            Report::SgxEnclave(_) => {
                return Err(VerifierError::InvalidFormat("SGX not yet supported".into()));
            }
        };

        // 4. Verify reportdata matches expected
        if reportdata != *expected_reportdata {
            return Err(VerifierError::ReportdataMismatch);
        }

        Ok(VerificationResult {
            tee_type,
            measurement,
            reportdata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_reportdata() -> [u8; 64] {
        let mut rd = [0u8; 64];
        for (i, byte) in rd.iter_mut().enumerate() {
            *byte = i as u8;
        }
        rd
    }

    #[tokio::test]
    async fn matching_reportdata_passes() {
        let rd = test_reportdata();
        let quote = build_dev_quote(&rd);
        let result = DevVerifier.verify(&quote, &rd).await.unwrap();
        assert_eq!(result.reportdata, rd);
        assert_eq!(result.tee_type, TeeType::TDX);
    }

    #[tokio::test]
    async fn mismatched_reportdata_rejected() {
        let rd = test_reportdata();
        let quote = build_dev_quote(&rd);
        let wrong_rd = [0xFF; 64];
        let result = DevVerifier.verify(&quote, &wrong_rd).await;
        assert!(matches!(result, Err(VerifierError::ReportdataMismatch)));
    }

    #[tokio::test]
    async fn short_quote_rejected() {
        let rd = test_reportdata();
        let short = &rd[..32]; // only 32 bytes
        let result = DevVerifier.verify(short, &rd).await;
        assert!(matches!(
            result,
            Err(VerifierError::QuoteTooShort {
                expected: 64,
                actual: 32
            })
        ));
    }

    #[tokio::test]
    async fn dev_measurement_is_deterministic() {
        let rd = test_reportdata();
        let quote = build_dev_quote(&rd);
        let r1 = DevVerifier.verify(&quote, &rd).await.unwrap();
        let r2 = DevVerifier.verify(&quote, &rd).await.unwrap();
        assert_eq!(r1.measurement, r2.measurement);
        assert_eq!(r1.measurement, DevVerifier::dev_measurement());
    }

    #[tokio::test]
    async fn minimum_64_byte_quote_works() {
        let rd = test_reportdata();
        // Exactly 64 bytes — no padding
        let quote = rd.to_vec();
        let result = DevVerifier.verify(&quote, &rd).await.unwrap();
        assert_eq!(result.reportdata, rd);
    }

    #[test]
    fn build_dev_quote_correctness() {
        let rd = test_reportdata();
        let quote = build_dev_quote(&rd);
        assert_eq!(quote.len(), 128);
        assert_eq!(&quote[..64], &rd[..]);
        assert_eq!(&quote[64..], &[0u8; 64]);
    }
}
