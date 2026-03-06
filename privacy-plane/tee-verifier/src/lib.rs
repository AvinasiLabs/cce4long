//! TEE quote verification service.
//!
//! Supports multiple TEE types via a dispatcher pattern:
//! each TeeType maps to a per-TEE Verifier implementation.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TeeType {
    Sample,
    Tdx,
    Snp,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub tee_type: TeeType,
    pub measurement: String,
    pub reportdata: [u8; 64],
}

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("reportdata mismatch")]
    ReportdataMismatch,
    #[error("invalid evidence format: {0}")]
    InvalidFormat(String),
    #[error("unsupported TEE type: {0:?}")]
    UnsupportedTeeType(TeeType),
}

/// Per-TEE verifier. Each TEE type has its own implementation
/// that knows how to parse and verify its evidence format.
#[async_trait]
pub trait Verifier: Send + Sync {
    async fn verify(
        &self,
        evidence: &serde_json::Value,
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError>;
}

/// Dispatcher: routes verification to the correct per-TEE verifier.
pub struct TeeVerifier {
    verifiers: HashMap<TeeType, Box<dyn Verifier>>,
}

impl Default for TeeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeVerifier {
    pub fn new() -> Self {
        Self {
            verifiers: HashMap::new(),
        }
    }

    pub fn register(mut self, tee_type: TeeType, v: impl Verifier + 'static) -> Self {
        self.verifiers.insert(tee_type, Box::new(v));
        self
    }

    pub async fn verify(
        &self,
        tee_type: &TeeType,
        evidence: &serde_json::Value,
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError> {
        let verifier = self
            .verifiers
            .get(tee_type)
            .ok_or(VerifierError::UnsupportedTeeType(*tee_type))?;
        verifier.verify(evidence, expected_reportdata).await
    }
}

/// Verifier for CoCo SampleAttester evidence.
///
/// Evidence format: `{"svn": "1", "report_data": "<base64(reportdata)>"}`
/// Compares decoded report_data against expected_reportdata.
pub struct SampleVerifier;

impl SampleVerifier {
    pub fn sample_measurement() -> &'static str {
        "sample-measurement-000000000000000000000000000000000000000000000000"
    }
}

#[async_trait]
impl Verifier for SampleVerifier {
    async fn verify(
        &self,
        evidence: &serde_json::Value,
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError> {
        use base64::Engine as _;

        let rd_b64 = evidence["report_data"]
            .as_str()
            .ok_or_else(|| VerifierError::InvalidFormat("missing 'report_data' field".into()))?;

        let rd_bytes = base64::engine::general_purpose::STANDARD
            .decode(rd_b64)
            .map_err(|e| VerifierError::InvalidFormat(format!("report_data base64: {e}")))?;

        let actual_reportdata: [u8; 64] = rd_bytes
            .try_into()
            .map_err(|v: Vec<u8>| {
                VerifierError::InvalidFormat(format!(
                    "report_data: expected 64 bytes, got {}",
                    v.len()
                ))
            })?;

        if actual_reportdata != *expected_reportdata {
            return Err(VerifierError::ReportdataMismatch);
        }

        Ok(VerificationResult {
            tee_type: TeeType::Sample,
            measurement: Self::sample_measurement().to_string(),
            reportdata: actual_reportdata,
        })
    }
}

/// Build a CoCo SampleAttester-compatible evidence JSON for testing.
pub fn build_sample_evidence(reportdata: &[u8; 64]) -> serde_json::Value {
    use base64::Engine as _;
    let rd_b64 = base64::engine::general_purpose::STANDARD.encode(reportdata);
    serde_json::json!({
        "svn": "1",
        "report_data": rd_b64
    })
}

/// DCAP-based verifier for TDX quotes. Fetches collateral from Intel PCCS
/// and verifies quote signature + cert chain.
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
impl Verifier for DcapVerifier {
    async fn verify(
        &self,
        evidence: &serde_json::Value,
        expected_reportdata: &[u8; 64],
    ) -> Result<VerificationResult, VerifierError> {
        use base64::Engine as _;
        use dcap_qvl::quote::Report;

        // Extract and decode the raw quote from evidence JSON
        let quote_b64 = evidence["quote"]
            .as_str()
            .ok_or_else(|| VerifierError::InvalidFormat("missing 'quote' field".into()))?;

        let quote = base64::engine::general_purpose::STANDARD
            .decode(quote_b64)
            .map_err(|e| VerifierError::InvalidFormat(format!("quote base64: {e}")))?;

        let collateral = dcap_qvl::collateral::get_collateral(&self.pccs_url, &quote)
            .await
            .map_err(|e| VerifierError::InvalidFormat(format!("collateral fetch: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let verified = dcap_qvl::verify::verify(&quote, &collateral, now)
            .map_err(|e| VerifierError::InvalidFormat(format!("quote verification: {e}")))?;

        tracing::info!(status = %verified.status, "DCAP quote verified");

        let (tee_type, measurement, reportdata) = match &verified.report {
            Report::TD10(td) => (
                TeeType::Tdx,
                hex::encode(td.mr_td),
                td.report_data,
            ),
            Report::TD15(td) => (
                TeeType::Tdx,
                hex::encode(td.base.mr_td),
                td.base.report_data,
            ),
            Report::SgxEnclave(_) => {
                return Err(VerifierError::InvalidFormat("SGX not yet supported".into()));
            }
        };

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
    async fn sample_verifier_matching_reportdata() {
        let rd = test_reportdata();
        let evidence = build_sample_evidence(&rd);
        let result = SampleVerifier.verify(&evidence, &rd).await.unwrap();
        assert_eq!(result.reportdata, rd);
        assert_eq!(result.tee_type, TeeType::Sample);
        assert_eq!(result.measurement, SampleVerifier::sample_measurement());
    }

    #[tokio::test]
    async fn sample_verifier_mismatched_reportdata() {
        let rd = test_reportdata();
        let evidence = build_sample_evidence(&rd);
        let wrong_rd = [0xFF; 64];
        let result = SampleVerifier.verify(&evidence, &wrong_rd).await;
        assert!(matches!(result, Err(VerifierError::ReportdataMismatch)));
    }

    #[tokio::test]
    async fn sample_verifier_missing_field() {
        let rd = test_reportdata();
        let evidence = serde_json::json!({"svn": "1"});
        let result = SampleVerifier.verify(&evidence, &rd).await;
        assert!(matches!(result, Err(VerifierError::InvalidFormat(_))));
    }

    #[tokio::test]
    async fn sample_verifier_invalid_base64() {
        let rd = test_reportdata();
        let evidence = serde_json::json!({"svn": "1", "report_data": "not-valid-base64!!!"});
        let result = SampleVerifier.verify(&evidence, &rd).await;
        assert!(matches!(result, Err(VerifierError::InvalidFormat(_))));
    }

    #[tokio::test]
    async fn sample_verifier_wrong_length() {
        use base64::Engine as _;
        let rd = test_reportdata();
        let short_b64 = base64::engine::general_purpose::STANDARD.encode(&[0u8; 32]);
        let evidence = serde_json::json!({"svn": "1", "report_data": short_b64});
        let result = SampleVerifier.verify(&evidence, &rd).await;
        assert!(matches!(result, Err(VerifierError::InvalidFormat(_))));
    }

    #[tokio::test]
    async fn sample_measurement_is_deterministic() {
        let rd = test_reportdata();
        let evidence = build_sample_evidence(&rd);
        let r1 = SampleVerifier.verify(&evidence, &rd).await.unwrap();
        let r2 = SampleVerifier.verify(&evidence, &rd).await.unwrap();
        assert_eq!(r1.measurement, r2.measurement);
    }

    #[test]
    fn build_sample_evidence_roundtrip() {
        let rd = test_reportdata();
        let evidence = build_sample_evidence(&rd);
        assert!(evidence["svn"].as_str().is_some());
        assert!(evidence["report_data"].as_str().is_some());
    }

    #[test]
    fn tee_type_serde_lowercase() {
        assert_eq!(serde_json::to_string(&TeeType::Sample).unwrap(), "\"sample\"");
        assert_eq!(serde_json::to_string(&TeeType::Tdx).unwrap(), "\"tdx\"");
        assert_eq!(serde_json::to_string(&TeeType::Snp).unwrap(), "\"snp\"");

        let roundtrip: TeeType = serde_json::from_str("\"sample\"").unwrap();
        assert_eq!(roundtrip, TeeType::Sample);
    }

    #[tokio::test]
    async fn dispatcher_routes_to_correct_verifier() {
        let rd = test_reportdata();
        let evidence = build_sample_evidence(&rd);

        let dispatcher = TeeVerifier::new().register(TeeType::Sample, SampleVerifier);

        let result = dispatcher
            .verify(&TeeType::Sample, &evidence, &rd)
            .await
            .unwrap();
        assert_eq!(result.tee_type, TeeType::Sample);
    }

    #[tokio::test]
    async fn dispatcher_rejects_unregistered_tee_type() {
        let rd = test_reportdata();
        let evidence = build_sample_evidence(&rd);

        let dispatcher = TeeVerifier::new().register(TeeType::Sample, SampleVerifier);

        let result = dispatcher.verify(&TeeType::Tdx, &evidence, &rd).await;
        assert!(matches!(result, Err(VerifierError::UnsupportedTeeType(TeeType::Tdx))));
    }
}
