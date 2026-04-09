//! Artifact schemas used by CLI output and verification flows.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ARTIFACT_VERSION: &str = "v1";
pub const PROOF_VERSION: &str = "v4";
pub const VM_VERSION: &str = "v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicOutput {
    pub accumulator: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub artifact_version: String,
    pub proof_version: String,
    pub vm_version: String,
    pub transcript: String,
    pub trace_len: u64,
    pub trace_digest: String,
    pub air_reason_code: String,
}

impl Receipt {
    #[must_use]
    /// Creates a receipt with current schema version anchors.
    pub fn new(
        transcript: String,
        trace_len: u64,
        trace_digest: String,
        air_reason_code: String,
    ) -> Self {
        Self {
            artifact_version: ARTIFACT_VERSION.to_string(),
            proof_version: PROOF_VERSION.to_string(),
            vm_version: VM_VERSION.to_string(),
            transcript,
            trace_len,
            trace_digest,
            air_reason_code,
        }
    }
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact serialization failed")]
    Serialize(#[source] serde_json::Error),
    #[error("artifact deserialization failed")]
    Deserialize(#[source] serde_json::Error),
}

/// Encodes public output into the canonical JSON artifact format.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn encode_public_output(value: &PublicOutput) -> Result<Vec<u8>, ArtifactError> {
    serde_json::to_vec_pretty(value).map_err(ArtifactError::Serialize)
}

/// Decodes public output from the canonical JSON artifact format.
///
/// # Errors
///
/// Returns an error when deserialization fails.
pub fn decode_public_output(bytes: &[u8]) -> Result<PublicOutput, ArtifactError> {
    serde_json::from_slice(bytes).map_err(ArtifactError::Deserialize)
}

/// Encodes receipt metadata into the canonical JSON artifact format.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn encode_receipt(value: &Receipt) -> Result<Vec<u8>, ArtifactError> {
    serde_json::to_vec_pretty(value).map_err(ArtifactError::Serialize)
}

/// Decodes receipt metadata from the canonical JSON artifact format.
///
/// # Errors
///
/// Returns an error when deserialization fails.
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, ArtifactError> {
    serde_json::from_slice(bytes).map_err(ArtifactError::Deserialize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_roundtrip() {
        let receipt = Receipt::new(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            3,
            "abc".to_string(),
            "ok".to_string(),
        );
        let encoded = encode_receipt(&receipt).expect("encode should pass");
        let decoded = decode_receipt(&encoded).expect("decode should pass");
        assert_eq!(decoded, receipt);
    }
}
