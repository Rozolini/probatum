//! Proof construction and serde-backed wire format [`Proof`].
//!
//! [`prove`] runs the integrated pipeline; [`encode_proof`] / [`decode_proof`] serialize proofs for disk or JSON-style transport. Field docs on [`Proof`] describe each commitment.

mod integrated;

use probatum_air::{AirConfig, AirError, validate_trace};
use probatum_field::Field;
use probatum_fri::FriProofBodyWire;
use probatum_trace::{ExecutionTrace, TraceError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROOF_VERSION: &str = "v4";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub proof_version: String,
    pub trace_len: u64,
    pub trace_digest: String,
    pub transcript: String,
    /// Merkle root over LDE evaluation rows (`commit_arithmetized_lde`), 64 hex chars.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lde_merkle_root_hex: String,
    /// Merkle root over LDE of the linear composition column, 64 hex chars.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub composition_lde_merkle_root_hex: String,
    /// One hex root per FRI layer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fri_layer_roots_hex: Vec<String>,
    /// BLAKE3 digest over terminal field elements (see `integrated.rs`), 64 hex chars.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fri_terminal_digest_hex: String,
    #[serde(default)]
    pub fri_num_queries: u32,
    /// Fiat–Shamir betas, terminal values, and FRI Merkle openings (`v4`).
    #[serde(default)]
    pub fri_body: FriProofBodyWire,
}

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("air validation failed")]
    Air(#[from] AirError),
    #[error("arithmetization failed")]
    Arithmetize(#[from] probatum_arith::ArithmetizeError),
    #[error("linear composition failed")]
    Compose(#[from] probatum_constraints::ComposeError),
    #[error("LDE failed: {0}")]
    Lde(#[from] probatum_evaluation::LdeError),
    #[error("LDE commitment failed: {0}")]
    Commit(#[from] probatum_evaluation::CommitError),
    #[error("Merkle tree failed: {0}")]
    Merkle(#[from] probatum_evaluation::MerkleError),
    #[error("FRI prove failed: {0}")]
    Fri(#[from] probatum_fri::FriProveError),
    #[error("proof serialization failed")]
    Serialize(#[source] serde_json::Error),
    #[error("proof deserialization failed")]
    Deserialize(#[source] serde_json::Error),
    #[error("trace digest generation failed")]
    Trace(#[from] TraceError),
    #[error("trace length {len} must be a power of two and at least 2 for integrated proofs")]
    TraceLengthNotPowerOfTwo { len: usize },
}

/// Builds a deterministic proof payload: integrated pipeline (arith → constraints → LDE → FS → FRI).
///
/// # Errors
///
/// Returns [`ProverError::TraceLengthNotPowerOfTwo`] when the trace length is not a power of two (required for FFT/LDE).
pub fn prove(trace: &ExecutionTrace) -> Result<Proof, ProverError> {
    validate_trace(trace, AirConfig::default())?;
    integrated::prove_integrated(trace)
}

/// Recomputes the expected `transcript` binding for an integrated proof (verifier helper).
#[must_use]
pub fn expected_transcript_hex(proof: &Proof) -> Option<String> {
    if proof.proof_version != PROOF_VERSION {
        return None;
    }
    integrated::recompute_transcript_hex(proof)
}

/// Composition LDE domain length (`trace_len * blowup`) for integrated proving.
#[must_use]
pub fn integrated_comp_domain_len(trace_len: u64) -> Option<usize> {
    integrated::integrated_comp_domain_len(trace_len)
}

/// Fiat–Shamir betas squeezed after the composition root absorb (must match `fri_body.betas`).
#[must_use]
pub fn recomputed_fri_betas(proof: &Proof) -> Option<Vec<Field>> {
    integrated::recomputed_fri_betas(proof)
}

/// Terminal digest over field elements (matches `fri_terminal_digest_hex`).
#[must_use]
pub fn integrated_terminal_digest(terminal: &[Field]) -> [u8; 32] {
    integrated::terminal_digest(terminal)
}

/// Encodes proof to the canonical on-disk representation (`proof.bin` payload).
pub fn encode_proof(proof: &Proof) -> Result<Vec<u8>, ProverError> {
    serde_json::to_vec(proof).map_err(ProverError::Serialize)
}

/// Decodes proof from canonical on-disk bytes.
pub fn decode_proof(bytes: &[u8]) -> Result<Proof, ProverError> {
    serde_json::from_slice(bytes).map_err(ProverError::Deserialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_trace::{ExecutionTrace, TraceRow};

    fn four_row_valid_trace() -> ExecutionTrace {
        ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 4 },
                TraceRow { clk: 2, pc: 2, acc: 8, op_tag: 1, op_arg: 0 },
                TraceRow { clk: 3, pc: 3, acc: 8, op_tag: 3, op_arg: 0 },
            ],
        }
    }

    #[test]
    fn generates_proof() {
        let trace = four_row_valid_trace();
        let proof = prove(&trace).expect("proof generation should pass");
        assert_eq!(proof.proof_version, PROOF_VERSION);
        assert_eq!(proof.trace_len, 4);
        assert_eq!(proof.trace_digest.len(), 64);
        assert_eq!(proof.transcript.len(), 64);
        assert!(!proof.lde_merkle_root_hex.is_empty());
    }

    #[test]
    fn rejects_non_power_of_two_length() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 3 },
                TraceRow { clk: 2, pc: 2, acc: 6, op_tag: 3, op_arg: 0 },
            ],
        };
        let err = prove(&trace).expect_err("need power-of-two length");
        assert!(matches!(err, ProverError::TraceLengthNotPowerOfTwo { len: 3 }));
    }

    #[test]
    fn rejects_malformed_proof_payload() {
        let malformed = b"{not-json";
        let err = decode_proof(malformed).expect_err("decode should fail");
        assert!(matches!(err, ProverError::Deserialize(_)));
    }

    #[test]
    fn transcript_matches_recompute() {
        let trace = four_row_valid_trace();
        let proof = prove(&trace).expect("proof");
        let expected = expected_transcript_hex(&proof).expect("expected transcript");
        assert_eq!(proof.transcript, expected);
    }

    #[test]
    fn proof_encoding_is_deterministic() {
        let trace = four_row_valid_trace();
        let proof = prove(&trace).expect("proof");
        let bytes_a = encode_proof(&proof).expect("encoding");
        let bytes_b = encode_proof(&proof).expect("encoding");
        assert_eq!(bytes_a, bytes_b);
    }
}

#[cfg(test)]
mod property_tests;
