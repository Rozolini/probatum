//! Proof verification with structured failure codes for CLI and JSON reports.

use probatum_fri::{FriWireError, assemble_fri_proof, verify_fri};
use probatum_prover::{
    PROOF_VERSION, Proof, expected_transcript_hex, integrated_comp_domain_len,
    integrated_terminal_digest, recomputed_fri_betas,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyResult {
    Ok,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyFailureCode {
    /// `proof_version` does not match the verifier's expected constant.
    ProofVersionMismatch,
    /// `trace_len == 0` or composition domain length could not be derived.
    EmptyTrace,
    /// `trace_digest` is not 64 lowercase hex digits.
    InvalidTraceDigestFormat,
    /// Binding transcript mismatch: `proof.transcript` differs from [`expected_transcript_hex`], or FS replay failed while deriving FRI betas.
    TranscriptMismatch,
    /// FRI wire is incomplete or inconsistent (bad hex roots, `assemble_fri_proof`, or terminal digest parse).
    FriPayloadInvalid,
    /// FRI betas in the proof differ from [`recomputed_fri_betas`].
    FriBetasMismatch,
    /// `fri_terminal_digest_hex` does not match the BLAKE3 hash over terminal field elements.
    FriTerminalDigestMismatch,
    /// `fri_num_queries` does not match the number of query bundles in `fri_body`.
    FriQueryCountMismatch,
    /// [`verify_fri`] rejected Merkle openings or the low-degree terminal check.
    FriLowDegreeCheckFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyOutcome {
    Ok,
    Fail(VerifyFailureCode),
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = u8::try_from((hi << 4) | lo).ok()?;
    }
    Some(out)
}

#[must_use]
/// Full verification with a stable failure code.
///
/// Order of checks: `proof_version` and trace metadata → transcript binding ([`expected_transcript_hex`])
/// → parse FRI layer roots and [`assemble_fri_proof`] → compare FRI betas and terminal digest →
/// query count → [`verify_fri`] on the composition domain.
pub fn verify_detailed(proof: &Proof) -> VerifyOutcome {
    if proof.proof_version != PROOF_VERSION {
        return VerifyOutcome::Fail(VerifyFailureCode::ProofVersionMismatch);
    }
    if proof.trace_len == 0 {
        return VerifyOutcome::Fail(VerifyFailureCode::EmptyTrace);
    }
    let is_digest_hex = proof.trace_digest.len() == 64
        && proof.trace_digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if !is_digest_hex {
        return VerifyOutcome::Fail(VerifyFailureCode::InvalidTraceDigestFormat);
    }
    let Some(expected_transcript) = expected_transcript_hex(proof) else {
        return VerifyOutcome::Fail(VerifyFailureCode::TranscriptMismatch);
    };
    if proof.transcript != expected_transcript {
        return VerifyOutcome::Fail(VerifyFailureCode::TranscriptMismatch);
    }

    let Some(comp_len) = integrated_comp_domain_len(proof.trace_len) else {
        return VerifyOutcome::Fail(VerifyFailureCode::EmptyTrace);
    };

    if proof.fri_body.betas.is_empty() || proof.fri_body.terminal.is_empty() {
        return VerifyOutcome::Fail(VerifyFailureCode::FriPayloadInvalid);
    }

    let layer_roots: Option<Vec<[u8; 32]>> =
        proof.fri_layer_roots_hex.iter().map(|h| parse_hex_32(h)).collect();
    let Some(layer_roots) = layer_roots else {
        return VerifyOutcome::Fail(VerifyFailureCode::FriPayloadInvalid);
    };

    let fri = match assemble_fri_proof(layer_roots, &proof.fri_body) {
        Ok(p) => p,
        Err(FriWireError::EmptyLayerRoots)
        | Err(FriWireError::LayerBetaMismatch)
        | Err(FriWireError::EmptyTerminal)
        | Err(FriWireError::QueryLayerCount) => {
            return VerifyOutcome::Fail(VerifyFailureCode::FriPayloadInvalid);
        }
    };

    let Some(expected_betas) = recomputed_fri_betas(proof) else {
        return VerifyOutcome::Fail(VerifyFailureCode::TranscriptMismatch);
    };
    if fri.betas != expected_betas {
        return VerifyOutcome::Fail(VerifyFailureCode::FriBetasMismatch);
    }

    let td = integrated_terminal_digest(&fri.terminal);
    let Some(digest_hex) = parse_hex_32(&proof.fri_terminal_digest_hex) else {
        return VerifyOutcome::Fail(VerifyFailureCode::FriPayloadInvalid);
    };
    if digest_hex != td {
        return VerifyOutcome::Fail(VerifyFailureCode::FriTerminalDigestMismatch);
    }

    if proof.fri_num_queries as usize != fri.queries.len() {
        return VerifyOutcome::Fail(VerifyFailureCode::FriQueryCountMismatch);
    }

    if verify_fri(&fri, comp_len).is_err() {
        return VerifyOutcome::Fail(VerifyFailureCode::FriLowDegreeCheckFailed);
    }

    VerifyOutcome::Ok
}

#[must_use]
/// Backward-compatible coarse verification result.
pub fn verify(proof: &Proof) -> VerifyResult {
    match verify_detailed(proof) {
        VerifyOutcome::Ok => VerifyResult::Ok,
        VerifyOutcome::Fail(_) => VerifyResult::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_prover::prove;
    use probatum_trace::{ExecutionTrace, TraceRow};

    fn four_row_trace() -> ExecutionTrace {
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
    fn verifies_valid_proof() {
        let proof = prove(&four_row_trace()).expect("prove");
        assert_eq!(verify(&proof), VerifyResult::Ok);
    }

    #[test]
    fn rejects_tampered_transcript() {
        let mut proof = prove(&four_row_trace()).expect("prove");
        proof.transcript =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert_eq!(verify(&proof), VerifyResult::Fail);
    }

    #[test]
    fn rejects_proof_version_mismatch() {
        let mut proof = prove(&four_row_trace()).expect("prove");
        proof.proof_version = "v999".to_string();
        assert_eq!(verify(&proof), VerifyResult::Fail);
    }

    #[test]
    fn detailed_returns_failure_code() {
        let mut proof = prove(&four_row_trace()).expect("prove");
        proof.trace_len = 0;
        assert_eq!(verify_detailed(&proof), VerifyOutcome::Fail(VerifyFailureCode::EmptyTrace));
    }

    #[test]
    fn rejects_bad_fri_beta() {
        let mut proof = prove(&four_row_trace()).expect("prove");
        if let Some(b) = proof.fri_body.betas.first_mut() {
            *b ^= 1;
        }
        assert_eq!(
            verify_detailed(&proof),
            VerifyOutcome::Fail(VerifyFailureCode::FriBetasMismatch)
        );
    }
}
