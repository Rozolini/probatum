//! Integrated STARK pipeline: arithmetize → constraints → LDE → FS → FRI.

use probatum_air::AirConfig;
use probatum_arith::arithmetize;
use probatum_constraints::{CONSTRAINT_FAMILY_COUNT, compose_linear, constraint_residuals};
use probatum_evaluation::{LdeParams, MerkleTree, commit_arithmetized_lde};
use probatum_field::{Field, MODULUS};
use probatum_fri::{FriProofBodyWire, fri_leaf_digest, prove_fri};
use probatum_trace::ExecutionTrace;
use probatum_transcript::{FsTranscript, hex_encode_32};

use crate::ProverError;

const LDE_BLOWUP: usize = 2;

// Labels passed to `FsTranscript::absorb_commitment_*` / `absorb_hex_digest`. Order and byte
// values must stay aligned with `probatum_transcript` and with what `expected_transcript_hex`
// replays; changing them is a wire-format break (bump `proof_version` / schema as needed).
const LDE_ROOT_MSG: &[u8] = b"msg:lde_row_merkle_root\0";
const COMP_ROOT_MSG: &[u8] = b"msg:composition_lde_merkle_root\0";
const FRI_ROUND_MSG: &[u8] = b"msg:fri_layer_root\0";
const TERMINAL_MSG: &[u8] = b"msg:fri_terminal_digest\0";

fn field_from_challenge(x: u128) -> Field {
    let m = MODULUS as u128;
    Field::new((x % m) as u64)
}

fn fri_rounds(len: usize) -> usize {
    if len < 2 {
        return 1;
    }
    let lg = usize::try_from(len.trailing_zeros()).unwrap_or(0);
    lg.saturating_sub(1).clamp(1, 8)
}

fn composition_merkle_root(
    comp_lde: &[Field],
) -> Result<[u8; 32], probatum_evaluation::MerkleError> {
    let leaves: Vec<[u8; 32]> = comp_lde.iter().copied().map(fri_leaf_digest).collect();
    let tree = MerkleTree::from_leaves(leaves)?;
    Ok(tree.root())
}

pub(crate) fn terminal_digest(term: &[Field]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"probatum.integrated.terminal.v1\0");
    for f in term {
        h.update(&f.inner().to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Runs the full cryptographic pipeline (requires `trace.len()` power of two ≥ 2).
pub fn prove_integrated(trace: &ExecutionTrace) -> Result<crate::Proof, ProverError> {
    let n = trace.len();
    if n < 2 || !n.is_power_of_two() {
        return Err(ProverError::TraceLengthNotPowerOfTwo { len: n });
    }

    let arith = arithmetize(trace, AirConfig::default())?;
    let trace_digest = trace.digest_hex()?;

    let lde = commit_arithmetized_lde(&arith, LdeParams { blowup: LDE_BLOWUP })?;
    let lde_root = lde.root;

    let mut t = FsTranscript::new();
    t.absorb_proof_inputs(crate::PROOF_VERSION, trace.len() as u64, trace_digest.as_str());
    t.absorb_commitment_root(LDE_ROOT_MSG, &lde_root);

    let mut t_alphas = t.clone();
    let mut alphas = Vec::with_capacity(CONSTRAINT_FAMILY_COUNT);
    for _ in 0..CONSTRAINT_FAMILY_COUNT {
        alphas.push(field_from_challenge(t_alphas.squeeze_challenge_u128()));
    }

    let residuals = constraint_residuals(&arith);
    let families = residuals.families_uniform();
    let comp = compose_linear(&families, &alphas)?;

    let comp_lde =
        probatum_evaluation::lde_extend_column(&comp, LDE_BLOWUP).map_err(ProverError::Lde)?;
    let comp_root = composition_merkle_root(&comp_lde)?;

    t.absorb_commitment_root(COMP_ROOT_MSG, &comp_root);

    let rounds = fri_rounds(comp_lde.len());
    let mut t_fri = t.clone();
    let betas: Vec<Field> =
        (0..rounds).map(|_| field_from_challenge(t_fri.squeeze_challenge_u128())).collect();

    let fri_proof = prove_fri(comp_lde, &betas, &[0usize]).map_err(ProverError::Fri)?;

    for (i, root) in fri_proof.layer_roots.iter().enumerate() {
        t.absorb_indexed_root(FRI_ROUND_MSG, i as u64, root);
    }
    let term_d = terminal_digest(&fri_proof.terminal);
    t.absorb_digest(TERMINAL_MSG, &term_d);

    let transcript = t.binding_hex();

    Ok(crate::Proof {
        proof_version: crate::PROOF_VERSION.to_string(),
        trace_len: trace.len() as u64,
        trace_digest,
        transcript,
        lde_merkle_root_hex: hex_encode_32(&lde_root),
        composition_lde_merkle_root_hex: hex_encode_32(&comp_root),
        fri_layer_roots_hex: fri_proof.layer_roots.iter().map(hex_encode_32).collect(),
        fri_terminal_digest_hex: hex_encode_32(&term_d),
        fri_num_queries: fri_proof.queries.len() as u32,
        fri_body: FriProofBodyWire::from(&fri_proof),
    })
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

pub fn integrated_comp_domain_len(trace_len: u64) -> Option<usize> {
    let n = usize::try_from(trace_len).ok()?;
    if n < 2 || !n.is_power_of_two() {
        return None;
    }
    Some(n.saturating_mul(LDE_BLOWUP))
}

/// Fiat–Shamir betas after composition root (same fork as proving).
pub fn recomputed_fri_betas(proof: &crate::Proof) -> Option<Vec<Field>> {
    let comp_len = integrated_comp_domain_len(proof.trace_len)?;
    let rounds = fri_rounds(comp_len);
    let lde_root = parse_hex_32(&proof.lde_merkle_root_hex)?;
    let comp_root = parse_hex_32(&proof.composition_lde_merkle_root_hex)?;
    let mut t = FsTranscript::new();
    t.absorb_proof_inputs(
        proof.proof_version.as_str(),
        proof.trace_len,
        proof.trace_digest.as_str(),
    );
    t.absorb_commitment_root(LDE_ROOT_MSG, &lde_root);
    t.absorb_commitment_root(COMP_ROOT_MSG, &comp_root);
    let mut t_fri = t.clone();
    let mut betas = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        betas.push(field_from_challenge(t_fri.squeeze_challenge_u128()));
    }
    Some(betas)
}

/// Recomputes the transcript from embedded commitment fields (must match prover order).
pub fn recompute_transcript_hex(proof: &crate::Proof) -> Option<String> {
    let lde_root = parse_hex_32(&proof.lde_merkle_root_hex)?;
    let comp_root = parse_hex_32(&proof.composition_lde_merkle_root_hex)?;

    let mut t = FsTranscript::new();
    t.absorb_proof_inputs(
        proof.proof_version.as_str(),
        proof.trace_len,
        proof.trace_digest.as_str(),
    );
    t.absorb_commitment_root(LDE_ROOT_MSG, &lde_root);
    t.absorb_commitment_root(COMP_ROOT_MSG, &comp_root);

    for (i, hx) in proof.fri_layer_roots_hex.iter().enumerate() {
        let root = parse_hex_32(hx)?;
        t.absorb_indexed_root(FRI_ROUND_MSG, i as u64, &root);
    }
    let td = parse_hex_32(&proof.fri_terminal_digest_hex)?;
    t.absorb_digest(TERMINAL_MSG, &td);

    Some(t.binding_hex())
}
