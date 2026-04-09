//! JSON-serializable FRI openings (betas, terminal, query Merkle paths) for integrated proofs.

use crate::prove::{DualOpening, FriProof, FriQueryOpenings};
use probatum_evaluation::MerkleProof;
use probatum_field::Field;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fiat–Shamir betas, terminal evaluations, and query openings (layer roots live in `Proof.fri_layer_roots_hex`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FriProofBodyWire {
    pub betas: Vec<u64>,
    pub terminal: Vec<u64>,
    pub queries: Vec<FriQueryOpeningsWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriQueryOpeningsWire {
    pub layers: Vec<DualOpeningWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualOpeningWire {
    pub position_lo: usize,
    pub position_hi: usize,
    pub value_lo: u64,
    pub value_hi: u64,
    pub proof_lo: MerkleProof,
    pub proof_hi: MerkleProof,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FriWireError {
    #[error("no FRI layer roots")]
    EmptyLayerRoots,
    #[error("layer root count does not match beta count")]
    LayerBetaMismatch,
    #[error("empty terminal")]
    EmptyTerminal,
    #[error("query layer count mismatch")]
    QueryLayerCount,
}

impl From<&FriProof> for FriProofBodyWire {
    fn from(p: &FriProof) -> Self {
        Self {
            betas: p.betas.iter().map(|b| b.inner()).collect(),
            terminal: p.terminal.iter().map(|t| t.inner()).collect(),
            queries: p.queries.iter().map(FriQueryOpeningsWire::from).collect(),
        }
    }
}

impl From<&FriQueryOpenings> for FriQueryOpeningsWire {
    fn from(q: &FriQueryOpenings) -> Self {
        Self { layers: q.layers.iter().map(DualOpeningWire::from).collect() }
    }
}

impl From<&DualOpening> for DualOpeningWire {
    fn from(d: &DualOpening) -> Self {
        Self {
            position_lo: d.position_lo,
            position_hi: d.position_hi,
            value_lo: d.value_lo.inner(),
            value_hi: d.value_hi.inner(),
            proof_lo: d.proof_lo.clone(),
            proof_hi: d.proof_hi.clone(),
        }
    }
}

/// Builds a [`FriProof`] for `verify_fri` using committed layer roots and the wire body.
pub fn assemble_fri_proof(
    layer_roots: Vec<[u8; 32]>,
    body: &FriProofBodyWire,
) -> Result<FriProof, FriWireError> {
    if layer_roots.is_empty() {
        return Err(FriWireError::EmptyLayerRoots);
    }
    if layer_roots.len() != body.betas.len() {
        return Err(FriWireError::LayerBetaMismatch);
    }
    if body.terminal.is_empty() {
        return Err(FriWireError::EmptyTerminal);
    }

    let betas: Vec<Field> = body.betas.iter().copied().map(Field::new).collect();
    let terminal: Vec<Field> = body.terminal.iter().copied().map(Field::new).collect();

    let rounds = layer_roots.len();
    let mut queries = Vec::with_capacity(body.queries.len());
    for q in &body.queries {
        if q.layers.len() != rounds {
            return Err(FriWireError::QueryLayerCount);
        }
        let layers: Vec<DualOpening> = q
            .layers
            .iter()
            .map(|d| DualOpening {
                position_lo: d.position_lo,
                position_hi: d.position_hi,
                value_lo: Field::new(d.value_lo),
                value_hi: Field::new(d.value_hi),
                proof_lo: d.proof_lo.clone(),
                proof_hi: d.proof_hi.clone(),
            })
            .collect();
        queries.push(FriQueryOpenings { layers });
    }

    Ok(FriProof { layer_roots, betas, terminal, queries })
}
