//! Build FRI layer commitments and per-query Merkle openings.

use crate::digest::fri_leaf_digest;
use crate::fold::{domain_generator, fold_layer, next_domain_generator};
use probatum_evaluation::{MerkleProof, MerkleTree};
use probatum_field::Field;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FriProveError {
    #[error("cannot prove FRI with zero betas")]
    ZeroBetas,
    #[error("query position {pos} out of range for terminal size {n}")]
    QueryOutOfRange { pos: usize, n: usize },
    #[error("fold: {0}")]
    Fold(#[from] crate::fold::FoldError),
    #[error("merkle: {0}")]
    Merkle(#[from] probatum_evaluation::MerkleError),
}

/// Openings for one query index `j` (valid for all layers: `j < |terminal|`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQueryOpenings {
    /// For each round `r`, dual openings into the `r`-th Merkle tree (evaluations before that round's fold).
    pub layers: Vec<DualOpening>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualOpening {
    pub position_lo: usize,
    pub position_hi: usize,
    pub value_lo: Field,
    pub value_hi: Field,
    pub proof_lo: MerkleProof,
    pub proof_hi: MerkleProof,
}

/// Merkle root per beta round, terminal evaluations, and per-query dual openings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProof {
    pub layer_roots: Vec<[u8; 32]>,
    pub betas: Vec<Field>,
    pub terminal: Vec<Field>,
    pub queries: Vec<FriQueryOpenings>,
}

/// `betas.len()` Merkle commitments: round `r` commits evaluations **before** applying `betas[r]`.
/// The final fold yields `terminal` (length = initial / 2^{betas.len()}).
pub fn prove_fri(
    initial: Vec<Field>,
    betas: &[Field],
    query_positions: &[usize],
) -> Result<FriProof, FriProveError> {
    if betas.is_empty() {
        return Err(FriProveError::ZeroBetas);
    }

    let mut omega = domain_generator(initial.len()).ok_or(FriProveError::ZeroBetas)?;
    let mut roots = Vec::with_capacity(betas.len());
    let mut trees = Vec::with_capacity(betas.len());
    let mut layer_values = Vec::with_capacity(betas.len());

    let mut v = initial;
    for beta in betas {
        layer_values.push(v.clone());
        let leaves: Vec<[u8; 32]> = v.iter().copied().map(fri_leaf_digest).collect();
        let tree = MerkleTree::from_leaves(leaves)?;
        roots.push(tree.root());
        trees.push(tree);

        v = fold_layer(&v, omega, *beta)?;
        omega = next_domain_generator(omega);
    }

    let terminal = v;
    let n_term = terminal.len();

    for &pos in query_positions {
        if pos >= n_term {
            return Err(FriProveError::QueryOutOfRange { pos, n: n_term });
        }
    }

    let mut queries = Vec::with_capacity(query_positions.len());

    for &j in query_positions {
        let mut layers_out = Vec::with_capacity(betas.len());

        for (round, tree) in trees.iter().enumerate() {
            let n = layer_values[round].len();
            let half = n / 2;
            if j >= half {
                return Err(FriProveError::QueryOutOfRange { pos: j, n: half });
            }
            let pos_lo = j;
            let pos_hi = j + half;
            let value_lo = layer_values[round][pos_lo];
            let value_hi = layer_values[round][pos_hi];

            let proof_lo = tree.prove(pos_lo);
            let proof_hi = tree.prove(pos_hi);

            layers_out.push(DualOpening {
                position_lo: pos_lo,
                position_hi: pos_hi,
                value_lo,
                value_hi,
                proof_lo,
                proof_hi,
            });
        }

        queries.push(FriQueryOpenings { layers: layers_out });
    }

    Ok(FriProof { layer_roots: roots, betas: betas.to_vec(), terminal, queries })
}
