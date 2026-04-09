//! Row-wise Merkle commitment over LDE evaluation rows.

use crate::lde::{LdeError, lde_extend_column};
use crate::merkle::{MerkleError, MerkleProof, MerkleTree};
use probatum_arith::ArithmetizedTrace;
use probatum_arith::COLUMN_COUNT;
use probatum_field::Field;
use thiserror::Error;

const ROW_DOMAIN: &[u8] = b"probatum.eval.lde_row.v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommitError {
    #[error("trace must be non-empty for LDE commitment")]
    EmptyTrace,
    #[error("LDE failed: {0}")]
    Lde(#[from] LdeError),
    #[error("Merkle failed: {0}")]
    Merkle(#[from] MerkleError),
}

/// Blowup as multiplier: LDE domain size = `trace_len * blowup` (both powers of two).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdeParams {
    pub blowup: usize,
}

impl LdeParams {
    /// # Panics
    ///
    /// Panics if `blowup` is zero (use only with validated constants in tests).
    #[must_use]
    pub const fn domain_len(self, trace_len: usize) -> usize {
        trace_len * self.blowup
    }
}

/// LDE table + Merkle root over row digests (one digest per LDE index, all columns packed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdeCommitment {
    pub blowup: usize,
    pub trace_len: usize,
    pub domain_len: usize,
    pub root: [u8; 32],
    /// `lde_columns[col][row]` — row-major over LDE domain index.
    pub lde_columns: Vec<Vec<Field>>,
}

fn field_to_le_bytes(f: Field) -> [u8; 8] {
    f.inner().to_le_bytes()
}

/// Canonical BLAKE3 digest for one LDE row (all columns concatenated, fixed LE field encoding).
#[must_use]
pub fn lde_row_digest(row: &[Field; COLUMN_COUNT]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROW_DOMAIN);
    for f in row {
        hasher.update(&field_to_le_bytes(*f));
    }
    *hasher.finalize().as_bytes()
}

/// Runs LDE on every arithmetized column, builds row digests, returns Merkle root and the LDE matrix.
///
/// # Errors
///
/// Fails when trace length is not a power of two, `blowup` is invalid, or FFT limits are exceeded.
pub fn commit_arithmetized_lde(
    trace: &ArithmetizedTrace,
    params: LdeParams,
) -> Result<LdeCommitment, CommitError> {
    if trace.is_empty() {
        return Err(CommitError::EmptyTrace);
    }
    let trace_len = trace.len();
    let cm = trace.column_major();
    let mut lde_columns = Vec::with_capacity(COLUMN_COUNT);
    for col in &cm {
        lde_columns.push(lde_extend_column(col, params.blowup)?);
    }
    let domain_len = lde_columns.first().map(Vec::len).unwrap_or(0);
    debug_assert!(lde_columns.iter().all(|c| c.len() == domain_len));

    let mut leaves = Vec::with_capacity(domain_len);
    for r in 0..domain_len {
        let mut row = [Field::ZERO; COLUMN_COUNT];
        for (c, slot) in row.iter_mut().enumerate() {
            *slot = lde_columns[c][r];
        }
        leaves.push(lde_row_digest(&row));
    }

    let tree = MerkleTree::from_leaves(leaves)?;
    Ok(LdeCommitment {
        blowup: params.blowup,
        trace_len,
        domain_len,
        root: tree.root(),
        lde_columns,
    })
}

impl LdeCommitment {
    /// Inclusion proof for LDE row `index` (same indexing as column vectors).
    ///
    /// # Panics
    ///
    /// Panics if `index >= domain_len` (caller must use a valid opened index).
    #[must_use]
    pub fn prove_row(&self, index: usize) -> MerkleProof {
        let leaves: Vec<[u8; 32]> = (0..self.domain_len)
            .map(|r| {
                let mut row = [Field::ZERO; COLUMN_COUNT];
                for (c, slot) in row.iter_mut().enumerate() {
                    *slot = self.lde_columns[c][r];
                }
                lde_row_digest(&row)
            })
            .collect();
        let tree = MerkleTree::from_leaves(leaves).expect("same leaves as commit");
        tree.prove(index)
    }

    /// Row digest at `index` (for verifier-side checks).
    #[must_use]
    pub fn row_digest(&self, index: usize) -> [u8; 32] {
        let mut row = [Field::ZERO; COLUMN_COUNT];
        for (c, slot) in row.iter_mut().enumerate() {
            *slot = self.lde_columns[c][index];
        }
        lde_row_digest(&row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_air::AirConfig;
    use probatum_arith::arithmetize;
    use probatum_trace::{ExecutionTrace, TraceRow};

    fn valid_four_row_trace() -> ExecutionTrace {
        // ADD -> MUL -> ADD -> HALT; selector coverage; sequential clk/pc/acc.
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
    fn commitment_deterministic() {
        let t = arithmetize(&valid_four_row_trace(), AirConfig::default()).expect("arith");
        let p = LdeParams { blowup: 4 };
        let c1 = commit_arithmetized_lde(&t, p).expect("commit");
        let c2 = commit_arithmetized_lde(&t, p).expect("commit");
        assert_eq!(c1.root, c2.root);
        assert_eq!(c1.domain_len, 16);
    }

    #[test]
    fn tamper_changes_root_and_invalidates_proof() {
        let t = arithmetize(&valid_four_row_trace(), AirConfig::default()).expect("arith");
        let mut c = commit_arithmetized_lde(&t, LdeParams { blowup: 2 }).expect("commit");
        let idx = 3;
        let proof = c.prove_row(idx);
        let leaf = c.row_digest(idx);
        assert!(crate::merkle::verify_merkle_proof(&c.root, idx, &leaf, &proof));

        c.lde_columns[0][idx] += Field::ONE;
        let bad_leaf = c.row_digest(idx);
        assert_ne!(bad_leaf, leaf);
        assert!(!crate::merkle::verify_merkle_proof(&c.root, idx, &bad_leaf, &proof));

        let c2 = commit_arithmetized_lde(&t, LdeParams { blowup: 2 }).expect("commit");
        assert_eq!(c2.root, c.root);
    }
}
