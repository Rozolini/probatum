//! Verify FRI Merkle paths and local fold consistency.

use crate::digest::fri_leaf_digest;
use crate::fold::{domain_generator, fold_pair_at_x, next_domain_generator};
use crate::prove::FriProof;
use probatum_evaluation::verify_merkle_proof;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FriVerifyError {
    #[error("layer count mismatch")]
    LayerCount,
    #[error("merkle verification failed at round {round}")]
    Merkle { round: usize },
    #[error("fold mismatch at round {round}")]
    FoldMismatch { round: usize },
    #[error("query {query} has wrong layer count")]
    QueryLayerCount { query: usize },
}

/// Verifies all Merkle openings and that each fold links layer `r` to `r+1`, and the last fold reaches `terminal[j]`.
pub fn verify_fri(proof: &FriProof, initial_domain_size: usize) -> Result<(), FriVerifyError> {
    let rounds = proof.betas.len();
    if rounds == 0 || proof.layer_roots.len() != rounds {
        return Err(FriVerifyError::LayerCount);
    }

    for (qi, query) in proof.queries.iter().enumerate() {
        if query.layers.len() != rounds {
            return Err(FriVerifyError::QueryLayerCount { query: qi });
        }

        let mut omega = domain_generator(initial_domain_size).ok_or(FriVerifyError::LayerCount)?;
        let j = query.layers[0].position_lo;

        for round in 0..rounds {
            let d = &query.layers[round];
            let root = &proof.layer_roots[round];

            if !verify_merkle_proof(root, d.position_lo, &fri_leaf_digest(d.value_lo), &d.proof_lo)
            {
                return Err(FriVerifyError::Merkle { round });
            }
            if !verify_merkle_proof(root, d.position_hi, &fri_leaf_digest(d.value_hi), &d.proof_hi)
            {
                return Err(FriVerifyError::Merkle { round });
            }

            let x = omega.pow(j as u64);
            let folded = fold_pair_at_x(d.value_lo, d.value_hi, x, proof.betas[round]);

            if round + 1 < rounds {
                let next = &query.layers[round + 1];
                if folded != next.value_lo {
                    return Err(FriVerifyError::FoldMismatch { round });
                }
            } else if folded != proof.terminal[j] {
                return Err(FriVerifyError::FoldMismatch { round });
            }

            omega = next_domain_generator(omega);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold::domain_generator;
    use crate::prove::prove_fri;
    use probatum_field::Field;

    #[test]
    fn honest_linear_poly_passes() {
        let n = 32usize;
        let omega = domain_generator(n).expect("omega");
        let c0 = Field::new(5);
        let c1 = Field::new(11);
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            let x = omega.pow(i as u64);
            v.push(c0 + c1 * x);
        }
        let betas = [Field::new(3), Field::new(7), Field::new(11)];
        let proof = prove_fri(v, &betas, &[0usize, 3]).expect("prove");
        verify_fri(&proof, n).expect("verify");
    }

    #[test]
    fn tampered_opening_fails() {
        let n = 16usize;
        let v = vec![Field::new(1); n];
        let betas = [Field::new(2), Field::new(3)];
        let mut proof = prove_fri(v, &betas, &[1]).expect("prove");
        proof.queries[0].layers[0].value_lo += Field::ONE;
        assert!(verify_fri(&proof, n).is_err());
    }

    #[test]
    fn bad_terminal_fails() {
        let n = 16usize;
        let v = vec![Field::new(1); n];
        let betas = [Field::new(2), Field::new(3)];
        let mut proof = prove_fri(v, &betas, &[0]).expect("prove");
        proof.terminal[0] += Field::ONE;
        assert!(verify_fri(&proof, n).is_err());
    }
}
