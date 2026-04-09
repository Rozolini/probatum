//! Binary Merkle tree over fixed-size leaf digests (BLAKE3), matching the odd-length duplicate-last pairing used in `probatum-trace`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const NODE_DOMAIN: &[u8] = b"probatum.eval.merkle.node.v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("cannot build Merkle tree from zero leaves")]
    Empty,
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Full binary Merkle structure for inclusion proofs.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Builds a tree from leaf digests (bottom level). Odd widths duplicate the last leaf when pairing.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::Empty`] when `leaves` is empty.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::Empty);
        }
        let mut levels = vec![leaves];
        while levels.last().expect("non-empty").len() > 1 {
            let prev = levels.last().expect("level");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = prev[i];
                let right = if i + 1 < prev.len() { prev[i + 1] } else { prev[i] };
                next.push(node_hash(&left, &right));
                i += 2;
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }

    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("at least one level")[0]
    }

    /// Number of leaf digests (bottom level).
    #[must_use]
    pub fn num_leaves(&self) -> usize {
        self.levels.first().expect("at least one level").len()
    }

    /// Inclusion proof: one sibling digest per level from leaf to root (exclusive of the leaf).
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range for the leaf level.
    #[must_use]
    pub fn prove(&self, index: usize) -> MerkleProof {
        let mut idx = index;
        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in &self.levels[..self.levels.len() - 1] {
            assert!(idx < level.len(), "index out of bounds");
            let sibling_idx = if idx % 2 == 0 {
                if idx + 1 < level.len() { idx + 1 } else { idx }
            } else {
                idx - 1
            };
            siblings.push(level[sibling_idx]);
            idx /= 2;
        }
        MerkleProof { siblings }
    }
}

/// Sibling digests from leaf level up to below the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<[u8; 32]>,
}

/// Verifies that `leaf` at `index` reaches `root` using `proof` and the same pairing rule as [`MerkleTree::from_leaves`].
#[must_use]
pub fn verify_merkle_proof(
    root: &[u8; 32],
    mut index: usize,
    leaf: &[u8; 32],
    proof: &MerkleProof,
) -> bool {
    let mut cur = *leaf;
    for sibling in &proof.siblings {
        if index % 2 == 0 {
            cur = node_hash(&cur, sibling);
        } else {
            cur = node_hash(sibling, &cur);
        }
        index /= 2;
    }
    cur == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_leaf() {
        let leaf = [7u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf]).expect("tree");
        assert_eq!(tree.root(), leaf);
        let proof = tree.prove(0);
        assert!(proof.siblings.is_empty());
        assert!(verify_merkle_proof(&tree.root(), 0, &leaf, &proof));
    }

    #[test]
    fn two_leaves_verify() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let tree = MerkleTree::from_leaves(vec![a, b]).expect("tree");
        let root = tree.root();
        let p0 = tree.prove(0);
        assert!(verify_merkle_proof(&root, 0, &a, &p0));
        let p1 = tree.prove(1);
        assert!(verify_merkle_proof(&root, 1, &b, &p1));
    }

    #[test]
    fn wrong_leaf_fails() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let tree = MerkleTree::from_leaves(vec![a, b]).expect("tree");
        let root = tree.root();
        let bad = [9u8; 32];
        let p = tree.prove(0);
        assert!(!verify_merkle_proof(&root, 0, &bad, &p));
    }
}
