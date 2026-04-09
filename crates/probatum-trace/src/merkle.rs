//! Binary Merkle tree over per-row leaf digests (BLAKE3).
//!
//! Odd-sized levels combine the last digest with itself. This is a deterministic
//! commitment helper; it is not a full STARK commitment layer.

use crate::{TraceError, TraceRow};

const LEAF_DOMAIN: &[u8] = b"probatum.trace.merkle.leaf.v1\0";
const NODE_DOMAIN: &[u8] = b"probatum.trace.merkle.node.v1\0";

/// Canonical leaf digest for one trace row.
///
/// # Errors
///
/// Returns an error when the row cannot be serialized to canonical JSON.
pub fn leaf_hash(row: &TraceRow) -> Result<[u8; 32], TraceError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    let bytes = serde_json::to_vec(row).map_err(TraceError::Serialize)?;
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Reduces a non-empty list of leaf digests to a single Merkle root.
#[must_use]
pub fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            next.push(node_hash(&left, &right));
            i += 2;
        }
        level = next;
    }
    Some(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceRow;

    #[test]
    fn single_leaf_root_equals_leaf() {
        let row = TraceRow { clk: 0, pc: 0, acc: 1, op_tag: 1, op_arg: 0 };
        let leaf = leaf_hash(&row).expect("leaf hash");
        let root = merkle_root_from_leaves(&[leaf]).expect("root");
        assert_eq!(leaf, root);
    }

    #[test]
    fn three_leaves_duplicate_last_at_first_level() {
        let a = leaf_hash(&TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 1 }).expect("leaf");
        let b = leaf_hash(&TraceRow { clk: 1, pc: 1, acc: 1, op_tag: 2, op_arg: 2 }).expect("leaf");
        let c = leaf_hash(&TraceRow { clk: 2, pc: 2, acc: 2, op_tag: 3, op_arg: 0 }).expect("leaf");
        let n1 = node_hash(&a, &b);
        let n2 = node_hash(&c, &c);
        let expected = node_hash(&n1, &n2);
        let got = merkle_root_from_leaves(&[a, b, c]).expect("root");
        assert_eq!(got, expected);
    }
}
