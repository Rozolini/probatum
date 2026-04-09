//! Leaf digests for FRI Merkle trees (domain-separated from trace/LDE).

use blake3::Hasher;
use probatum_field::Field;

const FRI_LEAF_DOMAIN: &[u8] = b"probatum.fri.leaf.v1\0";

#[must_use]
pub fn fri_leaf_digest(value: Field) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(FRI_LEAF_DOMAIN);
    h.update(&value.inner().to_le_bytes());
    *h.finalize().as_bytes()
}
