//! FRI-style folding with Merkle layers and per-query opening verification.
//!
//! Folding uses the usual degree-halving combination at paired domain points `x` and `-x` on a multiplicative subgroup.

mod body_wire;
mod digest;
mod fold;
mod prove;
mod verify;

pub use body_wire::{
    DualOpeningWire, FriProofBodyWire, FriQueryOpeningsWire, FriWireError, assemble_fri_proof,
};
pub use digest::fri_leaf_digest;
pub use fold::{FoldError, domain_generator, fold_layer, fold_pair_at_x, next_domain_generator};
pub use prove::{DualOpening, FriProof, FriProveError, FriQueryOpenings, prove_fri};
pub use verify::{FriVerifyError, verify_fri};
