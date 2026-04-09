//! Low-degree extension (LDE) per trace column and Merkle commitment to LDE rows.
//!
//! Trace length must be a **power of two** for the radix-2 FFT trace subgroup. Traces should be
//! padded to the next power of two with AIR-consistent dummy rows before arithmetization.

mod commit;
mod lde;
mod merkle;

pub use commit::{CommitError, LdeCommitment, LdeParams, commit_arithmetized_lde, lde_row_digest};
pub use lde::{LdeError, lde_extend_column};
pub use merkle::{MerkleError, MerkleProof, MerkleTree, verify_merkle_proof};
