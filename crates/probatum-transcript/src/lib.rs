//! Fiat-Shamir-style transcript over BLAKE3 with explicit **domain separation** and a versioned absorb order.
//!
//! # Byte-level layout (schema `1`)
//!
//! The internal hasher is initialized with:
//! - label `b"probatum.fs.transcript\0"`;
//! - little-endian `u32` schema id `1`.
//!
//! [`FsTranscript::absorb_proof_inputs`] appends, in order:
//! - `b"msg:proof_version\0"` then `len(proof_version)` as `u64` LE then UTF-8 bytes;
//! - `b"msg:trace_len\0"` then `trace_len` as `u64` LE;
//! - `b"msg:trace_digest_hex\0"` then `len(digest_hex)` as `u64` LE then ASCII bytes.
//!
//! The public **transcript string** in `Proof.transcript` (prover crate) is the lowercase hex encoding of the 256-bit **binding** digest:
//! - take a clone of the state after absorbs, update with `b"fork:binding\0"`, finalize.
//!
//! Challenge squeezing (FRI, composition weights, etc.) uses a separate fork:
//! - clone state, update `b"fork:challenge\0"` and a little-endian `u64` counter (starting at 0), finalize; first 16 bytes interpreted as `u128` LE.
//!
//! Any change to the above order or labels is a **breaking** change: bump the schema id and/or `proof_version` and update golden tests.

/// Schema id baked into the transcript root (bump when absorb order or labels change).
pub const TRANSCRIPT_SCHEMA_ID: u32 = 1;

/// Fiat-Shamir transcript state (BLAKE3, absorb chain).
#[derive(Clone)]
pub struct FsTranscript {
    hasher: blake3::Hasher,
    challenge_counter: u64,
}

impl FsTranscript {
    #[must_use]
    pub fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"probatum.fs.transcript\0");
        hasher.update(&TRANSCRIPT_SCHEMA_ID.to_le_bytes());
        Self { hasher, challenge_counter: 0 }
    }

    /// Absorbs public proof metadata in canonical order (see module docs).
    pub fn absorb_proof_inputs(
        &mut self,
        proof_version: &str,
        trace_len: u64,
        trace_digest_hex: &str,
    ) {
        self.hasher.update(b"msg:proof_version\0");
        self.hasher.update(&(proof_version.len() as u64).to_le_bytes());
        self.hasher.update(proof_version.as_bytes());

        self.hasher.update(b"msg:trace_len\0");
        self.hasher.update(&trace_len.to_le_bytes());

        self.hasher.update(b"msg:trace_digest_hex\0");
        self.hasher.update(&(trace_digest_hex.len() as u64).to_le_bytes());
        self.hasher.update(trace_digest_hex.as_bytes());
    }

    /// Absorbs a 32-byte commitment (e.g. Merkle root) after a fixed domain label.
    pub fn absorb_commitment_root(&mut self, msg: &'static [u8], root: &[u8; 32]) {
        self.hasher.update(msg);
        self.hasher.update(root);
    }

    /// Absorbs a variable-length digest (e.g. BLAKE3 output) with length prefix.
    pub fn absorb_digest(&mut self, msg: &'static [u8], digest: &[u8]) {
        self.hasher.update(msg);
        self.hasher.update(&(digest.len() as u64).to_le_bytes());
        self.hasher.update(digest);
    }

    /// Indexed Merkle root (e.g. FRI layer `round`).
    pub fn absorb_indexed_root(&mut self, msg: &'static [u8], index: u64, root: &[u8; 32]) {
        self.hasher.update(msg);
        self.hasher.update(&index.to_le_bytes());
        self.hasher.update(root);
    }

    /// 64-character lowercase hex binding digest for the current absorbed public inputs.
    #[must_use]
    pub fn binding_hex(&self) -> String {
        let mut h = self.hasher.clone();
        h.update(b"fork:binding\0");
        hex_encode_32(h.finalize().as_bytes())
    }

    /// Pseudorandom challenge (domain-separated from [`Self::binding_hex`]).
    #[must_use]
    pub fn squeeze_challenge_u128(&mut self) -> u128 {
        let mut h = self.hasher.clone();
        h.update(b"fork:challenge\0");
        h.update(&self.challenge_counter.to_le_bytes());
        self.challenge_counter += 1;
        let b = h.finalize();
        let x = b.as_bytes();
        u128::from_le_bytes(x[0..16].try_into().expect("16 bytes"))
    }
}

impl Default for FsTranscript {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: new transcript, absorb proof inputs, return binding hex (what `Proof.transcript` stores for FS-bound proofs).
#[must_use]
pub fn proof_binding_hex(proof_version: &str, trace_len: u64, trace_digest_hex: &str) -> String {
    let mut t = FsTranscript::new();
    t.absorb_proof_inputs(proof_version, trace_len, trace_digest_hex);
    t.binding_hex()
}

/// Lowercase hex encoding of 32 bytes (e.g. Merkle roots in proof JSON).
#[must_use]
pub fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from(LUT[(b >> 4) as usize]));
        s.push(char::from(LUT[(b & 0xf) as usize]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vector_tiny_inputs() {
        // Fixed 64-char lowercase hex (not necessarily a real trace digest).
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let got = proof_binding_hex("v2", 3, digest);
        assert_eq!(got.len(), 64);
        assert!(got.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(got, "ce04455bc2d306469389827fa97360065b83fbccd38e0856e23e95a147feb58f");
    }

    #[test]
    fn absorb_order_sensitive() {
        let a = proof_binding_hex("v2", 1, "a");
        let b = proof_binding_hex("v2", 1, "b");
        assert_ne!(a, b);
        let c = proof_binding_hex("v2", 2, "a");
        assert_ne!(a, c);
    }

    #[test]
    fn squeeze_deterministic_sequence() {
        let mut t = FsTranscript::new();
        t.absorb_proof_inputs(
            "v2",
            3,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let b = t.binding_hex();
        let mut t2 = FsTranscript::new();
        t2.absorb_proof_inputs(
            "v2",
            3,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(t2.binding_hex(), b);
        let c0 = t2.squeeze_challenge_u128();
        let c1 = t2.squeeze_challenge_u128();
        assert_ne!(c0, c1);
        let mut t3 = FsTranscript::new();
        t3.absorb_proof_inputs(
            "v2",
            3,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(t3.squeeze_challenge_u128(), c0);
        assert_eq!(t3.squeeze_challenge_u128(), c1);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn flip_one_digest_char_changes_binding(
            idx in 0usize..64usize,
            trace_len in 1u64..256u64
        ) {
            let base = "0000000000000000000000000000000000000000000000000000000000000000";
            let mut chars: Vec<char> = base.chars().collect();
            let old = chars[idx];
            let new_c = if old == '0' { '1' } else { '0' };
            chars[idx] = new_c;
            let flipped: String = chars.into_iter().collect();
            let h0 = proof_binding_hex("v2", trace_len, base);
            let h1 = proof_binding_hex("v2", trace_len, &flipped);
            prop_assert_ne!(h0, h1);
        }
    }
}
