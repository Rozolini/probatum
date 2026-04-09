//! Trace data model and deterministic trace hashing helpers.

mod merkle;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use merkle::{leaf_hash, merkle_root_from_leaves};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRow {
    pub clk: u64,
    pub pc: u64,
    pub acc: u64,
    pub op_tag: u8,
    pub op_arg: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExecutionTrace {
    pub rows: Vec<TraceRow>,
}

impl ExecutionTrace {
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Computes a deterministic digest for the current trace.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical trace serialization fails.
    pub fn digest_hex(&self) -> Result<String, TraceError> {
        let bytes = serde_json::to_vec(self).map_err(TraceError::Serialize)?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// Merkle root over per-row leaf digests (see `merkle` module).
    ///
    /// # Errors
    ///
    /// Returns an error when the trace is empty or a row cannot be serialized.
    pub fn merkle_root_hex(&self) -> Result<String, TraceError> {
        if self.is_empty() {
            return Err(TraceError::EmptyTraceMerkle);
        }
        let mut leaves = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            leaves.push(leaf_hash(row)?);
        }
        let root = merkle_root_from_leaves(&leaves).expect("non-empty trace has a root");
        Ok(blake3::Hash::from(root).to_hex().to_string())
    }
}

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("trace serialization failed")]
    Serialize(#[source] serde_json::Error),
    #[error("merkle root is undefined for an empty trace")]
    EmptyTraceMerkle,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_has_length() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 0, op_arg: 0 }] };
        assert_eq!(trace.len(), 1);
        assert!(!trace.is_empty());
    }

    #[test]
    fn digest_is_deterministic() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 7, op_tag: 1, op_arg: 2 }] };
        let d1 = trace.digest_hex().expect("digest should pass");
        let d2 = trace.digest_hex().expect("digest should pass");
        assert_eq!(d1, d2);
    }

    #[test]
    fn merkle_root_rejects_empty_trace() {
        let trace = ExecutionTrace::default();
        let err = trace.merkle_root_hex().expect_err("empty trace has no merkle root");
        assert!(matches!(err, TraceError::EmptyTraceMerkle));
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 3 },
                TraceRow { clk: 2, pc: 2, acc: 6, op_tag: 3, op_arg: 0 },
            ],
        };
        let a = trace.merkle_root_hex().expect("merkle");
        let b = trace.merkle_root_hex().expect("merkle");
        assert_eq!(a.len(), 64);
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod property_tests;
