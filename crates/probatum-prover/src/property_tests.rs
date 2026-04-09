//! Property-based checks for proof encoding and decoding.

use crate::{PROOF_VERSION, decode_proof, encode_proof, prove};
use probatum_trace::{ExecutionTrace, TraceRow};
use proptest::prelude::*;

fn valid_trace_four_rows(add_arg: u64, mul_arg: u64) -> ExecutionTrace {
    let after_add = add_arg;
    let after_mul = add_arg.wrapping_mul(mul_arg);
    ExecutionTrace {
        rows: vec![
            TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: add_arg },
            TraceRow { clk: 1, pc: 1, acc: after_add, op_tag: 2, op_arg: mul_arg },
            TraceRow { clk: 2, pc: 2, acc: after_mul, op_tag: 1, op_arg: 0 },
            TraceRow { clk: 3, pc: 3, acc: after_mul, op_tag: 3, op_arg: 0 },
        ],
    }
}

proptest! {
    #[test]
    fn proof_encodes_and_decodes_roundtrip(add_arg in any::<u64>(), mul_arg in any::<u64>()) {
        let trace = valid_trace_four_rows(add_arg, mul_arg);
        let proof = prove(&trace).expect("prove");
        prop_assert_eq!(proof.trace_len, 4);
        prop_assert_eq!(proof.proof_version.as_str(), PROOF_VERSION);
        let bytes = encode_proof(&proof).expect("encode");
        let decoded = decode_proof(&bytes).expect("decode");
        prop_assert_eq!(proof, decoded);
    }
}
