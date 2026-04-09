//! Property-based checks for trace digests.

use crate::{ExecutionTrace, TraceRow};
use proptest::prelude::*;

fn trace_row_strategy() -> impl Strategy<Value = TraceRow> {
    (any::<u64>(), any::<u64>(), any::<u64>(), 1u8..=3u8, any::<u64>())
        .prop_map(|(clk, pc, acc, op_tag, op_arg)| TraceRow { clk, pc, acc, op_tag, op_arg })
}

proptest! {
    #[test]
    fn digest_hex_is_stable(rows in prop::collection::vec(trace_row_strategy(), 0..48)) {
        let trace = ExecutionTrace { rows };
        let d1 = trace.digest_hex().expect("digest");
        let d2 = trace.digest_hex().expect("digest");
        prop_assert_eq!(d1.len(), 64);
        prop_assert_eq!(d1, d2);
    }

    #[test]
    fn merkle_root_hex_is_stable(rows in prop::collection::vec(trace_row_strategy(), 1..48)) {
        let trace = ExecutionTrace { rows };
        let m1 = trace.merkle_root_hex().expect("merkle");
        let m2 = trace.merkle_root_hex().expect("merkle");
        prop_assert_eq!(m1.len(), 64);
        prop_assert_eq!(m1, m2);
    }
}
