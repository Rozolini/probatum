//! Criterion benchmark: `verify_detailed` on a valid `v4` proof.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use probatum_prover::prove;
use probatum_trace::{ExecutionTrace, TraceRow};
use probatum_verifier::verify_detailed;

fn four_row_trace() -> ExecutionTrace {
    ExecutionTrace {
        rows: vec![
            TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
            TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 4 },
            TraceRow { clk: 2, pc: 2, acc: 8, op_tag: 1, op_arg: 0 },
            TraceRow { clk: 3, pc: 3, acc: 8, op_tag: 3, op_arg: 0 },
        ],
    }
}

fn bench_verify_detailed(c: &mut Criterion) {
    let proof = prove(&four_row_trace()).expect("prove");
    c.bench_function("verify_detailed_v4", |b| {
        b.iter(|| verify_detailed(black_box(&proof)));
    });
}

criterion_group!(benches, bench_verify_detailed);
criterion_main!(benches);
