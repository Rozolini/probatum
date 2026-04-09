//! Criterion benchmark: integrated `prove` on the canonical 4-row sample trace.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use probatum_prover::prove;
use probatum_trace::{ExecutionTrace, TraceRow};

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

fn bench_integrated_prove(c: &mut Criterion) {
    let trace = four_row_trace();
    c.bench_function("prove_integrated_4_rows", |b| {
        b.iter(|| prove(black_box(&trace)).expect("prove"));
    });
}

criterion_group!(benches, bench_integrated_prove);
criterion_main!(benches);
