//! Property-based checks for deterministic VM stepping.

use crate::{Instruction, OpCode, VmState, step};
use proptest::prelude::*;

fn non_halt_instruction() -> impl Strategy<Value = Instruction> {
    prop_oneof![
        any::<u64>().prop_map(|arg| Instruction { op: OpCode::Add, arg }),
        any::<u64>().prop_map(|arg| Instruction { op: OpCode::Mul, arg }),
    ]
}

fn run_to_halt(program: &[Instruction]) -> VmState {
    let mut state = VmState::default();
    let mut guard = 0usize;
    while !state.halted {
        assert!(guard < 4096, "step guard exceeded");
        guard += 1;
        step(&mut state, program).expect("step should succeed until halt");
    }
    state
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn execution_is_deterministic(ops in prop::collection::vec(non_halt_instruction(), 0..24)) {
        let halt = Instruction {
            op: OpCode::Halt,
            arg: 0,
        };
        let mut program = ops;
        program.push(halt);
        let program = program.into_boxed_slice();
        let a = run_to_halt(&program);
        let b = run_to_halt(&program);
        prop_assert_eq!(a, b);
    }
}
