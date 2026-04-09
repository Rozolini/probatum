//! Deterministic VM core used by trace generation tests and demos.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpCode {
    Add,
    Mul,
    Halt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub op: OpCode,
    pub arg: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VmState {
    pub pc: usize,
    pub acc: u64,
    pub halted: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VmError {
    #[error("program counter out of bounds: {0}")]
    ProgramCounterOutOfBounds(usize),
}

/// Executes exactly one instruction from the current program counter.
///
/// The function is intentionally side-effect free outside `state` so higher
/// layers can produce deterministic traces and replay transitions.
pub fn step(state: &mut VmState, program: &[Instruction]) -> Result<(), VmError> {
    if state.halted {
        return Ok(());
    }
    let Some(instruction) = program.get(state.pc) else {
        return Err(VmError::ProgramCounterOutOfBounds(state.pc));
    };

    match instruction.op {
        OpCode::Add => state.acc = state.acc.wrapping_add(instruction.arg),
        OpCode::Mul => state.acc = state.acc.wrapping_mul(instruction.arg),
        OpCode::Halt => state.halted = true,
    }
    state.pc += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_program() {
        let program = [
            Instruction { op: OpCode::Add, arg: 5 },
            Instruction { op: OpCode::Mul, arg: 3 },
            Instruction { op: OpCode::Halt, arg: 0 },
        ];
        let mut state = VmState::default();
        while !state.halted {
            step(&mut state, &program).expect("vm step should succeed");
        }
        assert_eq!(state.acc, 15);
    }

    #[cfg(feature = "loom")]
    #[test]
    fn loom_model_progresses_state() {
        loom::model(|| {
            let program = [Instruction { op: OpCode::Add, arg: 1 }];
            let mut state = VmState::default();
            let result = step(&mut state, &program);
            assert!(result.is_ok());
        });
    }
}

#[cfg(test)]
mod property_tests;
