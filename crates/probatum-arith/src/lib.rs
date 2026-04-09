//! Arithmetized execution trace: register columns and opcode selectors in [`Field`].

mod columns;
mod trace;

pub use columns::{ACC, CLK, COLUMN_COUNT, OP_ARG, PC, S_ADD, S_HALT, S_MUL};
pub use trace::{ArithRow, ArithmetizeError, ArithmetizedTrace, arithmetize};
