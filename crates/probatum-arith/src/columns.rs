//! Fixed column indices for dense row-major layouts (used by later polynomial layers).

/// `clk` (clock).
pub const CLK: usize = 0;
/// Program counter.
pub const PC: usize = 1;
/// Accumulator (pre-instruction state, matches `TraceRow::acc`).
pub const ACC: usize = 2;
/// Instruction immediate argument.
pub const OP_ARG: usize = 3;
/// Selector: `1` iff current row is `ADD`.
pub const S_ADD: usize = 4;
/// Selector: `1` iff current row is `MUL`.
pub const S_MUL: usize = 5;
/// Selector: `1` iff current row is `HALT`.
pub const S_HALT: usize = 6;

/// Number of field columns per trace row (fixed layout v1).
pub const COLUMN_COUNT: usize = 7;
