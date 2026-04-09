//! Map [`ExecutionTrace`](probatum_trace::ExecutionTrace) rows into [`ArithRow`].

use crate::columns::{ACC, CLK, COLUMN_COUNT, OP_ARG, PC, S_ADD, S_HALT, S_MUL};
use probatum_air::{AirConfig, AirError, validate_trace};
use probatum_field::Field;
use probatum_trace::{ExecutionTrace, TraceRow};
use thiserror::Error;

/// One row of the arithmetized trace (canonical field encoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArithRow {
    /// All columns in index order [`CLK`..=`S_HALT`](crate::columns).
    pub cols: [Field; COLUMN_COUNT],
}

impl ArithRow {
    #[must_use]
    pub fn clk(&self) -> Field {
        self.cols[CLK]
    }

    #[must_use]
    pub fn pc(&self) -> Field {
        self.cols[PC]
    }

    #[must_use]
    pub fn acc(&self) -> Field {
        self.cols[ACC]
    }

    #[must_use]
    pub fn op_arg(&self) -> Field {
        self.cols[OP_ARG]
    }

    #[must_use]
    pub fn s_add(&self) -> Field {
        self.cols[S_ADD]
    }

    #[must_use]
    pub fn s_mul(&self) -> Field {
        self.cols[S_MUL]
    }

    #[must_use]
    pub fn s_halt(&self) -> Field {
        self.cols[S_HALT]
    }
}

/// Full trace as field columns (same row order as [`ExecutionTrace`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArithmetizedTrace {
    pub rows: Vec<ArithRow>,
}

impl ArithmetizedTrace {
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Column-major storage: `out[col][row]`.
    #[must_use]
    pub fn column_major(&self) -> Vec<Vec<Field>> {
        let n = self.rows.len();
        let mut out = vec![vec![Field::ZERO; n]; COLUMN_COUNT];
        for (r, row) in self.rows.iter().enumerate() {
            for (c, v) in row.cols.iter().enumerate() {
                out[c][r] = *v;
            }
        }
        out
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArithmetizeError {
    #[error("air validation failed")]
    Air(#[from] AirError),
}

/// Converts a trace to field columns after AIR validation.
///
/// Selector semantics match `probatum-air`: `op_tag` 1 = ADD, 2 = MUL, 3 = HALT.
/// Each row has `s_add + s_mul + s_halt = 1` in the field.
///
/// # Errors
///
/// Returns an error when [`validate_trace`](probatum_air::validate_trace) fails.
pub fn arithmetize(
    trace: &ExecutionTrace,
    air: AirConfig,
) -> Result<ArithmetizedTrace, ArithmetizeError> {
    validate_trace(trace, air)?;
    let rows = trace.rows.iter().map(|row| ArithRow { cols: row_to_cols(row) }).collect();
    Ok(ArithmetizedTrace { rows })
}

fn row_to_cols(row: &TraceRow) -> [Field; COLUMN_COUNT] {
    let (s_add, s_mul, s_halt) = selectors(row.op_tag);
    [
        Field::new(row.clk),
        Field::new(row.pc),
        Field::new(row.acc),
        Field::new(row.op_arg),
        s_add,
        s_mul,
        s_halt,
    ]
}

fn selectors(op_tag: u8) -> (Field, Field, Field) {
    match op_tag {
        1 => (Field::ONE, Field::ZERO, Field::ZERO),
        2 => (Field::ZERO, Field::ONE, Field::ZERO),
        3 => (Field::ZERO, Field::ZERO, Field::ONE),
        // `validate_trace` ensures `op_tag ∈ {1,2,3}` before we map rows.
        _ => unreachable!("arithmetize: row op_tag must be validated by AIR"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_trace::ExecutionTrace;

    fn valid_demo_trace() -> ExecutionTrace {
        ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 4 },
                TraceRow { clk: 2, pc: 2, acc: 8, op_tag: 3, op_arg: 0 },
            ],
        }
    }

    #[test]
    fn valid_trace_arithmetizes() {
        let t = valid_demo_trace();
        let a = arithmetize(&t, AirConfig::default()).expect("arith");
        assert_eq!(a.len(), 3);
        for row in &a.rows {
            let sum = row.s_add() + row.s_mul() + row.s_halt();
            assert_eq!(sum, Field::ONE);
        }
    }

    #[test]
    fn rejects_air_invalid_trace() {
        let bad =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 9, op_arg: 0 }] };
        let err = arithmetize(&bad, AirConfig::default()).expect_err("invalid op");
        assert!(matches!(err, ArithmetizeError::Air(AirError::InvalidOpTag(9))));
    }

    #[test]
    fn column_major_shape() {
        let t = valid_demo_trace();
        let a = arithmetize(&t, AirConfig::default()).expect("arith");
        let cm = a.column_major();
        assert_eq!(cm.len(), COLUMN_COUNT);
        assert_eq!(cm[0].len(), 3);
    }
}
