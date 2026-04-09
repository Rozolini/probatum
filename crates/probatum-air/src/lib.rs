//! AIR-style validation layer for trace boundary and transition invariants.

use probatum_trace::{ExecutionTrace, TraceRow};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SelectorCoverage {
    pub add_rows: usize,
    pub mul_rows: usize,
    pub halt_rows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AirStatus {
    Ok,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirDiagnostics {
    pub status: AirStatus,
    pub reason_code: String,
    pub trace_rows: usize,
    pub selector_coverage: SelectorCoverage,
}

impl SelectorCoverage {
    #[must_use]
    pub fn all_selectors_seen(self) -> bool {
        self.add_rows > 0 && self.mul_rows > 0 && self.halt_rows > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirConfig {
    pub min_trace_rows: usize,
}

impl Default for AirConfig {
    fn default() -> Self {
        Self { min_trace_rows: 1 }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AirError {
    #[error("trace length {actual} is smaller than required {required}")]
    TraceTooShort { actual: usize, required: usize },
    #[error("first row must start at clk=0 and pc=0")]
    InvalidTraceStart,
    #[error("last row must be HALT opcode")]
    LastRowMustBeHalt,
    #[error("invalid opcode tag {0}")]
    InvalidOpTag(u8),
    #[error("non-sequential transition at row {0}")]
    NonSequentialTransition(usize),
    #[error("invalid accumulator transition at row {0}")]
    InvalidAccumulatorTransition(usize),
    #[error("halt row must have zero argument at row {0}")]
    InvalidHaltArgument(usize),
    #[error("selector coverage incomplete")]
    IncompleteSelectorCoverage,
}

/// Validates a full trace against boundary, transition, and selector-coverage rules.
pub fn validate_trace(trace: &ExecutionTrace, config: AirConfig) -> Result<(), AirError> {
    if trace.len() < config.min_trace_rows {
        return Err(AirError::TraceTooShort {
            actual: trace.len(),
            required: config.min_trace_rows,
        });
    }
    validate_boundary_constraints(trace)?;
    validate_transition_constraints(trace)?;
    let coverage = selector_coverage(trace);
    if !coverage.all_selectors_seen() {
        return Err(AirError::IncompleteSelectorCoverage);
    }
    Ok(())
}

#[must_use]
/// Returns per-opcode row counts used by selector coverage checks and reports.
pub fn selector_coverage(trace: &ExecutionTrace) -> SelectorCoverage {
    let mut coverage = SelectorCoverage::default();
    for row in &trace.rows {
        if is_add(row.op_tag) {
            coverage.add_rows += 1;
        } else if is_mul(row.op_tag) {
            coverage.mul_rows += 1;
        } else if is_halt(row.op_tag) {
            coverage.halt_rows += 1;
        }
    }
    coverage
}

#[must_use]
/// Produces machine-readable AIR status without changing validation semantics.
pub fn diagnostics(trace: &ExecutionTrace, config: AirConfig) -> AirDiagnostics {
    let coverage = selector_coverage(trace);
    match validate_trace(trace, config) {
        Ok(()) => AirDiagnostics {
            status: AirStatus::Ok,
            reason_code: "ok".to_string(),
            trace_rows: trace.len(),
            selector_coverage: coverage,
        },
        Err(err) => AirDiagnostics {
            status: AirStatus::Fail,
            reason_code: reason_code_for_error(&err).to_string(),
            trace_rows: trace.len(),
            selector_coverage: coverage,
        },
    }
}

fn reason_code_for_error(error: &AirError) -> &'static str {
    match error {
        AirError::TraceTooShort { .. } => "trace_too_short",
        AirError::InvalidTraceStart => "invalid_trace_start",
        AirError::LastRowMustBeHalt => "last_row_must_be_halt",
        AirError::InvalidOpTag(_) => "invalid_op_tag",
        AirError::NonSequentialTransition(_) => "non_sequential_transition",
        AirError::InvalidAccumulatorTransition(_) => "invalid_accumulator_transition",
        AirError::InvalidHaltArgument(_) => "invalid_halt_argument",
        AirError::IncompleteSelectorCoverage => "incomplete_selector_coverage",
    }
}

fn validate_op_tag(op_tag: u8) -> Result<(), AirError> {
    if matches!(op_tag, 1..=3) { Ok(()) } else { Err(AirError::InvalidOpTag(op_tag)) }
}

fn validate_boundary_constraints(trace: &ExecutionTrace) -> Result<(), AirError> {
    let first = trace.rows.first().ok_or(AirError::InvalidTraceStart)?;
    if first.clk != 0 || first.pc != 0 {
        return Err(AirError::InvalidTraceStart);
    }
    Ok(())
}

fn validate_transition_constraints(trace: &ExecutionTrace) -> Result<(), AirError> {
    for (i, row) in trace.rows.iter().enumerate() {
        validate_op_tag(row.op_tag)?;
        if row.op_tag == 3 && row.op_arg != 0 {
            return Err(AirError::InvalidHaltArgument(i));
        }
        if let Some(next) = trace.rows.get(i + 1) {
            validate_transition(i, row, next)?;
        }
    }
    if trace.rows.last().is_some_and(|row| row.op_tag != 3) {
        return Err(AirError::LastRowMustBeHalt);
    }
    Ok(())
}

fn validate_transition(index: usize, row: &TraceRow, next: &TraceRow) -> Result<(), AirError> {
    if next.clk != row.clk + 1 || next.pc != row.pc + 1 {
        return Err(AirError::NonSequentialTransition(index));
    }
    let expected_next_acc = expected_next_accumulator(row)?;
    if next.acc != expected_next_acc {
        return Err(AirError::InvalidAccumulatorTransition(index));
    }
    Ok(())
}

fn expected_next_accumulator(row: &TraceRow) -> Result<u64, AirError> {
    if is_add(row.op_tag) {
        return Ok(row.acc.wrapping_add(row.op_arg));
    }
    if is_mul(row.op_tag) {
        return Ok(row.acc.wrapping_mul(row.op_arg));
    }
    if is_halt(row.op_tag) {
        return Ok(row.acc);
    }
    Err(AirError::InvalidOpTag(row.op_tag))
}

const fn is_add(op_tag: u8) -> bool {
    op_tag == 1
}

const fn is_mul(op_tag: u8) -> bool {
    op_tag == 2
}

const fn is_halt(op_tag: u8) -> bool {
    op_tag == 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_trace::{ExecutionTrace, TraceRow};

    #[test]
    fn rejects_empty_trace() {
        let trace = ExecutionTrace::default();
        let err = validate_trace(&trace, AirConfig::default()).expect_err("empty trace must fail");
        assert_eq!(err, AirError::TraceTooShort { actual: 0, required: 1 });
    }

    #[test]
    fn validates_correct_transitions() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 4 },
                TraceRow { clk: 2, pc: 2, acc: 8, op_tag: 3, op_arg: 0 },
            ],
        };
        validate_trace(&trace, AirConfig::default()).expect("trace should be valid");
    }

    #[test]
    fn rejects_invalid_accumulator_transition() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 5, op_tag: 3, op_arg: 0 },
            ],
        };
        let err = validate_trace(&trace, AirConfig::default()).expect_err("must fail");
        assert_eq!(err, AirError::InvalidAccumulatorTransition(0));
    }

    #[test]
    fn rejects_invalid_opcode_tag() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 9, op_arg: 0 }] };
        let err = validate_trace(&trace, AirConfig::default()).expect_err("must fail");
        assert_eq!(err, AirError::InvalidOpTag(9));
    }

    #[test]
    fn rejects_non_sequential_transition() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 1, op_tag: 1, op_arg: 1 },
                TraceRow { clk: 2, pc: 2, acc: 2, op_tag: 3, op_arg: 0 },
            ],
        };
        let err = validate_trace(&trace, AirConfig::default()).expect_err("must fail");
        assert_eq!(err, AirError::NonSequentialTransition(0));
    }

    #[test]
    fn rejects_last_row_without_halt() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 1 }] };
        let err = validate_trace(&trace, AirConfig::default()).expect_err("must fail");
        assert_eq!(err, AirError::LastRowMustBeHalt);
    }

    #[test]
    fn rejects_halt_with_non_zero_argument() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 3, op_arg: 1 }] };
        let err = validate_trace(&trace, AirConfig::default()).expect_err("must fail");
        assert_eq!(err, AirError::InvalidHaltArgument(0));
    }

    #[test]
    fn rejects_incomplete_selector_coverage() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 3, op_arg: 0 }] };
        let err = validate_trace(&trace, AirConfig::default()).expect_err("must fail");
        assert_eq!(err, AirError::IncompleteSelectorCoverage);
    }

    #[test]
    fn selector_add_transition_is_applied() {
        let row = TraceRow { clk: 0, pc: 0, acc: 10, op_tag: 1, op_arg: 7 };
        let next = TraceRow { clk: 1, pc: 1, acc: 17, op_tag: 3, op_arg: 0 };
        validate_transition(0, &row, &next).expect("add selector should pass");
    }

    #[test]
    fn selector_mul_transition_is_applied() {
        let row = TraceRow { clk: 0, pc: 0, acc: 6, op_tag: 2, op_arg: 5 };
        let next = TraceRow { clk: 1, pc: 1, acc: 30, op_tag: 3, op_arg: 0 };
        validate_transition(0, &row, &next).expect("mul selector should pass");
    }

    #[test]
    fn selector_halt_transition_is_applied() {
        let row = TraceRow { clk: 0, pc: 0, acc: 11, op_tag: 3, op_arg: 0 };
        let next = TraceRow { clk: 1, pc: 1, acc: 11, op_tag: 3, op_arg: 0 };
        validate_transition(0, &row, &next).expect("halt selector should pass");
    }

    #[test]
    fn selector_coverage_counts_rows() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 3 },
                TraceRow { clk: 2, pc: 2, acc: 6, op_tag: 3, op_arg: 0 },
            ],
        };
        let coverage = selector_coverage(&trace);
        assert_eq!(coverage.add_rows, 1);
        assert_eq!(coverage.mul_rows, 1);
        assert_eq!(coverage.halt_rows, 1);
        assert!(coverage.all_selectors_seen());
    }

    #[test]
    fn diagnostics_returns_ok_reason() {
        let trace = ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 3 },
                TraceRow { clk: 2, pc: 2, acc: 6, op_tag: 3, op_arg: 0 },
            ],
        };
        let diag = diagnostics(&trace, AirConfig::default());
        assert_eq!(diag.status, AirStatus::Ok);
        assert_eq!(diag.reason_code, "ok");
    }

    #[test]
    fn diagnostics_returns_reason_code_for_failure() {
        let trace =
            ExecutionTrace { rows: vec![TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 3, op_arg: 0 }] };
        let diag = diagnostics(&trace, AirConfig::default());
        assert_eq!(diag.status, AirStatus::Fail);
        assert_eq!(diag.reason_code, "incomplete_selector_coverage");
    }
}
