//! Evaluate constraint expressions on the trace domain (one value per row or per edge).

use crate::composition::pad_to_len;
use probatum_arith::ArithmetizedTrace;
use probatum_field::Field;

/// All constraint families for the toy VM (evaluation form, not symbolic polynomials).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintResiduals {
    /// Trace length `n`.
    pub n: usize,
    /// `clk` and `pc` must be zero on row 0; stored length `n` with zeros elsewhere.
    pub boundary_clk: Vec<Field>,
    pub boundary_pc: Vec<Field>,
    /// For each edge `i -> i+1`, `0 <= i < n-1`: clock increases by one.
    pub transition_clk: Vec<Field>,
    /// Same for `pc`.
    pub transition_pc: Vec<Field>,
    /// Opcode-specific accumulator transition (matches `probatum-air` semantics).
    pub transition_acc: Vec<Field>,
    /// `s_halt * op_arg` must be zero on every row.
    pub halt_arg: Vec<Field>,
    /// `s_add + s_mul + s_halt - 1` on every row.
    pub selector_sum: Vec<Field>,
    /// Last row must be `HALT`: entry `1 - s_halt` at index `n-1` only (rest zero).
    pub last_row_halt: Vec<Field>,
}

impl ConstraintResiduals {
    /// Pads shorter vectors with zeros so every family has length `n` (composition input).
    #[must_use]
    pub fn families_uniform(&self) -> Vec<Vec<Field>> {
        let n = self.n;
        vec![
            pad_to_len(&self.boundary_clk, n),
            pad_to_len(&self.boundary_pc, n),
            pad_to_len(&self.transition_clk, n),
            pad_to_len(&self.transition_pc, n),
            pad_to_len(&self.transition_acc, n),
            pad_to_len(&self.halt_arg, n),
            pad_to_len(&self.selector_sum, n),
            pad_to_len(&self.last_row_halt, n),
        ]
    }

    /// True iff every stored residual is zero where the constraint is active.
    #[must_use]
    pub fn all_zero(&self) -> bool {
        self.boundary_clk.iter().all(|x| x.is_zero())
            && self.boundary_pc.iter().all(|x| x.is_zero())
            && self.transition_clk.iter().all(|x| x.is_zero())
            && self.transition_pc.iter().all(|x| x.is_zero())
            && self.transition_acc.iter().all(|x| x.is_zero())
            && self.halt_arg.iter().all(|x| x.is_zero())
            && self.selector_sum.iter().all(|x| x.is_zero())
            && self.last_row_halt.iter().all(|x| x.is_zero())
    }
}

/// Computes residuals for an arithmetized trace (usually AIR-valid).
#[must_use]
pub fn constraint_residuals(a: &ArithmetizedTrace) -> ConstraintResiduals {
    let n = a.len();
    assert!(n >= 1, "empty trace");

    let mut boundary_clk = vec![Field::ZERO; n];
    let mut boundary_pc = vec![Field::ZERO; n];
    boundary_clk[0] = a.rows[0].clk();
    boundary_pc[0] = a.rows[0].pc();

    let mut transition_clk = Vec::with_capacity(n.saturating_sub(1));
    let mut transition_pc = Vec::with_capacity(n.saturating_sub(1));
    let mut transition_acc = Vec::with_capacity(n.saturating_sub(1));
    for i in 0..n.saturating_sub(1) {
        let r = &a.rows[i];
        let nx = &a.rows[i + 1];
        transition_clk.push(nx.clk() - r.clk() - Field::ONE);
        transition_pc.push(nx.pc() - r.pc() - Field::ONE);
        let acc_add = nx.acc() - (r.acc() + r.op_arg());
        let acc_mul = nx.acc() - (r.acc() * r.op_arg());
        let acc_halt = nx.acc() - r.acc();
        transition_acc.push(r.s_add() * acc_add + r.s_mul() * acc_mul + r.s_halt() * acc_halt);
    }

    let mut halt_arg = Vec::with_capacity(n);
    let mut selector_sum = Vec::with_capacity(n);
    for r in &a.rows {
        halt_arg.push(r.s_halt() * r.op_arg());
        selector_sum.push(r.s_add() + r.s_mul() + r.s_halt() - Field::ONE);
    }

    let mut last_row_halt = vec![Field::ZERO; n];
    last_row_halt[n - 1] = Field::ONE - a.rows[n - 1].s_halt();

    ConstraintResiduals {
        n,
        boundary_clk,
        boundary_pc,
        transition_clk,
        transition_pc,
        transition_acc,
        halt_arg,
        selector_sum,
        last_row_halt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_air::AirConfig;
    use probatum_arith::arithmetize;
    use probatum_trace::{ExecutionTrace, TraceRow};

    fn valid_three_row() -> ExecutionTrace {
        ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 4 },
                TraceRow { clk: 2, pc: 2, acc: 8, op_tag: 3, op_arg: 0 },
            ],
        }
    }

    #[test]
    fn valid_trace_all_zero() {
        let t = arithmetize(&valid_three_row(), AirConfig::default()).expect("arith");
        let r = constraint_residuals(&t);
        assert!(r.all_zero());
    }

    #[test]
    fn corrupted_acc_nonzero() {
        let mut t = arithmetize(&valid_three_row(), AirConfig::default()).expect("arith");
        t.rows[1].cols[probatum_arith::ACC] = Field::new(1);
        let r = constraint_residuals(&t);
        assert!(!r.all_zero());
    }

    #[test]
    fn linear_composition_zero_on_valid() {
        use crate::CONSTRAINT_FAMILY_COUNT;
        use crate::compose_linear;

        let t = arithmetize(&valid_three_row(), AirConfig::default()).expect("arith");
        let res = constraint_residuals(&t);
        let fam = res.families_uniform();
        assert_eq!(fam.len(), CONSTRAINT_FAMILY_COUNT);
        let alphas = vec![Field::new(11); CONSTRAINT_FAMILY_COUNT];
        let c = compose_linear(&fam, &alphas).expect("compose");
        assert!(c.iter().all(|x| x.is_zero()));
    }
}
