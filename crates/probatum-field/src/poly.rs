//! Dense univariate polynomials over [`Field`](crate::Field).

use crate::goldilocks::Field;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial(Vec<Field>);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolyError {
    #[error("division by zero polynomial")]
    DivisionByZero,
}

impl Polynomial {
    /// Creates a polynomial from coefficients `[c0, c1, …]` representing `c0 + c1 x + …`.
    #[must_use]
    pub fn from_coeffs(mut coeffs: Vec<Field>) -> Self {
        trim_trailing_zeros(&mut coeffs);
        Self(coeffs)
    }

    #[must_use]
    pub fn zero() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn coeffs(&self) -> &[Field] {
        &self.0
    }

    #[must_use]
    pub fn degree(&self) -> Option<usize> {
        if self.0.is_empty() { None } else { Some(self.0.len() - 1) }
    }

    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let n = self.0.len().max(rhs.0.len());
        let mut out = vec![Field::ZERO; n];
        for (i, slot) in out.iter_mut().enumerate() {
            let a = self.0.get(i).copied().unwrap_or(Field::ZERO);
            let b = rhs.0.get(i).copied().unwrap_or(Field::ZERO);
            *slot = a + b;
        }
        Self::from_coeffs(out)
    }

    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        let n = self.0.len().max(rhs.0.len());
        let mut out = vec![Field::ZERO; n];
        for (i, slot) in out.iter_mut().enumerate() {
            let a = self.0.get(i).copied().unwrap_or(Field::ZERO);
            let b = rhs.0.get(i).copied().unwrap_or(Field::ZERO);
            *slot = a - b;
        }
        Self::from_coeffs(out)
    }

    /// Schoolbook multiplication.
    #[must_use]
    pub fn mul(&self, rhs: &Self) -> Self {
        if self.0.is_empty() || rhs.0.is_empty() {
            return Self::zero();
        }
        let mut out = vec![Field::ZERO; self.0.len() + rhs.0.len() - 1];
        for (i, a) in self.0.iter().enumerate() {
            for (j, b) in rhs.0.iter().enumerate() {
                out[i + j] += *a * *b;
            }
        }
        Self::from_coeffs(out)
    }

    /// Horner evaluation at `x`.
    #[must_use]
    pub fn eval(&self, x: Field) -> Field {
        if self.0.is_empty() {
            return Field::ZERO;
        }
        let mut acc = Field::ZERO;
        for &c in self.0.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }
}

fn trim_trailing_zeros(c: &mut Vec<Field>) {
    while c.last().is_some_and(|x| x.is_zero()) {
        c.pop();
    }
}

/// Polynomial long division: `a = q * b + r`, `deg r < deg b`.
pub fn div_rem(a: &Polynomial, b: &Polynomial) -> Result<(Polynomial, Polynomial), PolyError> {
    if b.0.is_empty() || (b.0.len() == 1 && b.0[0].is_zero()) {
        return Err(PolyError::DivisionByZero);
    }
    if a.0.is_empty() {
        return Ok((Polynomial::zero(), Polynomial::zero()));
    }

    let deg_b = b.0.len() - 1;
    let b_lead = b.0[deg_b];
    let b_inv = b_lead.inv().ok_or(PolyError::DivisionByZero)?;

    let mut rem = a.0.clone();
    let mut q = vec![Field::ZERO; a.0.len().saturating_sub(deg_b).max(1)];

    while rem.len() >= b.0.len() {
        let deg_r = rem.len() - 1;
        let lead = *rem.last().expect("non-empty remainder");
        if lead.is_zero() {
            rem.pop();
            trim_trailing_zeros(&mut rem);
            continue;
        }
        let shift = deg_r - deg_b;
        let scale = lead * b_inv;
        if shift >= q.len() {
            q.resize(shift + 1, Field::ZERO);
        }
        q[shift] += scale;
        for j in 0..b.0.len() {
            rem[shift + j] -= b.0[j] * scale;
        }
        trim_trailing_zeros(&mut rem);
    }

    Ok((Polynomial::from_coeffs(q), Polynomial::from_coeffs(rem)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goldilocks::MODULUS;

    #[test]
    fn mul_div_roundtrip_small() {
        let p = Polynomial::from_coeffs(vec![Field::new(1), Field::new(2), Field::new(3)]);
        let q = Polynomial::from_coeffs(vec![Field::new(5), Field::new(7)]);
        let prod = p.mul(&q);
        let (qq, r) = div_rem(&prod, &q).expect("div");
        assert_eq!(r, Polynomial::zero());
        assert_eq!(qq, p);
    }

    #[test]
    fn eval_line() {
        let p = Polynomial::from_coeffs(vec![Field::new(3), Field::new(2)]);
        assert_eq!(p.eval(Field::new(4)), Field::new((3 + 8) % MODULUS));
    }
}
