//! Linear composition of padded constraint rows.

use probatum_field::Field;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ComposeError {
    #[error("need at least one family")]
    Empty,
    #[error("family lengths differ")]
    LengthMismatch,
    #[error("alpha count {got} != family count {expected}")]
    AlphaCount { expected: usize, got: usize },
}

/// Pads `v` with zeros to length `n`.
#[must_use]
pub fn pad_to_len(v: &[Field], n: usize) -> Vec<Field> {
    if v.len() > n {
        return v[..n].to_vec();
    }
    let mut o = v.to_vec();
    o.resize(n, Field::ZERO);
    o
}

/// Pointwise linear combination: `out[i] = sum_k alphas[k] * families[k][i]`.
pub fn compose_linear(
    families: &[Vec<Field>],
    alphas: &[Field],
) -> Result<Vec<Field>, ComposeError> {
    if families.is_empty() {
        return Err(ComposeError::Empty);
    }
    let n = families[0].len();
    if !families.iter().all(|f| f.len() == n) {
        return Err(ComposeError::LengthMismatch);
    }
    if alphas.len() != families.len() {
        return Err(ComposeError::AlphaCount { expected: families.len(), got: alphas.len() });
    }
    let mut out = vec![Field::ZERO; n];
    for i in 0..n {
        for (k, fam) in families.iter().enumerate() {
            out[i] += fam[i] * alphas[k];
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_matches_manual() {
        let a = vec![Field::ONE, Field::ZERO];
        let b = vec![Field::ZERO, Field::ONE];
        let out = compose_linear(&[a, b], &[Field::new(2), Field::new(3)]).expect("compose");
        assert_eq!(out[0], Field::new(2));
        assert_eq!(out[1], Field::new(3));
    }
}
