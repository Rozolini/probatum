//! Low-degree extension: interpolate trace evaluations on a size-`n` subgroup, then evaluate on a larger subgroup.

use probatum_field::{FftError, Field, MAX_FFT_LEN, fft, ifft};
use thiserror::Error;

/// Trace length must be a power of two so the trace domain is a multiplicative subgroup (radix-2 FFT).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LdeError {
    #[error("trace length {0} must be a non-zero power of two")]
    TraceLengthNotPowerOfTwo(usize),
    #[error("blowup factor {0} must be a power of two and at least 1")]
    InvalidBlowup(usize),
    #[error("LDE domain size {lde} exceeds MAX_FFT_LEN")]
    DomainTooLarge { lde: usize },
    #[error("FFT error: {0}")]
    Fft(#[from] FftError),
}

/// `trace_evals[i]` = column value at `ω^i` on the trace subgroup (`ω` primitive `n`-th root of unity).
///
/// Returns evaluations of the same interpolant on the **`n * blowup`**-point subgroup (canonical radix-2 FFT domain).
///
/// # Errors
///
/// Fails when `trace_evals.len()` or `blowup` are not powers of two, or when the LDE domain is too large.
pub fn lde_extend_column(trace_evals: &[Field], blowup: usize) -> Result<Vec<Field>, LdeError> {
    let n = trace_evals.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(LdeError::TraceLengthNotPowerOfTwo(n));
    }
    if blowup == 0 || !blowup.is_power_of_two() {
        return Err(LdeError::InvalidBlowup(blowup));
    }
    let lde = n.checked_mul(blowup).ok_or(LdeError::DomainTooLarge { lde: usize::MAX })?;
    if lde > MAX_FFT_LEN {
        return Err(LdeError::DomainTooLarge { lde });
    }

    let mut coeffs = ifft(trace_evals)?;
    coeffs.resize(lde, Field::ZERO);
    fft(&coeffs).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn horner_eval(coeffs: &[Field], x: Field) -> Field {
        let mut acc = Field::ZERO;
        for &c in coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    #[test]
    fn lde_matches_naive_horner_small() {
        let n = 4usize;
        let vals: Vec<Field> =
            (0..n).map(|i| Field::new((i as u64 * 13 + 5) % probatum_field::MODULUS)).collect();
        let blowup = 4usize;
        let lde = lde_extend_column(&vals, blowup).expect("lde");
        let l = n * blowup;
        assert_eq!(lde.len(), l);

        let mut coeffs = ifft(&vals).expect("ifft");
        coeffs.resize(l, Field::ZERO);
        let omega_l = Field::primitive_root_of_unity(l.trailing_zeros()).expect("root");
        for (j, lde_j) in lde.iter().enumerate().take(l) {
            let x = omega_l.pow(j as u64);
            let expected = horner_eval(&coeffs, x);
            assert_eq!(*lde_j, expected, "j={j}");
        }
    }

    #[test]
    fn rejects_non_power_of_two_trace() {
        let vals = vec![Field::ONE, Field::ONE, Field::ONE];
        let err = lde_extend_column(&vals, 2).expect_err("expect err");
        assert_eq!(err, LdeError::TraceLengthNotPowerOfTwo(3));
    }
}
