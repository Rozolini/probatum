//! Radix-2 Cooley–Tukey FFT over the Goldilocks field.

use crate::goldilocks::Field;
use thiserror::Error;

/// Maximum FFT length `2^24` (keeps work bounded in tests and early integrations).
pub const MAX_FFT_LEN: usize = 1 << 24;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FftError {
    #[error("fft length must be a non-zero power of two")]
    InvalidLength,
    #[error("fft length {0} exceeds MAX_FFT_LEN")]
    TooLarge(usize),
}

fn bit_reverse(mut i: u32, bits: u32) -> u32 {
    let mut r = 0u32;
    for _ in 0..bits {
        r = (r << 1) | (i & 1);
        i >>= 1;
    }
    r
}

/// Discrete Fourier transform: `y[k] = sum_j c[j] * ω^(jk)` with primitive `n`-th root `ω`.
pub fn fft(coeffs: &[Field]) -> Result<Vec<Field>, FftError> {
    let n = coeffs.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(FftError::InvalidLength);
    }
    if n > MAX_FFT_LEN {
        return Err(FftError::TooLarge(n));
    }
    let k = n.trailing_zeros();
    let omega = Field::primitive_root_of_unity(k).ok_or(FftError::InvalidLength)?;
    fft_inplace(coeffs, omega)
}

/// Inverse DFT, scaled so `ifft(fft(c)) == c`.
pub fn ifft(values: &[Field]) -> Result<Vec<Field>, FftError> {
    let n = values.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(FftError::InvalidLength);
    }
    if n > MAX_FFT_LEN {
        return Err(FftError::TooLarge(n));
    }
    let k = n.trailing_zeros();
    let omega = Field::primitive_root_of_unity(k).ok_or(FftError::InvalidLength)?;
    let omega_inv = omega.pow((n as u64) - 1);
    let mut out = fft_inplace(values, omega_inv)?;
    let n_inv = Field::from_u64(n as u64).inv().ok_or(FftError::InvalidLength)?;
    for x in &mut out {
        *x *= n_inv;
    }
    Ok(out)
}

fn fft_inplace(input: &[Field], omega: Field) -> Result<Vec<Field>, FftError> {
    let n = input.len();
    let log_n = n.trailing_zeros();
    let mut a = input.to_vec();

    for i in 0..n {
        let j = bit_reverse(i as u32, log_n) as usize;
        if i < j {
            a.swap(i, j);
        }
    }

    let mut len = 2usize;
    while len <= n {
        let half = len / 2;
        let wlen = omega.pow((n / len) as u64);
        for i in (0..n).step_by(len) {
            let mut w = Field::ONE;
            for j in 0..half {
                let u = a[i + j];
                let v = a[i + j + half] * w;
                a[i + j] = u + v;
                a[i + j + half] = u - v;
                w *= wlen;
            }
        }
        len <<= 1;
    }

    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goldilocks::MODULUS;

    fn naive_dft(coeffs: &[Field], omega: Field) -> Vec<Field> {
        let n = coeffs.len();
        let mut out = vec![Field::ZERO; n];
        for (k, slot) in out.iter_mut().enumerate() {
            let mut acc = Field::ZERO;
            for (j, cj) in coeffs.iter().enumerate() {
                let exp = ((j as u128 * k as u128) % (n as u128)) as u64;
                acc += *cj * omega.pow(exp);
            }
            *slot = acc;
        }
        out
    }

    #[test]
    fn fft_matches_naive_small() {
        for log_n in 1u32..=6 {
            let n = 1usize << log_n;
            let omega = Field::primitive_root_of_unity(log_n).expect("root");
            let coeffs: Vec<Field> =
                (0..n).map(|i| Field::new((i as u64 * 7 + 3) % MODULUS)).collect();
            let y_fft = fft(&coeffs).expect("fft");
            let y_naive = naive_dft(&coeffs, omega);
            assert_eq!(y_fft, y_naive, "log_n={log_n}");
        }
    }

    #[test]
    fn ifft_inverts_fft() {
        let coeffs: Vec<Field> = vec![Field::new(1), Field::new(2), Field::new(3), Field::new(4)];
        let y = fft(&coeffs).expect("fft");
        let round = ifft(&y).expect("ifft");
        assert_eq!(round, coeffs);
    }
}
