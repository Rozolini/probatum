//! Goldilocks prime field, dense polynomials, and radix-2 FFT/IFFT on power-of-two lengths.
//!
//! Modulus `p = 2^64 - 2^32 + 1` supports multiplicative subgroups of order `2^k` for `k <= 32`.

mod fft;
mod goldilocks;
mod poly;

pub use fft::{FftError, MAX_FFT_LEN, fft, ifft};
pub use goldilocks::{Field, MODULUS};
pub use poly::{PolyError, Polynomial, div_rem};

#[cfg(test)]
mod property_tests;
