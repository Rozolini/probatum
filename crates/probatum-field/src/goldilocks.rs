//! Goldilocks field: prime `p = 2^64 - 2^32 + 1`.

use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use serde::{Deserialize, Serialize};

/// Prime modulus `2^64 - 2^32 + 1` (fits in 64 bits).
pub const MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// Element of the Goldilocks field (canonical `0..MODULUS`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Field(pub u64);

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Field({:#x})", self.0)
    }
}

impl Field {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    /// Reduces `x` into `[0, MODULUS)`.
    #[must_use]
    pub const fn new(x: u64) -> Self {
        Self(x % MODULUS)
    }

    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// `self^exp (mod p)` via square-and-multiply.
    #[must_use]
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc *= base;
            }
            base *= base;
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse; [`None`] only when `self` is zero.
    #[must_use]
    pub fn inv(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        // Fermat: a^(p-2) mod p
        Some(self.pow(MODULUS - 2))
    }

    /// A primitive `2^k`-th root of unity for `k <= 32` (exists in this field).
    #[must_use]
    pub fn primitive_root_of_unity(k: u32) -> Option<Self> {
        if k == 0 || k > 32 {
            return None;
        }
        let root_2_32 = primitive_order_2_32_root()?;
        // `root_2_32` has order `2^32`; raise to `2^(32-k)` to get order `2^k`.
        let shift = 32u32.saturating_sub(k);
        Some(root_2_32.pow(1u64 << shift))
    }

    /// Builds [`Field`] from a small integer (for FFT scaling by `n`).
    #[must_use]
    pub fn from_u64(x: u64) -> Self {
        Self::new(x)
    }
}

impl Neg for Field {
    type Output = Self;

    fn neg(self) -> Self {
        if self.0 == 0 { Self::ZERO } else { Self(MODULUS - self.0) }
    }
}

impl Add for Field {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let s = (self.0 as u128 + rhs.0 as u128) % (MODULUS as u128);
        Self(s as u64)
    }
}

impl Sub for Field {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl Mul for Field {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let p = MODULUS as u128;
        let prod = (self.0 as u128 * rhs.0 as u128) % p;
        Self(prod as u64)
    }
}

impl AddAssign for Field {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl MulAssign for Field {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl SubAssign for Field {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

/// Finds `h = g^((p-1)/2^32)` with full order `2^32` for some small `g`.
fn primitive_order_2_32_root() -> Option<Field> {
    // `(p-1)/2^32 = 2^32 - 1`.
    let exp = (MODULUS - 1) >> 32;
    debug_assert_eq!(exp, u64::MAX >> 32); // 2^32 - 1

    for g in 2u64..=10_000 {
        let base = Field::new(g);
        let h = base.pow(exp);
        if h.is_zero() {
            continue;
        }
        // If `h^(2^31) != 1`, order is not a divisor of `2^31`, hence order is `2^32`.
        if h.pow(1u64 << 31) != Field::ONE {
            return Some(h);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_is_prime_shape() {
        assert_eq!(u128::from(MODULUS), (1u128 << 64) - (1u128 << 32) + 1);
    }

    #[test]
    fn add_sub_inverse() {
        let a = Field::new(123_456_789);
        assert_eq!(a + (-a), Field::ZERO);
    }

    #[test]
    fn mul_inv_roundtrip() {
        let a = Field::new(42);
        let ai = a.inv().expect("nonzero invertible");
        assert_eq!(a * ai, Field::ONE);
    }

    #[test]
    fn primitive_unity_order() {
        let k = 8usize;
        let w = Field::primitive_root_of_unity(k as u32).expect("root");
        let n = 1u64 << k;
        assert_eq!(w.pow(n), Field::ONE);
        assert_ne!(w.pow(n / 2), Field::ONE);
    }
}
