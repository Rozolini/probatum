//! Conservative degree bounds for LDE sizing (formal polynomials interpolate trace columns).

/// Number of padded constraint families returned by [`ConstraintResiduals::families_uniform`](crate::ConstraintResiduals::families_uniform).
pub const CONSTRAINT_FAMILY_COUNT: usize = 8;

/// Upper bound on total degree of a random linear combination of constraint numerators,
/// when each trace column is interpolated by a polynomial of degree at most `n-1`.
///
/// This is a **conservative** engineering estimate for `n >= 2`, not a tight certificate.
#[must_use]
pub fn composition_degree_upper_bound(trace_len: usize) -> usize {
    let n = trace_len;
    match n {
        0 => 0,
        1 => 1,
        _ => 3 * (n - 1) + 2,
    }
}
