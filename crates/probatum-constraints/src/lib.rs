//! Algebraic residuals for the toy VM AIR and linear composition (evaluation form).
//! Evaluates constraint expressions on the trace domain (indexed rows).

mod composition;
mod degrees;
mod residuals;

pub use composition::{ComposeError, compose_linear, pad_to_len};
pub use degrees::{CONSTRAINT_FAMILY_COUNT, composition_degree_upper_bound};
pub use residuals::{ConstraintResiduals, constraint_residuals};
