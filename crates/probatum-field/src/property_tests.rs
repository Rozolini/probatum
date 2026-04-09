//! Property-based algebraic checks.

use crate::Field;
use crate::MODULUS;
use proptest::prelude::*;

proptest! {
    #[test]
    fn add_associative(a in any::<u64>(), b in any::<u64>(), c in any::<u64>()) {
        let x = Field::new(a);
        let y = Field::new(b);
        let z = Field::new(c);
        prop_assert_eq!((x + y) + z, x + (y + z));
    }

    #[test]
    fn mul_associative(a in any::<u64>(), b in any::<u64>(), c in any::<u64>()) {
        let x = Field::new(a);
        let y = Field::new(b);
        let z = Field::new(c);
        prop_assert_eq!((x * y) * z, x * (y * z));
    }

    #[test]
    fn mul_inverse_nonzero(a in 1u64..MODULUS) {
        let x = Field::new(a);
        prop_assume!(!x.is_zero());
        let xi = x.inv().expect("invertible");
        prop_assert_eq!(x * xi, Field::ONE);
    }
}
