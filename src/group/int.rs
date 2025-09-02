// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Yulong Ming (myl7)

//! Integers as a group.
//!
//! - Associative operation: Integer wrapping addition, `$(a + b) \mod 2^N$`.
//! - Identity element: 0.
//! - Inverse element: `-x`.
//!
//! # Security
//!
//! Such a group whose cardinality is not a prime number cannot provide the attribute that: if `a` and `b` are individually indistinguishable with random elements, `a * b` (integer multiplication) is still that.
//! If you need this attribute (e.g., for some verification), use [`crate::group::int_prime`] instead.

use std::mem::size_of;
use std::ops::{Add, AddAssign, Neg};

use super::Group;

macro_rules! decl_int_group {
    ($t:ty, $t_impl:ident) => {
        /// See [`self`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $t_impl(pub $t);

        impl Add for $t_impl {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                $t_impl(self.0.wrapping_add(rhs.0))
            }
        }

        impl AddAssign for $t_impl {
            fn add_assign(&mut self, rhs: Self) {
                self.0 = self.0.wrapping_add(rhs.0);
            }
        }

        impl Neg for $t_impl {
            type Output = Self;

            fn neg(self) -> Self::Output {
                $t_impl(self.0.wrapping_neg())
            }
        }

        impl Group<{ size_of::<$t>() }> for $t_impl {
            fn zero() -> Self {
                $t_impl(0)
            }
        }

        impl $t_impl {
            /// Returns the maximum element `2^n - 1`.
            pub const fn max() -> Self {
                Self(<$t>::MAX)
            }

            /// Returns the canonical non-zero element of the group.
            /// Since this is an additive group, there is no predefined notion of multiplicative
            /// identity, so we provide it through this custom method for the integer groups,
            /// instead of as a method of the `Group` trait.
            pub const fn one() -> Self {
                Self(1)
            }
        }

        impl From<[u8; { size_of::<$t>() }]> for $t_impl {
            fn from(value: [u8; { size_of::<$t>() }]) -> Self {
                if cfg!(not(feature = "int-be")) {
                    $t_impl(<$t>::from_le_bytes(
                        (&value[..size_of::<$t>()]).clone().try_into().unwrap(),
                    ))
                } else {
                    $t_impl(<$t>::from_be_bytes(
                        (&value[..size_of::<$t>()]).clone().try_into().unwrap(),
                    ))
                }
            }
        }

        impl From<$t> for $t_impl {
            fn from(value: $t) -> Self {
                $t_impl(value)
            }
        }

        impl From<bool> for $t_impl {
            fn from(value: bool) -> Self {
                if value {
                    Self::one()
                } else {
                    const BLEN: usize = size_of::<$t>();
                    <Self as Group<BLEN>>::zero()
                }
            }
        }

        impl From<$t_impl> for [u8; { size_of::<$t>() }] {
            fn from(value: $t_impl) -> Self {
                let mut bs = [0; { size_of::<$t>() }];
                if cfg!(not(feature = "int-be")) {
                    bs[..size_of::<$t>()].copy_from_slice(&value.0.to_le_bytes());
                } else {
                    bs[..size_of::<$t>()].copy_from_slice(&value.0.to_be_bytes());
                }
                bs
            }
        }

        impl From<$t_impl> for $t {
            fn from(value: $t_impl) -> Self {
                value.0
            }
        }
    };
}

decl_int_group!(u8, U8Group);
decl_int_group!(u16, U16Group);
decl_int_group!(u32, U32Group);
decl_int_group!(u64, U64Group);
decl_int_group!(u128, U128Group);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_group_axioms;

    test_group_axioms!(test_u8_group_axioms, U8Group, 1);
    test_group_axioms!(test_u16_group_axioms, U16Group, 2);
    test_group_axioms!(test_u32_group_axioms, U32Group, 4);
    test_group_axioms!(test_u64_group_axioms, U64Group, 8);
    test_group_axioms!(test_u128_group_axioms, U128Group, 16);
}
