// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Yulong Ming (myl7)

//! Byte vectors as a group.
//!
//! - Associative operation: XOR.
//! - Identity element: All bits zero.
//! - Inverse element: `x` itself.

use std::ops::{Add, AddAssign, Neg};

use serde::{Deserialize, Serialize};

use super::Group;
use crate::utils::xor_inplace;

/// See [`self`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ByteGroup<const BLEN: usize>(#[serde(with = "serde_byte_array")] pub [u8; BLEN]);

impl<const BLEN: usize> Add for ByteGroup<BLEN> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        xor_inplace(&mut self.0, &[&rhs.0]);
        self
    }
}

impl<const BLEN: usize> AddAssign for ByteGroup<BLEN> {
    fn add_assign(&mut self, rhs: Self) {
        xor_inplace(&mut self.0, &[&rhs.0])
    }
}

impl<const BLEN: usize> Neg for ByteGroup<BLEN> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl<const BLEN: usize> Group<BLEN> for ByteGroup<BLEN> {
    fn zero() -> Self {
        ByteGroup([0; BLEN])
    }
}

impl<const BLEN: usize> From<[u8; BLEN]> for ByteGroup<BLEN> {
    fn from(value: [u8; BLEN]) -> Self {
        Self(value)
    }
}

impl<const BLEN: usize> From<ByteGroup<BLEN>> for [u8; BLEN] {
    fn from(value: ByteGroup<BLEN>) -> Self {
        value.0
    }
}

impl From<bool> for ByteGroup<16> {
    fn from(value: bool) -> Self {
        if value {
            Self::one()
        } else {
            Self::zero()
        }
    }
}

impl From<u128> for ByteGroup<16> {
    fn from(value: u128) -> Self {
        let mut bytes = [0_u8; 16];
        let mask: u128 = (1_u128 << 8) - 1;

        for i in 0..16 {
            bytes[i] = ((value & (mask << (i * 8))) >> (i * 8)) as u8;
        }

        Self::from(bytes)
    }
}

impl ByteGroup<16> {
    /// Returns the maximum element `2^n - 1`.
    pub const fn max() -> Self {
        Self([u8::max_value(); 16])
    }

    /// Returns the canonical non-zero element of the group.
    /// Since this is an additive group, there is no predefined notion of multiplicative
    /// identity, so we provide it through this custom method for the integer groups,
    /// instead of as a method of the `Group` trait.
    pub const fn one() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_group_axioms;

    test_group_axioms!(test_group_axioms, ByteGroup<16>, 16);
}
