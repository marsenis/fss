// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Yulong Ming (myl7)

//! Many variable names and the LaTeX math expressions in the doc comment are from the paper _Function Secret Sharing for Mixed-Mode and Fixed-Point Secure Computation_.

#![cfg_attr(not(feature = "stable"), feature(portable_simd))]

use group::Group;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use anyhow::{bail, Result};

use crate::{group::byte::ByteGroup, icf::OutG};

pub mod dcf;
pub mod dpf;
pub mod group;
pub mod icf;
#[cfg(feature = "prg")]
pub mod prg;
pub mod utils;

/// Point function.
/// Despite the name, it only ships an element of the input domain and an element of the output domain.
/// The actual meaning of the 2 elements is determined by the context.
///
/// - `IN_BLEN` is the **byte** length of the size of the input domain.
///   `$n$` or `$\lceil \log_2 |\mathbb{G}^{in}| \rceil$` (but the byte length).
/// - `OUT_BLEN` is the **byte** length of the size of the output domain.
///   `$\lambda$` or `$\lceil \log_2 |\mathbb{G}^{out}| \rceil$` (but the byte length).
pub struct PointFn<const IN_BLEN: usize, const OUT_BLEN: usize, G>
where
    G: Group<OUT_BLEN>,
{
    /// `$\alpha$`, or say `x` in `y = f(x)`.
    pub alpha: [u8; IN_BLEN],
    /// `$\beta$`, or say `y` in `y = f(x)`.
    pub beta: G,
}

/// Pseudorandom generator (PRG).
///
/// Requires `Sync` for multi-threading.
/// We still require it for single-threading since it should be still easy to be included.
pub trait Prg<const BLEN: usize, const BLEN_N: usize>: Sync {
    fn gen(&self, seed: &[u8; BLEN]) -> [([[u8; BLEN]; BLEN_N], bool); 2];
}

/// `Cw`. Correclation word.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cw<const OUT_BLEN: usize, G>
where
    G: Group<OUT_BLEN>,
{
    #[serde_as(as = "serde_with::Bytes")]
    pub s: [u8; OUT_BLEN],
    pub v: G,
    pub tl: bool,
    pub tr: bool,
}

impl<const OUT_BLEN: usize, G> Cw<OUT_BLEN, G>
where
    G: Group<OUT_BLEN>,
{
    pub fn num_bits(&self) -> usize {
        OUT_BLEN * 8 + size_of::<G>() * 8 + 1 + 1
    }
}

/// `k`.
///
/// `cws` and `cw_np1` are shared by the 2 parties.
/// Only `s0s[0]` is different.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share<const OUT_BLEN: usize, G>
where
    G: Group<OUT_BLEN>,
{
    /// For the output of `gen`, its length is 2.
    /// For the input of `eval`, the first one is used.
    #[serde_as(as = "Vec<serde_with::Bytes>")]
    pub s0s: Vec<[u8; OUT_BLEN]>,
    /// The length of `cws` must be `n = 8 * N`.
    pub cws: Vec<Cw<OUT_BLEN, G>>,
    /// `$CW^{(n + 1)}$`.
    pub cw_np1: G,
}

impl<const OUT_BLEN: usize, G> Share<OUT_BLEN, G>
where
    G: Group<OUT_BLEN>,
{
    pub fn num_bits(&self) -> usize {
        self.s0s.len() * OUT_BLEN * 8
            + self.cws.iter().fold(0, |acc, cw| acc + cw.num_bits())
            + size_of::<G>() * 8
    }
}

impl Share<16, ByteGroup<16>> {
    /// Serialize the share into a vector of 32-bit words.
    pub fn serialize(&self) -> Result<Vec<u32>> {
        let bincode_config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&self, bincode_config)?;

        let mut out = Vec::with_capacity(1 + (bytes.len() + 3) / 4);

        // Append the length of the byte array.
        assert!(bytes.len() <= u32::max_value() as usize);
        let len = bytes.len() as u32;
        out.push(len);

        // Pad to multiple of 4 and pack into u32s (LE).
        let mut padded_bytes = bytes;
        while padded_bytes.len() % 4 != 0 {
            padded_bytes.push(0);
        }
        for chunk in padded_bytes.chunks_exact(4) {
            out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }

        Ok(out)
    }

    pub fn deserialize(data: &[u32]) -> Result<Self> {
        if data.is_empty() {
            bail!("missing length u32");
        }

        // Recover data length.
        let byte_len = data[0] as usize;

        let mut bytes = Vec::with_capacity(data.len().saturating_sub(1) * 4);

        for &w in &data[1..] {
            bytes.extend_from_slice(&w.to_le_bytes());
        }

        if bytes.len() < byte_len {
            bail!("payload shorter than declared length");
        }

        // If we need to remove more than 3 bytes of padding,
        // something went wrong during serialization.
        debug_assert!(bytes.len().saturating_sub(3) >= byte_len);

        // Drop padding.
        bytes.truncate(byte_len);

        let bincode_config = bincode::config::standard();
        let (share, _size) = bincode::serde::decode_from_slice(&bytes, bincode_config)?;

        Ok(share)
    }
}
