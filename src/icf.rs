use rand::{rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    dcf::{BoundState, CmpFn, Dcf, DcfImpl},
    group::Group,
    Prg, Share,
};

use anyhow::{anyhow, bail, Result};

/// Work in `Z_{32}`, or 4 byte wide integers.
pub const NUM_BYTES: usize = 4;

/// The Integer Group structure for `Z_32`.
pub type IntG = crate::group::int::U32Group;

/// The Rust-equivalent primitive type for `IntG`
type IntGPrimitive = u32;

pub fn split_keys<const OUT_BLEN: usize, G>(
    keys: Share<OUT_BLEN, G>,
) -> (Share<OUT_BLEN, G>, Share<OUT_BLEN, G>)
where
    G: Group<OUT_BLEN>,
{
    let mut k0 = keys.clone();
    k0.s0s.remove(1);

    let mut k1 = keys.clone();
    k1.s0s.remove(0);

    (k0, k1)
}

/// A key-share for the Interval Containment Function.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcShare {
    pub dcf_share: Share<NUM_BYTES, IntG>,
    pub z: IntG,
}

impl IcShare {
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

/// An Interval Containment Function.
#[derive(Clone, Debug)]
pub struct IntvFn {
    pub r_in: IntG,
    pub r_out: IntG,
}

/// An Interval Containment Function (ICF) FSS construct, generic on a pseudorandom generator of the
/// appropriate size.
pub struct Icf<P>
where
    P: Prg<NUM_BYTES, 2>,
{
    p: IntG,
    q: IntG,
    dcf: DcfImpl<NUM_BYTES, NUM_BYTES, P>,
}

impl<P> Icf<P>
where
    P: Prg<NUM_BYTES, 2>,
{
    pub fn new(p: IntG, q: IntG, prg: P) -> Self {
        Self {
            p,
            q,
            dcf: DcfImpl::<NUM_BYTES, NUM_BYTES, P>::new(prg),
        }
    }

    pub fn gen(&self, f: IntvFn, rng: &mut ThreadRng) -> (IcShare, IcShare) {
        let s0s: [[u8; NUM_BYTES]; 2] = rng.gen();

        let gamma = f.r_in + IntG::max();

        let cmp_fn = CmpFn {
            alpha: gamma.into(),
            beta: IntG::one(),
            bound: BoundState::LtAlpha,
        };

        let keys = self.dcf.gen(&cmp_fn, [&s0s[0], &s0s[1]]);

        let (k0, k1) = split_keys(keys);

        let q_prime = self.q + IntG::one();
        let a_p = self.p + f.r_in;
        let a_q = self.q + f.r_in;
        let a_q_prime = a_q + IntG::one();

        let z0 = IntG::from(rng.gen::<IntGPrimitive>());

        // TODO: Implement comparison for group elements.
        let ind_1 = IntG::from(a_p > a_q);
        let ind_2 = IntG::from(a_p > self.p);
        let ind_3 = IntG::from(a_q_prime > q_prime);
        let ind_4 = IntG::from(a_q == IntG::max());

        let z1 = z0 + -(f.r_out + ind_1 + -ind_2 + ind_3 + ind_4);

        let k0 = IcShare {
            dcf_share: k0,
            z: z0,
        };
        let k1 = IcShare {
            dcf_share: k1,
            z: z1,
        };

        (k0, k1)
    }

    pub fn eval(&self, b: bool, k: &IcShare, x: IntG) -> IntG {
        let q_prime = self.q + IntG::one();

        let zero = <IntG as Group<NUM_BYTES>>::zero();

        let x_p = x + IntG::max() + -self.p;
        let mut s_b_p = zero;
        self.dcf
            .eval(b, &k.dcf_share, &[&x_p.into()], &mut [&mut s_b_p]);

        let x_q_prime = x + IntG::max() + -q_prime;
        let mut s_b_q_prime = zero;
        self.dcf.eval(
            b,
            &k.dcf_share,
            &[&x_q_prime.into()],
            &mut [&mut s_b_q_prime],
        );

        let ind_1 = IntG::from(x > self.p);
        let ind_2 = IntG::from(x > q_prime);

        (if b { ind_1 + -ind_2 } else { zero }) + -s_b_p + s_b_q_prime + k.z
    }
}
