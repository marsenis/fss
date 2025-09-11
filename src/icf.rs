use rand::{rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    dcf::{BoundState, CmpFn, Dcf, DcfImpl},
    group::Group,
    Prg, Share,
};

use anyhow::{anyhow, bail, Result};

/// Input domain is `U_{2^32} ~= Z_{2^32}`, or 4 byte wide integers.
pub const IN_BLEN: usize = 4;

/// Security constant in bits.
pub const LAMBDA: usize = 128;
/// Security constant in bytes. Matching the name used in the [crate::dcf] module.
pub const OUT_BLEN: usize = LAMBDA / 8;

/// These are needed only for cipher construction.
const OUT_BLEN_N: usize = 2;
const CIPHER_N: usize = (OUT_BLEN / 16) * OUT_BLEN_N * 2;

/// The integer Group structure of the output (the image set of the secret-shared function).
/// Standard choices include `Z_{2^128}` ([crate::group::int::U128Group]), or `(Z_2)^128`
/// ([crate::group::byte::ByteGroup]).
pub type OutG = crate::group::int::U128Group;
// pub type OutG = crate::group::byte::ByteGroup<OUT_BLEN>;

/// The integer Group structure of the input (the domain of the secret-shared function).
pub type InG = crate::group::int::U32Group;

/// The Rust-equivalent integer primitive types for [InG] and [OutG].
type InGPrimitive = u32;
type OutGPrimitive = u128;

/// Splits a single DCF key into the two keys `k0` and `k1` to be sent to each party.
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
    pub dcf_share: Share<OUT_BLEN, OutG>,
    pub z: OutG,
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

    /// Returns the number of bits stored in this struct.
    pub fn num_bits(&self) -> usize {
        self.dcf_share.num_bits() + size_of::<OutG>() * 8
    }
}

/// An Interval Containment Function.
#[derive(Clone, Debug)]
pub struct IntvFn {
    pub r_in: InG,
    pub r_out: OutG,
}

/// An Interval Containment Function (ICF) FSS construct, generic on a pseudorandom generator of the
/// appropriate size.
pub struct Icf<P>
where
    P: Prg<OUT_BLEN, 2>,
{
    p: InG,
    q: InG,
    dcf: DcfImpl<IN_BLEN, OUT_BLEN, P>,
}

impl<P> Icf<P>
where
    P: Prg<OUT_BLEN, 2>,
{
    pub fn new(p: InG, q: InG, prg: P) -> Self {
        assert!(p <= q);
        Self {
            p,
            q,
            dcf: DcfImpl::<IN_BLEN, OUT_BLEN, P>::new(prg),
        }
    }

    pub fn gen(&self, f: IntvFn, rng: &mut ThreadRng) -> (IcShare, IcShare) {
        let s0s: [[u8; OUT_BLEN]; 2] = rng.gen();

        let gamma = f.r_in + InG::max();

        let cmp_fn = CmpFn {
            alpha: gamma.into(),
            beta: OutG::one(),
            bound: BoundState::LtAlpha,
        };

        let keys = self.dcf.gen(&cmp_fn, [&s0s[0], &s0s[1]]);

        let (k0, k1) = split_keys(keys);

        let q_prime = self.q + InG::one();
        let a_p = self.p + f.r_in;
        let a_q = self.q + f.r_in;
        let a_q_prime = a_q + InG::one();

        let z0 = OutG::from(rng.gen::<OutGPrimitive>());

        let ind_1 = OutG::from(a_p > a_q);
        let ind_2 = OutG::from(a_p > self.p);
        let ind_3 = OutG::from(a_q_prime > q_prime);
        let ind_4 = OutG::from(a_q == InG::max());

        let z1 = -z0 + (f.r_out + ind_1 + -ind_2 + ind_3 + ind_4);

        let k0 = IcShare {
            dcf_share: k0,
            z: z0,
        };
        let k1 = IcShare {
            dcf_share: k1,
            z: z1,
        };

        println!("k0.num_bits() = {}", k0.num_bits());
        println!("k1.num_bits() = {}", k1.num_bits());

        println!(
            "num_bits(serde(k0)) = {}",
            k0.serialize().unwrap().len() * 32
        );
        println!(
            "num_bits(serde(k1)) = {}",
            k1.serialize().unwrap().len() * 32
        );

        debug_assert_eq!(IcShare::deserialize(&k0.serialize().unwrap()).unwrap(), k0);
        debug_assert_eq!(IcShare::deserialize(&k1.serialize().unwrap()).unwrap(), k1);

        (k0, k1)
    }

    pub fn eval(&self, b: bool, k: &IcShare, x: InG) -> OutG {
        let q_prime = self.q + InG::one();

        let out_zero = <OutG as Group<OUT_BLEN>>::zero();

        let x_p = x + InG::max() + -self.p;
        let mut s_b_p = out_zero;
        self.dcf
            .eval(b, &k.dcf_share, &[&x_p.into()], &mut [&mut s_b_p]);

        let x_q_prime = x + InG::max() + -q_prime;
        let mut s_b_q_prime = out_zero;
        self.dcf.eval(
            b,
            &k.dcf_share,
            &[&x_q_prime.into()],
            &mut [&mut s_b_q_prime],
        );

        let ind_1 = OutG::from(x > self.p);
        let ind_2 = OutG::from(x > q_prime);

        (if b { ind_1 + -ind_2 } else { out_zero }) + -s_b_p + s_b_q_prime + k.z
    }
}

#[cfg(all(test, feature = "prg"))]
mod tests {
    use arbtest::arbtest;

    use super::*;
    use crate::prg::Aes128MatyasMeyerOseasPrg;

    #[test]
    fn test_correctness() {
        arbtest(|u| {
            let keys: [[u8; OUT_BLEN]; CIPHER_N] = u.arbitrary()?;
            let prg = Aes128MatyasMeyerOseasPrg::<OUT_BLEN, OUT_BLEN_N, CIPHER_N>::new(
                &std::array::from_fn(|i| &keys[i]),
            );
            let a = u.arbitrary::<InGPrimitive>()?;
            let b = u.arbitrary::<InGPrimitive>()?;
            let p = InG::from(std::cmp::min(a, b));
            let q = InG::from(std::cmp::max(a, b));

            let icf = Icf::new(p, q, prg);

            let r_in = InG::from(u.arbitrary::<InGPrimitive>()?);
            let r_out = OutG::from(u.arbitrary::<OutGPrimitive>()?);

            println!("r_in = {r_in:?}, r_out = {r_out:?}");

            let f = IntvFn { r_in, r_out };

            let mut rng = rand::thread_rng();

            let (k0, k1) = icf.gen(f, &mut rng);

            let x = InG::from(u.arbitrary::<InGPrimitive>()?);

            let y0 = icf.eval(false, &k0, x);
            let y1 = icf.eval(true, &k1, x);

            let res = y0 + y1;

            println!("res = {res:?}, r_out = {r_out:?}");
            assert!(res == r_out || res == OutG::one() + r_out);

            Ok(())
        });
    }
}
