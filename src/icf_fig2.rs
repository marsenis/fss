use rand::{rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    dcf::{BoundState, CmpFn, Dcf, DcfImpl},
    group::Group,
    Prg, Share,
};

use eyre::{bail, Result};

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
// pub type OutG = crate::group::int::U128Group;
pub type OutG = crate::group::byte::ByteGroup<OUT_BLEN>;

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
pub struct IcShareFig2 {
    pub dcf_share0: Share<OUT_BLEN, OutG>,
    pub dcf_share1: Share<OUT_BLEN, OutG>,
    pub w: OutG,
}

impl IcShareFig2 {
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
        self.dcf_share0.num_bits() + self.dcf_share1.num_bits() + size_of::<OutG>() * 8
    }
}

/// An Interval Containment Function.
#[derive(Clone, Debug)]
pub struct IntvFnFig2 {
    pub r_in: InG,
    pub r_out: OutG,
}

/// An Interval Containment Function (ICF) FSS construct, generic on a pseudorandom generator of the
/// appropriate size.
pub struct IcfFig2<P>
where
    P: Prg<OUT_BLEN, 2>,
{
    p: InG,
    q: InG,
    dcf0: DcfImpl<IN_BLEN, OUT_BLEN, P>,
    dcf1: DcfImpl<IN_BLEN, OUT_BLEN, P>,
}

impl<P> IcfFig2<P>
where
    P: Prg<OUT_BLEN, 2>,
{
    pub fn new(p: InG, q: InG, prg0: P, prg1: P) -> Self {
        assert!(p <= q);
        Self {
            p,
            q,
            dcf0: DcfImpl::<IN_BLEN, OUT_BLEN, P>::new(prg0),
            dcf1: DcfImpl::<IN_BLEN, OUT_BLEN, P>::new(prg1),
        }
    }

    pub fn gen(&self, f: IntvFnFig2, rng: &mut ThreadRng) -> (IcShareFig2, IcShareFig2) {
        let s0s: [[u8; OUT_BLEN]; 4] = rng.gen();

        let alpha_p = f.r_in + self.p;
        let alpha_q = f.r_in + self.q;

        let cmp_fn0 = CmpFn {
            alpha: alpha_p.0.to_be_bytes(),
            beta: OutG::max(),
            bound: BoundState::LtAlpha,
        };

        let cmp_fn1 = CmpFn {
            alpha: alpha_q.0.to_be_bytes(),
            beta: OutG::one(),
            bound: BoundState::GtAlpha,
        };

        let keys_p = self.dcf0.gen(&cmp_fn0, [&s0s[0], &s0s[1]]);
        let keys_q = self.dcf1.gen(&cmp_fn1, [&s0s[2], &s0s[3]]);

        let (kp0, kp1) = split_keys(keys_p);
        let (kq0, kq1) = split_keys(keys_q);

        let w0 = OutG::from(rng.gen::<OutGPrimitive>());

        let ind = OutG::from(alpha_p > alpha_q);

        let w1 = -w0 + (f.r_out + ind);

        let k0 = IcShareFig2 {
            dcf_share0: kp0,
            dcf_share1: kq0,
            w: w0,
        };
        let k1 = IcShareFig2 {
            dcf_share0: kp1,
            dcf_share1: kq1,
            w: w1,
        };

        /*
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
        */

        debug_assert_eq!(
            IcShareFig2::deserialize(&k0.serialize().unwrap()).unwrap(),
            k0
        );
        debug_assert_eq!(
            IcShareFig2::deserialize(&k1.serialize().unwrap()).unwrap(),
            k1
        );

        (k0, k1)
    }

    pub fn eval(&self, b: bool, k: &IcShareFig2, x: InG) -> OutG {
        let out_zero = <OutG as Group<OUT_BLEN>>::zero();

        let mut t_b_p = out_zero;
        self.dcf0
            .eval(b, &k.dcf_share0, &[&x.clone().into()], &mut [&mut t_b_p]);

        let mut t_b_q = out_zero;
        self.dcf1
            .eval(b, &k.dcf_share1, &[&x.clone().into()], &mut [&mut t_b_q]);

        // t0 + t1 = (1 - x)
        // x = 1 - (t0 + t1)
        // x = (1 - t0) - t1
        t_b_q = if b { -t_b_q } else { OutG::one() + -t_b_q };

        // TODO: Invert DCF1.
        t_b_p + t_b_q + k.w
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
            let keys0: [[u8; OUT_BLEN]; CIPHER_N] = u.arbitrary()?;
            let prg0 = Aes128MatyasMeyerOseasPrg::<OUT_BLEN, OUT_BLEN_N, CIPHER_N>::new(
                &std::array::from_fn(|i| &keys0[i]),
            );
            let keys1: [[u8; OUT_BLEN]; CIPHER_N] = u.arbitrary()?;
            let prg1 = Aes128MatyasMeyerOseasPrg::<OUT_BLEN, OUT_BLEN_N, CIPHER_N>::new(
                &std::array::from_fn(|i| &keys1[i]),
            );
            //let a = u.arbitrary::<InGPrimitive>()?;
            //let b = u.arbitrary::<InGPrimitive>()?;
            //let p = InG::from(std::cmp::min(a, b));
            //let q = InG::from(std::cmp::max(a, b));
            let p = InG::from(0);
            let q = InG::from(1u32 << 31);

            let icf = IcfFig2::new(p, q, prg0, prg1);

            let r_in = InG::from(u.arbitrary::<u32>()? as u32);
            // let r_out = OutG::from(u.arbitrary::<OutGPrimitive>()?);
            let r_out = OutG::from(0);

            // println!("r_in = {r_in:?}, r_out = {r_out:?}");
            // f(x) = g(x - r_in) + r_out

            let f = IntvFnFig2 { r_in, r_out };

            let mut rng = rand::thread_rng();

            let (k0, k1) = icf.gen(f, &mut rng);

            // let x = InG::from(u.arbitrary::<InGPrimitive>()?);
            let x = InG::from((1u32 << 31) - 1) + r_in;

            let y0 = icf.eval(false, &k0, x);
            let y1 = icf.eval(true, &k1, x);

            let res = y0 + y1;

            println!("res = {res:?}, r_in = {r_in:?}");
            // assert!(res == r_out || res == OutG::one() + r_out);

            Ok(())
        });
    }
}
