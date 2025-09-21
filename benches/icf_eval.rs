// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Yulong Ming (myl7)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fss_rs::icf::{Icf, InG, IntvFn, OutG, CIPHER_N, IN_BLEN, OUT_BLEN, OUT_BLEN_N};
use rand::prelude::*;

use fss_rs::group::byte::ByteGroup;
use fss_rs::group::Group;
use fss_rs::prg::Aes128MatyasMeyerOseasPrg;

fn from_domain_range_size(c: &mut Criterion) {
    let mut keys = [[0; 16]; CIPHER_N];
    keys.iter_mut().for_each(|k| thread_rng().fill_bytes(k));
    let keys_iter = std::array::from_fn(|i| &keys[i]);

    let prg = Aes128MatyasMeyerOseasPrg::<OUT_BLEN, OUT_BLEN_N, CIPHER_N>::new(&keys_iter);

    let p = InG::zero();
    let q = InG::from((1u32 << 31) - 1);
    let icf = Icf::new(p, q, prg);

    let mut s0s = [[0; OUT_BLEN]; 2];
    s0s.iter_mut().for_each(|s0| thread_rng().fill_bytes(s0));

    let r_in = InG::zero();
    let r_out = OutG::zero();
    let f = IntvFn { r_in, r_out };

    let mut rng = rand::thread_rng();

    let (k0, _) = icf.gen(f, &mut rng);

    let x = InG::from(2048);

    c.bench_with_input(
        BenchmarkId::new("icf eval", format!("{}b -> {}B", IN_BLEN * 8, OUT_BLEN)),
        &(),
        |b, &_| {
            b.iter(|| {
                icf.eval(false, &k0, x);
            });
        },
    );
}

fn bench(c: &mut Criterion) {
    from_domain_range_size(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
