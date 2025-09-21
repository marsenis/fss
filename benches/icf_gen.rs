// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Yulong Ming (myl7)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fss_rs::group::Group;
use fss_rs::icf::{Icf, InG, IntvFn, OutG, CIPHER_N, IN_BLEN, OUT_BLEN};
use rand::prelude::*;

use fss_rs::prg::Aes128MatyasMeyerOseasPrg;

fn from_domain_range_size(c: &mut Criterion) {
    let mut keys = [[0; 16]; CIPHER_N];
    keys.iter_mut().for_each(|k| thread_rng().fill_bytes(k));
    let keys_iter = std::array::from_fn(|i| &keys[i]);

    let prg = Aes128MatyasMeyerOseasPrg::<OUT_BLEN, _, CIPHER_N>::new(&keys_iter);

    let p = InG::from(0);
    let q = InG::from((1u32 << 31) - 1);
    let icf = Icf::new(p, q, prg);

    let mut s0s = [[0; OUT_BLEN]; 2];
    s0s.iter_mut().for_each(|s0| thread_rng().fill_bytes(s0));

    let r_in = InG::zero();
    let r_out = OutG::zero();
    let f = IntvFn { r_in, r_out };

    let mut rng = rand::thread_rng();

    c.bench_with_input(
        BenchmarkId::new("icf gen", format!("{}b -> {}B", IN_BLEN * 8, OUT_BLEN)),
        &(),
        |b, &_| {
            b.iter(|| {
                let f = IntvFn { r_in, r_out };
                icf.gen(f, &mut rng);
            });
        },
    );
}

fn bench(c: &mut Criterion) {
    from_domain_range_size(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
