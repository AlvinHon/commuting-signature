use criterion::{criterion_group, criterion_main, Criterion};

use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_std::{test_rng, UniformRand};
use commuting_signature::{Params, Signer};

type Fr = <E as Pairing>::ScalarField;

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_verify_ciphertexts,
    bench_sign_on_ciphertexts
);

criterion_main!(benches);

pub fn bench_sign(c: &mut Criterion) {
    let rng = &mut test_rng();

    let params = Params::<E>::rand(rng);
    let signer = Signer::rand(rng);
    let value = Fr::rand(rng);

    c.bench_function("sign", |b| {
        b.iter(|| {
            signer.sign(rng, &params, value);
        })
    });
}

pub fn bench_verify(c: &mut Criterion) {
    let rng = &mut test_rng();

    let params = Params::<E>::rand(rng);
    let signer = Signer::rand(rng);
    let verifier = signer.verifier(&params);
    let value = Fr::rand(rng);

    let (message, signature, _) = signer.sign(rng, &params, value);

    c.bench_function("verify", |b| {
        b.iter(|| {
            verifier.verify(&params, &message, &signature);
        })
    });
}

pub fn bench_verify_ciphertexts(c: &mut Criterion) {
    let rng = &mut test_rng();

    let params = Params::<E>::rand(rng);
    let signer = Signer::rand(rng);
    let verifier = signer.verifier(&params);
    let value = Fr::rand(rng);

    let (_, _, ciphertexts) = signer.sign(rng, &params, value);

    c.bench_function("verify_ciphertexts", |b| {
        b.iter(|| {
            verifier.verify_ciphertexts(&params, &ciphertexts);
        })
    });
}

pub fn bench_sign_on_ciphertexts(c: &mut Criterion) {
    let rng = &mut test_rng();

    let params = Params::<E>::rand(rng);
    let signer = Signer::rand(rng);
    let value = Fr::rand(rng);

    let (_, _, ciphertexts) = signer.sign(rng, &params, value);

    c.bench_function("sign_on_ciphertexts", |b| {
        b.iter(|| {
            signer.sign_on_ciphertexts(rng, &params, &ciphertexts);
        })
    });
}
