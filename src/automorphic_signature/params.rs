//! Defines the public parameters structs [Params] and [ParamsEx] for the automorphic signatures.

use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};

/// The public parameters for the automorphic signatures, Scheme 1.
#[derive(Clone, Debug)]
pub struct Params<E: Pairing> {
    pub g: <E as Pairing>::G1Affine,
    pub h: <E as Pairing>::G2Affine,

    // additional generators
    pub f: <E as Pairing>::G1Affine,
    pub k: <E as Pairing>::G1Affine,
    pub t: <E as Pairing>::G1Affine,
}

impl<E: Pairing> Params<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            g: <E as Pairing>::G1Affine::rand(rng),
            h: <E as Pairing>::G2Affine::rand(rng),
            f: <E as Pairing>::G1Affine::rand(rng),
            k: <E as Pairing>::G1Affine::rand(rng),
            t: <E as Pairing>::G1Affine::rand(rng),
        }
    }
}

/// The public parameters for the automorphic signatures, Scheme 2.
pub struct ParamsEx<E: Pairing> {
    pub g: <E as Pairing>::G1Affine,
    pub h: <E as Pairing>::G2Affine,

    // additional generators
    pub f: <E as Pairing>::G1Affine,
    pub k: <E as Pairing>::G1Affine,
    pub l: <E as Pairing>::G1Affine,
    pub t: <E as Pairing>::G1Affine,
}

impl<E: Pairing> ParamsEx<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            g: <E as Pairing>::G1Affine::rand(rng),
            h: <E as Pairing>::G2Affine::rand(rng),
            f: <E as Pairing>::G1Affine::rand(rng),
            k: <E as Pairing>::G1Affine::rand(rng),
            l: <E as Pairing>::G1Affine::rand(rng),
            t: <E as Pairing>::G1Affine::rand(rng),
        }
    }
}

/// Implements the trait to get the generators `g` and `h`
/// for automorphic signature algorithm. The public parameters
/// ([Params] or [ParamsEx]) implement this trait.
pub trait DHGenerators<E: Pairing> {
    fn g(&self) -> <E as Pairing>::G1Affine;
    fn h(&self) -> <E as Pairing>::G2Affine;
}

impl<E: Pairing> DHGenerators<E> for Params<E> {
    fn g(&self) -> <E as Pairing>::G1Affine {
        self.g
    }

    fn h(&self) -> <E as Pairing>::G2Affine {
        self.h
    }
}

impl<E: Pairing> DHGenerators<E> for ParamsEx<E> {
    fn g(&self) -> <E as Pairing>::G1Affine {
        self.g
    }

    fn h(&self) -> <E as Pairing>::G2Affine {
        self.h
    }
}
