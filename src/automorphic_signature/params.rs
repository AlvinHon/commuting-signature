//! Defines the public parameters structs [Params] and [ParamsEx] for the automorphic signatures.

use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};

/// The public parameters for the automorphic signatures, Scheme 1.
#[derive(Clone, Debug)]
pub struct Params<E: Pairing> {
    pub g: <E as Pairing>::G1,
    pub h: <E as Pairing>::G2,

    // additional generators
    pub f: <E as Pairing>::G1,
    pub k: <E as Pairing>::G1,
    pub t: <E as Pairing>::G1,
}

impl<E: Pairing> Params<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            g: <E as Pairing>::G1::rand(rng),
            h: <E as Pairing>::G2::rand(rng),
            f: <E as Pairing>::G1::rand(rng),
            k: <E as Pairing>::G1::rand(rng),
            t: <E as Pairing>::G1::rand(rng),
        }
    }
}

/// The public parameters for the automorphic signatures, Scheme 2.
pub struct ParamsEx<E: Pairing> {
    pub g: <E as Pairing>::G1,
    pub h: <E as Pairing>::G2,

    // additional generators
    pub f: <E as Pairing>::G1,
    pub k: <E as Pairing>::G1,
    pub l: <E as Pairing>::G1,
    pub t: <E as Pairing>::G1,
}

impl<E: Pairing> ParamsEx<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            g: <E as Pairing>::G1::rand(rng),
            h: <E as Pairing>::G2::rand(rng),
            f: <E as Pairing>::G1::rand(rng),
            k: <E as Pairing>::G1::rand(rng),
            l: <E as Pairing>::G1::rand(rng),
            t: <E as Pairing>::G1::rand(rng),
        }
    }
}

/// Implements the trait to get the generators `g` and `h`
/// for automorphic signature algorithm. The public parameters
/// ([Params] or [ParamsEx]) implement this trait.
pub trait DHGenerators<E: Pairing> {
    fn g(&self) -> <E as Pairing>::G1;
    fn h(&self) -> <E as Pairing>::G2;
}

impl<E: Pairing> DHGenerators<E> for Params<E> {
    fn g(&self) -> <E as Pairing>::G1 {
        self.g
    }

    fn h(&self) -> <E as Pairing>::G2 {
        self.h
    }
}

impl<E: Pairing> DHGenerators<E> for ParamsEx<E> {
    fn g(&self) -> <E as Pairing>::G1 {
        self.g
    }

    fn h(&self) -> <E as Pairing>::G2 {
        self.h
    }
}
