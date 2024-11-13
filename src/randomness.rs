//! Defines the [CommitRandomness] and [SigRandomness] structs, which represent the randomness used in the message and signature commitments.

use std::ops::Add;

use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};
use gs_ppe::Randomness;

/// (tau, mu, nu, rho, sigma), the randomness used in the message commitment.
#[derive(Copy, Clone, Debug)]
pub struct CommitRandomness<E: Pairing>(
    pub E::ScalarField,
    pub Randomness<<E as Pairing>::G1>,
    pub Randomness<<E as Pairing>::G2>,
    pub Randomness<<E as Pairing>::G1>,
    pub Randomness<<E as Pairing>::G2>,
);
impl<E: Pairing> CommitRandomness<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self(
            E::ScalarField::rand(rng),
            Randomness::rand(rng),
            Randomness::rand(rng),
            Randomness::rand(rng),
            Randomness::rand(rng),
        )
    }
}

impl<E: Pairing> Add for CommitRandomness<E> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(
            self.0 + other.0,
            self.1 + other.1,
            self.2 + other.2,
            self.3 + other.3,
            self.4 + other.4,
        )
    }
}

/// (alpha, beta, delta, rho, sigma), the randomness used in the signature commitment.
#[derive(Copy, Clone, Debug)]
pub struct SigRandomness<E: Pairing>(
    pub Randomness<<E as Pairing>::G1>,
    pub Randomness<<E as Pairing>::G1>,
    pub Randomness<<E as Pairing>::G2>,
    pub Randomness<<E as Pairing>::G1>,
    pub Randomness<<E as Pairing>::G2>,
);

impl<E: Pairing> SigRandomness<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self(
            Randomness::rand(rng),
            Randomness::rand(rng),
            Randomness::rand(rng),
            Randomness::rand(rng),
            Randomness::rand(rng),
        )
    }
}

impl<E: Pairing> Add for SigRandomness<E> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(
            self.0 + other.0,
            self.1 + other.1,
            self.2 + other.2,
            self.3 + other.3,
            self.4 + other.4,
        )
    }
}

/// (xi, psi), the randomness used in the key commitment.
#[derive(Copy, Clone, Debug)]
pub struct KeyRandomness<E: Pairing>(
    pub Randomness<<E as Pairing>::G1>,
    pub Randomness<<E as Pairing>::G2>,
);

impl<E: Pairing> KeyRandomness<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self(Randomness::rand(rng), Randomness::rand(rng))
    }
}

impl<E: Pairing> Add for KeyRandomness<E> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0, self.1 + other.1)
    }
}
