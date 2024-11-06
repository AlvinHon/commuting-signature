use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};
use gs_ppe::Randomness;

/// (tau, mu, nu, rho, sigma)
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

/// (alpha, beta, delta, rho, sigma)
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
