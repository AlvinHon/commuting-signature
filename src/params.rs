use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::CommitmentKeys;

use crate::automorphic_signature;

pub struct Params<E: Pairing> {
    pub(crate) pps: automorphic_signature::Params<E>,
    pub(crate) cks: CommitmentKeys<E>,
}

impl<E: Pairing> Params<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let pps = automorphic_signature::Params::rand(rng);
        let cks = CommitmentKeys::rand(rng);
        Self { pps, cks }
    }
}
