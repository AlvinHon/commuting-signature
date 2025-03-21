//! Defines the [Params] struct representing the public parameters for the commuting signature scheme.

use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{CommitmentKeys, ExtractKey};

use crate::automorphic_signature;

/// The parameters for the commuting signature scheme. It consists of the parameters for the automorphic
/// signature scheme and the commitment keys from the GS Proof System.
#[derive(Clone, Debug)]
pub struct Params<E: Pairing> {
    pub(crate) pps: automorphic_signature::Params<E>,
    pub(crate) cks: CommitmentKeys<E>,
    pub(crate) ek: Option<ExtractKey<E>>,
}

impl<E: Pairing> Params<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let pps = automorphic_signature::Params::rand(rng);
        let cks = CommitmentKeys::rand(rng);
        Self { pps, cks, ek: None }
    }

    pub fn rand_ex<R: Rng>(rng: &mut R) -> Self {
        let pps = automorphic_signature::Params::rand(rng);
        let (cks, ek) = CommitmentKeys::rand_ex(rng);
        Self {
            pps,
            cks,
            ek: Some(ek),
        }
    }
}
