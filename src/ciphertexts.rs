//! Defines the [Ciphertexts] struct representing verifiable encrypted message and signature.

use ark_ec::pairing::Pairing;

use crate::{commit::Commitment, proofs::Proofs, sigcom::SigCommitment};

/// Verifiable encrypted message and signature, represented by the commitments
/// to the message and signature, with proofs for the validity of the committed
/// message and signature.
#[derive(Clone, Debug)]
pub struct Ciphertexts<E: Pairing> {
    pub(crate) commitment: Commitment<E>,
    pub(crate) sig_commitment: SigCommitment<E>,
    pub(crate) proofs: Proofs<E>,
}
