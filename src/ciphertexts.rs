use ark_ec::pairing::Pairing;

use crate::{commit::Commitment, proofs::Proofs, sigcom::SigCommitment};

/// Contains the commitments to the message and signature, with proofs for the validity of the committed
/// message and signature.
pub struct Ciphertexts<E: Pairing> {
    pub(crate) commitment: Commitment<E>,
    pub(crate) sig_commitment: SigCommitment<E>,
    pub(crate) proofs: Proofs<E>,
}
