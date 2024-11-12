//! Defines the `Verifier` struct and its methods.
//!
use ark_ec::pairing::Pairing;

use crate::{
    automorphic_signature::{Signature, VerifyingKey},
    ciphertexts::Ciphertexts,
    Message, Params,
};

/// Provides the functionality to verify a message, signature and ciphertexts.
pub struct Verifier<E: Pairing> {
    pub(crate) vk: VerifyingKey<E>,
}

impl<E: Pairing> Verifier<E> {
    /// Verify a message with a signature.
    ///
    /// ## Example
    ///
    /// ```
    /// use ark_bls12_381::Bls12_381 as E;
    /// use ark_ec::pairing::Pairing;
    /// use ark_std::{test_rng, UniformRand};
    /// use commuting_signature::{Params, Signer};
    ///
    /// type Fr = <E as Pairing>::ScalarField;
    ///
    /// let rng = &mut test_rng();
    /// let params = Params::<E>::rand(rng);
    /// let signer = Signer::rand(rng);
    /// let verifier = signer.verifier(&params);
    ///
    /// let value = Fr::rand(rng);
    ///
    /// let (message, signature, _) = signer.sign(rng, &params, value);
    ///
    /// assert!(verifier.verify(&params, &message, &signature));
    /// ```
    pub fn verify(&self, pp: &Params<E>, message: &Message<E>, signature: &Signature<E>) -> bool {
        self.vk.verify(&pp.pps, message, signature)
    }

    /// Verify an encrypted message/signature pair that the commitments in the ciphertexts are
    /// committing to a valid message/signature pair.
    ///
    /// ## Example
    ///
    /// ```
    /// use ark_bls12_381::Bls12_381 as E;
    /// use ark_ec::pairing::Pairing;
    /// use ark_std::{test_rng, UniformRand};
    /// use commuting_signature::{Params, Signer};
    ///
    /// type Fr = <E as Pairing>::ScalarField;
    ///
    /// let rng = &mut test_rng();
    /// let params = Params::<E>::rand(rng);
    /// let signer = Signer::rand(rng);
    /// let verifier = signer.verifier(&params);
    ///
    /// let value = Fr::rand(rng);
    ///
    /// let (message, signature, ciphertexts) = signer.sign(rng, &params, value);
    ///
    /// assert!(verifier.verify_ciphertexts(&params, &ciphertexts));
    /// ```
    pub fn verify_ciphertexts(&self, pp: &Params<E>, ciphertexts: &Ciphertexts<E>) -> bool {
        let is_commitment_valid = ciphertexts.commitment.verify_proofs(pp);
        let is_sig_commitment_valid = ciphertexts.sig_commitment.verify_proofs(
            pp,
            &self.vk,
            &ciphertexts.commitment,
            &ciphertexts.proofs,
        );
        is_commitment_valid && is_sig_commitment_valid
    }
}
