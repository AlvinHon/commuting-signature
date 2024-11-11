use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

use crate::{
    automorphic_signature::{Signature, SigningKey},
    ciphertexts::Ciphertexts,
    commit::Commitment,
    randomness::CommitRandomness,
    sigcom::sig_com,
    Message, Params, Verifier,
};

/// Provides the functionality to sign a value and output a message with signature with their encrypted
/// ciphertexts.
pub struct Signer<E: Pairing> {
    pub(crate) sk: SigningKey<E>,
}

impl<E: Pairing> Signer<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            sk: SigningKey::rand(rng),
        }
    }

    /// Create a new Verifier instance.
    pub fn verifier(&self, pp: &Params<E>) -> Verifier<E> {
        Verifier {
            vk: self.sk.verifying_key(&pp.pps),
        }
    }

    /// Sign a value and outputs a message with signature with their encrypted ciphertexts. The ciphertexts
    /// contain commitments to the message and signature, with a proof for the validity of the committed
    /// message and signature.
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
    /// assert!(verifier.verify(&params, &message, &signature));
    /// assert!(verifier.verify_ciphertexts(&params, &ciphertexts));
    /// ```
    pub fn sign<R: Rng>(
        &self,
        rng: &mut R,
        pp: &Params<E>,
        m: E::ScalarField,
    ) -> (Message<E>, Signature<E>, Ciphertexts<E>) {
        let mn = Message::new(&pp.pps, m);
        let com_randomness = CommitRandomness::rand(rng);

        // Com_M
        let com_m = Commitment::new(rng, pp, &mn, com_randomness);

        // SigCom
        let (sig_com, proofs, pre_sig) = sig_com(rng, pp, &self.sk, &com_m).unwrap();

        let precom_sig = pre_sig.to_precommit_signature(pp, com_randomness);

        (
            mn,
            precom_sig.signature,
            Ciphertexts {
                commitment: com_m,
                sig_commitment: sig_com,
                proofs,
            },
        )
    }

    /// Create a verifiable encrypted signature on the encrypted message.
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
    ///
    /// let value = Fr::rand(rng);
    /// let (_, _, ciphertexts) = signer.sign(rng, &params, value);
    ///
    ///
    /// let signer2 = Signer::rand(rng);
    /// let verifier2 = signer2.verifier(&params);
    /// let ciphertexts2 = signer2.sign_on_ciphertexts(rng, &params, &ciphertexts);
    ///
    /// assert!(verifier2.verify_ciphertexts(&params, &ciphertexts2));
    /// ```
    pub fn sign_on_ciphertexts<R: Rng>(
        &self,
        rng: &mut R,
        pp: &Params<E>,
        ciphertexts: &Ciphertexts<E>,
    ) -> Ciphertexts<E> {
        let commitment = ciphertexts.commitment.clone();
        let (sig_commitment, proofs, _) = sig_com(rng, pp, &self.sk, &commitment).unwrap();

        Ciphertexts {
            commitment,
            sig_commitment,
            proofs,
        }
    }
}
