use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{Proof, Variable};

use crate::{
    automorphic_signature::{Signature, VerifyingKey},
    equations, Commitment, Params, SigRandomness,
};

pub struct AdaptProof<E: Pairing> {
    pi_a: Proof<E>,
    pi_b: Proof<E>,
    pi_r: Proof<E>,
}

impl<E: Pairing> AdaptProof<E> {
    /// The function `AdPrC`, adapt proof when committing on a signature. Given a verifiably encrypted signature,
    /// produce a proof of validity for it and its associated verifiably encrypted message.
    pub fn when_commiting_signature<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        c: &Commitment<E>,
        sig: &Signature<E>,
        randomness: SigRandomness<E>,
        pi_a_bar: &Proof<E>,
    ) -> Result<Self, ()> {
        if !c.verify_proofs(pp) {
            return Err(());
        }

        let y = vk.1;
        let SigRandomness(alpha, beta, delta, rho, sigma) = randomness;

        // Verify the proof pi_a_bar where C contains a commitment to m s.t. E_a_bar.
        let eq_a_bar = equations::equation_a_bar(pp, y, sig.a, sig.d, sig.s);
        if !eq_a_bar.verify(&pp.cks, &[c.c_m], &[], pi_a_bar) {
            return Err(());
        }

        // Compute pi_a_tide.
        let var_a = Variable::with_randomness(sig.a, alpha);
        let var_d = Variable::with_randomness(sig.d, delta);
        let var_s = Variable::with_randomness(sig.s, sigma);
        let eq_a_tide = equations::equation_a_tide_from_lhs(pp, sig.s, sig.a, sig.d, y);
        let pi_a_tide = Proof::new(rng, &pp.cks, &eq_a_tide, &[var_a], &[var_s, var_d]);

        // Compute pi_b.
        let var_b = Variable::with_randomness(sig.b, beta);
        let eq_b = equations::equation_b(pp);
        let pi_b = Proof::new(rng, &pp.cks, &eq_b, &[var_b], &[var_d]);

        // Compute pi_r.
        let var_r = Variable::with_randomness(sig.r, rho);
        let eq_r = equations::equation_dh(pp);
        let pi_r = Proof::new(rng, &pp.cks, &eq_r, &[var_r], &[var_s]);

        Ok(Self {
            pi_a: pi_a_tide + pi_a_bar.clone(),
            pi_b,
            pi_r,
        })
    }
}
