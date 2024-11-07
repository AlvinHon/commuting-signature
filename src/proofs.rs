use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{Proof, Variable};

use crate::{
    automorphic_signature::{Signature, VerifyingKey},
    equations, CommitRandomness, Commitment, Message, Params, SigCommitment, SigRandomness,
};

/// (pi_*, pi_b, pi_r)
pub struct Proofs<E: Pairing>(pub Proof<E>, pub Proof<E>, pub Proof<E>);

#[derive(Clone, Debug)]
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
        let y = vk.1;
        let SigRandomness(alpha, beta, delta, rho, sigma) = randomness;

        // Verify the proof pi_a_bar that C contains a commitment to m s.t. E_a_bar.
        let eq_a_bar = equations::equation_a_bar_from_rhs(pp, y, sig.a, sig.d, sig.s);
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

    /// The function `AdPrC_M`, adapt proof when committing on a message. Given a verifiably encrypted signature,
    /// produce a proof of validity for it and its associated verifiably encrypted signature.
    pub fn when_commiting_message<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        mn: &Message<E>,
        randomness: CommitRandomness<E>,
        sig_com: &SigCommitment<E>,
        pi_tide: &Proofs<E>,
    ) -> Result<Self, ()> {
        let Proofs(pi_a_tide, pi_b, pi_r) = pi_tide;
        let CommitRandomness(_, mu, _, _, _) = randomness;

        // Verify the proof pi_a_tide that sig_com contains a commitment to sig s.t. E_a_tide.
        let eq_a_tide = equations::equation_a_tide_from_rhs(pp, vk.1, mn.0);
        if eq_a_tide.verify(&pp.cks, &[sig_com.c_a], &[], &pi_a_tide) {
            return Err(());
        }

        let eq_a_bar = equations::equation_a_bar_from_lhs(pp, mn.0);
        let var_m = Variable::with_randomness(mn.0, mu);
        let pi_a_bar = Proof::new(rng, &pp.cks, &eq_a_bar, &[var_m], &[]);

        Ok(Self {
            pi_a: pi_a_tide.clone() + pi_a_bar,
            pi_b: pi_b.clone(),
            pi_r: pi_r.clone(),
        })
    }
}

impl<E: Pairing> From<AdaptProof<E>> for Proofs<E> {
    fn from(adapt_proof: AdaptProof<E>) -> Self {
        Proofs(adapt_proof.pi_a, adapt_proof.pi_b, adapt_proof.pi_r)
    }
}
