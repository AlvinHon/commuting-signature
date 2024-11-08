use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{Proof, Variable};

use crate::{
    automorphic_signature::VerifyingKey, equations, sigcom::CommittedSignature, CommitRandomness,
    Commitment, Message, Params, SigCommitment, SigRandomness,
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
    /// The function `AdPrC`, adapt proof when committing on a signature.
    /// Given a message/signature pair of which one is verifiably encrypted,
    /// produce a proof that it and its associated message are verifiably encrypted.
    pub fn committing_signature<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        c: &Commitment<E>,
        // ((A, B, D, R, S), (alpha, beta, delta, rho, sigma))
        committed_sig: &CommittedSignature<E>,
        pi_a_bar: &Proof<E>,
    ) -> Option<Self> {
        let y = vk.1;
        let CommittedSignature { sig, randomness } = committed_sig;
        let SigRandomness(alpha, beta, delta, rho, sigma) = *randomness;

        // Verify the proof pi_a_bar that C contains a commitment to m s.t. E_a_bar.
        // i.e. Verify(ck, E_Ver(vk,.,Σ), C, pi_a_bar) = 1
        let eq_a_bar = equations::equation_a_bar_from_rhs(pp, y, sig.a, sig.d, sig.s);
        if !eq_a_bar.verify(&pp.cks, &[c.c_m], &[], pi_a_bar) {
            return None;
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

        Some(Self {
            pi_a: pi_a_tide + pi_a_bar.clone(),
            pi_b,
            pi_r,
        })
    }

    /// The function `AdPrC_M`, adapt proof when committing on a message.
    /// Given a message/signature pair of which one is verifiably encrypted,
    /// produce a proof that it and its associated signature are verifiably encrypted.
    pub fn committing_message<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        mn: &Message<E>,
        randomness: CommitRandomness<E>,
        sig_com: &SigCommitment<E>,
        pi_tide: &Proofs<E>,
    ) -> Option<Self> {
        let Proofs(pi_a_tide, pi_b, pi_r) = pi_tide;
        let CommitRandomness(_, mu, _, _, _) = randomness;

        // Verify the proof pi_a_tide that sig_com contains a commitment to sig s.t. E_a_tide.
        // i.e. Verify(ck, E_Ver(vk,M,.), C_Σ, pi_tide) = 1
        let eq_a_tide = equations::equation_a_tide_from_rhs(pp, vk.1, mn.0);
        if eq_a_tide.verify(&pp.cks, &[sig_com.c_a], &[], pi_a_tide) {
            return None;
        }

        let eq_a_bar = equations::equation_a_bar_from_lhs(pp, mn.0);
        let var_m = Variable::with_randomness(mn.0, mu);
        let pi_a_bar = Proof::new(rng, &pp.cks, &eq_a_bar, &[var_m], &[]);

        Some(Self {
            pi_a: pi_a_tide.clone() + pi_a_bar,
            pi_b: pi_b.clone(),
            pi_r: pi_r.clone(),
        })
    }

    /// The function `AdPrDC`, adapt proof when decommitting on a signature.
    /// Given a verifiably encrypted message/signature pair,
    /// produce an adapted proof (`pi_a_bar` in `AdPrC`) that a signature is valid on a committed message.
    pub fn decommitting_signature<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        c: &Commitment<E>,
        // ((A, B, D, R, S), (alpha, beta, delta, rho, sigma))
        committed_sig: &CommittedSignature<E>,
        pi: &Proofs<E>,
    ) -> Option<Proof<E>> {
        let CommittedSignature { sig, randomness } = committed_sig;
        // Verify the proof pi that C contains a commitment to message s.t. E_a, E_b and E_r.
        // i.e. Verify(ck, E_Ver(vk,.,.), C, Com(ck, Σ, rho), pi) = 1
        if !committed_sig
            .as_sigcommitment(pp)
            .verify_proofs(pp, vk, c, pi)
        {
            return None;
        }

        let y = vk.1;
        let SigRandomness(alpha, _, delta, _, sigma) = *randomness;
        let Proofs(pi_a, _, _) = pi;

        let var_a = Variable::with_randomness(sig.a, alpha);
        let var_d = Variable::with_randomness(sig.d, delta);
        let var_s = Variable::with_randomness(sig.s, sigma);
        let eq_a_tide = equations::equation_a_tide_from_lhs(pp, sig.s, sig.a, sig.d, y);
        let pi_a_tide = Proof::new(rng, &pp.cks, &eq_a_tide, &[var_a], &[var_s, var_d]);

        Some(pi_a.clone() / pi_a_tide)
    }
    /// The function `AdPrDC_M`, adapt proof when decommitting on a message.
    /// Given a verifiably encrypted message/signature pair,
    /// produce an adapted proof (`pi_tide` in `AdPrC_M`) that a committed signature is valid on a given message.
    pub fn decommitting_message<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        mn: &Message<E>,
        randomness: CommitRandomness<E>,
        sig_com: &SigCommitment<E>,
        pi: &Proofs<E>,
    ) -> Option<Self> {
        let c = Commitment::new(rng, pp, mn, randomness);
        // i.e. Verify(ck, E_Ver(vk,.,.), Com_M(ck, M, mu), C_Σ, pi) = 1
        if !sig_com.verify_proofs(pp, vk, &c, pi) {
            return None;
        }

        let CommitRandomness(_, mu, _, _, _) = randomness;
        let Proofs(pi_a, pi_b, pi_r) = pi;

        let eq_a_bar = equations::equation_a_bar_from_lhs(pp, mn.0);
        let var_m = Variable::with_randomness(mn.0, mu);
        let pi_a_bar = Proof::new(rng, &pp.cks, &eq_a_bar, &[var_m], &[]);
        Some(Self {
            pi_a: pi_a.clone() / pi_a_bar,
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
