use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{Proof, Randomness, Variable};
use std::ops::Neg;

use crate::{
    automorphic_signature::VerifyingKey,
    commit::Commitment,
    equations,
    randomness::{CommitRandomness, KeyRandomness, SigRandomness},
    sigcom::{PrecommitSignature, SigCommitment},
    Message, Params,
};

/// (pi_*, pi_b, pi_r), the proofs commonly used in the proof adaptation alogrithms.
#[derive(Clone, Debug)]
pub struct Proofs<E: Pairing>(pub Proof<E>, pub Proof<E>, pub Proof<E>);

/// The proofs (pi_a, pi_b, pi_r), used in the proof adaptation algorithms for the
/// equations `E_a`, `E_b`, and `E_r`.
#[derive(Clone, Debug)]
pub struct AdaptProof<E: Pairing> {
    pi_a: Proof<E>,
    pi_b: Proof<E>,
    pi_r: Proof<E>,
}

impl<E: Pairing> AdaptProof<E> {
    /// The function `AdPrC`, adapt proof when committing a signature.
    /// Given a message/signature pair of which one is verifiably encrypted,
    /// produce a proof that it and its associated message are verifiably encrypted.
    pub fn committing_signature<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        c: &Commitment<E>,
        // ((A, B, D, R, S), (alpha, beta, delta, rho, sigma))
        precommit_sig: &PrecommitSignature<E>,
        pi_a_bar: &Proof<E>,
    ) -> Option<Self> {
        let y = vk.1;
        let PrecommitSignature {
            signature,
            randomness,
        } = precommit_sig;
        let SigRandomness(alpha, beta, delta, rho, sigma) = *randomness;

        // Verify the proof pi_a_bar that C contains a commitment to m s.t. E_a_bar.
        // i.e. Verify(ck, E_Ver(vk,.,Σ), C, pi_a_bar) = 1
        let eq_a_bar =
            equations::equation_a_bar_from_rhs(pp, y, signature.a, signature.d, signature.s);
        if !eq_a_bar.verify(&pp.cks, &[c.c_m], &[], pi_a_bar) {
            return None;
        }

        // Compute pi_a_tide.
        let var_a = Variable::with_randomness(signature.a, alpha);
        let var_d = Variable::with_randomness(signature.d, delta);
        let var_s = Variable::with_randomness(signature.s, sigma);
        let eq_a_tide =
            equations::equation_a_tide_from_lhs(pp, signature.s, signature.a, signature.d, y);
        let pi_a_tide = Proof::new(rng, &pp.cks, &eq_a_tide, &[var_a], &[var_s, var_d]);

        // Compute pi_b.
        let var_b = Variable::with_randomness(signature.b, beta);
        let eq_b = equations::equation_b(pp);
        let pi_b = Proof::new(rng, &pp.cks, &eq_b, &[var_b], &[var_d]);

        // Compute pi_r.
        let var_r = Variable::with_randomness(signature.r, rho);
        let eq_r = equations::equation_dh(pp);
        let pi_r = Proof::new(rng, &pp.cks, &eq_r, &[var_r], &[var_s]);

        Some(Self {
            pi_a: pi_a_tide + pi_a_bar.clone(),
            pi_b,
            pi_r,
        })
    }

    /// The function `AdPrC_M`, adapt proof when committing a message.
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

    /// The function `AdPrC_K`, adapt proof when committing the public key vk = (X, Y),
    /// and produce an adapted proof that the first element `pi_a` is adapted (i.e. `pi_a_cap` in `AdPrDC_K`).
    pub fn committing_key<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        // (xi, psi), only psi is needed.
        randomness: KeyRandomness<E>,
        c: &Commitment<E>,
        sig_com: &SigCommitment<E>,
        pi: &Proofs<E>,
    ) -> Option<Self> {
        // Verify the proof pi that the commitments c and sig_com s.t. E_a, E_b, E_r.
        // i.e. Verify(ck, E_Ver(vk,.,.), C, C_Σ, pi) = 1
        if !sig_com.verify_proofs(pp, vk, c, pi) {
            return None;
        }

        let y = vk.1;
        let mut pi_a_cap = pi.0.clone();

        let var_y = Variable::with_zero_randomness(y);
        let c_y = pp.cks.v.commit(&var_y);

        let eq_a_cap = equations::equation_a_cap(pp);
        pi_a_cap.randomize(
            rng,
            &pp.cks,
            &eq_a_cap,
            &[
                (sig_com.c_a, Randomness::zero()),
                (c.c_m, Randomness::zero()),
            ],
            &[
                (sig_com.c_s, Randomness::zero()),
                (sig_com.c_d, Randomness::zero()),
                (c_y, randomness.1),
            ],
        );

        Some(Self {
            pi_a: pi_a_cap,
            pi_b: pi.1.clone(), // remain unchanged
            pi_r: pi.2.clone(), // remain unchanged
        })
    }

    /// The function `AdPrDC`, adapt proof when decommitting a signature.
    /// Given a verifiably encrypted message/signature pair,
    /// produce an adapted proof (`pi_a_bar` in `AdPrC`) that a signature is valid on a committed message.
    pub fn decommitting_signature<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        c: &Commitment<E>,
        // ((A, B, D, R, S), (alpha, beta, delta, rho, sigma))
        committed_sig: &PrecommitSignature<E>,
        pi: &Proofs<E>,
    ) -> Option<Proof<E>> {
        let PrecommitSignature {
            signature,
            randomness,
        } = committed_sig;
        // Verify the proof pi that C contains a commitment to message s.t. E_a, E_b and E_r.
        // i.e. Verify(ck, E_Ver(vk,.,.), C, Com(ck, Σ, rho), pi) = 1
        if !committed_sig.commit(pp).verify_proofs(pp, vk, c, pi) {
            return None;
        }

        let y = vk.1;
        let SigRandomness(alpha, _, delta, _, sigma) = *randomness;
        let Proofs(pi_a, _, _) = pi;

        let var_a = Variable::with_randomness(signature.a, alpha);
        let var_d = Variable::with_randomness(signature.d, delta);
        let var_s = Variable::with_randomness(signature.s, sigma);
        let eq_a_tide =
            equations::equation_a_tide_from_lhs(pp, signature.s, signature.a, signature.d, y);
        let pi_a_tide = Proof::new(rng, &pp.cks, &eq_a_tide, &[var_a], &[var_s, var_d]);

        Some(pi_a.clone() / pi_a_tide)
    }
    /// The function `AdPrDC_M`, adapt proof when decommitting a message.
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

    /// The function `AdPrDC_K`, adapt proof when decommitting the public key vk = (X, Y),
    /// and produce an adapted proof.
    pub fn decommitting_key<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        randomness: KeyRandomness<E>,
        c: &Commitment<E>,
        sig_com: &SigCommitment<E>,
        pi_a_cap: &Proofs<E>,
    ) -> Option<Self> {
        let y = vk.1;
        let Proofs(pi_a_cap, pi_b, pi_r) = pi_a_cap;
        let eq_a_cap = equations::equation_a_cap(pp);

        let var_y = Variable::with_randomness(y, randomness.1);
        let c_y = pp.cks.v.commit(&var_y);

        // Verify the proof pi_a_cap that the commitment to the public key with the message/signature commitments s.t. E_a_cap.
        // i.e. Verify(ck, E_Ver(.,.,.), C, C_Σ, pi_a_cap) = 1
        if !eq_a_cap.verify(
            &pp.cks,
            &[sig_com.c_a, c.c_m],
            &[sig_com.c_s, sig_com.c_d, c_y],
            pi_a_cap,
        ) {
            return None;
        }

        let mut pi_a = pi_a_cap.clone();
        pi_a.randomize(
            rng,
            &pp.cks,
            &eq_a_cap,
            &[
                (sig_com.c_a, Randomness::zero()),
                (c.c_m, Randomness::zero()),
            ],
            &[
                (sig_com.c_s, Randomness::zero()),
                (sig_com.c_d, Randomness::zero()),
                (c_y, randomness.1.neg()),
            ],
        );

        Some(Self {
            pi_a,
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

/// The `prove` function in Figure 1 in the paper. It is not being used publicly.
/// It exists for testing purposes.
#[allow(unused)]
pub(crate) fn prove_message<E: Pairing, R: Rng>(
    rng: &mut R,
    pp: &Params<E>,
    mn: &Message<E>,
    com_randomness: CommitRandomness<E>,
) -> Proof<E> {
    let m = mn.0;
    let CommitRandomness(_, mu, _, _, _) = com_randomness;

    let equ_a_bar = equations::equation_a_bar_from_lhs(pp, m);
    Proof::new(
        rng,
        &pp.cks,
        &equ_a_bar,
        &[Variable::with_randomness(m, mu)],
        &[],
    )
}

/// The `prove` function in Figure 1 in the paper. It is not being used publicly.
/// It exists for testing purposes.
#[allow(unused)]
pub(crate) fn prove_signature<E: Pairing, R: Rng>(
    rng: &mut R,
    pp: &Params<E>,
    vk: &VerifyingKey<E>,
    committed_sig: &PrecommitSignature<E>,
) -> Proofs<E> {
    let y = vk.1;
    let PrecommitSignature {
        signature,
        randomness,
    } = committed_sig;
    let SigRandomness(alpha, beta, delta, rho, sigma) = *randomness;

    let var_a = Variable::with_randomness(signature.a, alpha);
    let var_d = Variable::with_randomness(signature.d, delta);
    let var_s = Variable::with_randomness(signature.s, sigma);
    let equ_a_tide =
        equations::equation_a_tide_from_lhs(pp, signature.s, signature.a, signature.d, y);
    let pi_a_tide = Proof::new(rng, &pp.cks, &equ_a_tide, &[var_a], &[var_s, var_d]);

    let var_b = Variable::with_randomness(signature.b, beta);
    let equ_b = equations::equation_b(pp);
    let pi_b = Proof::new(rng, &pp.cks, &equ_b, &[var_b], &[var_d]);

    let equ_r = equations::equation_dh(pp);
    let var_r = Variable::with_randomness(signature.r, rho);
    let pi_r = Proof::new(rng, &pp.cks, &equ_r, &[var_r], &[var_s]);

    Proofs(pi_a_tide, pi_b, pi_r)
}
