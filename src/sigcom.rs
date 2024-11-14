//! Defines the `SigCom` algorithm to commit on a signature, and the related structures.

use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{Com, Proof, Randomness, Variable};
use std::ops::Mul;

use crate::{
    automorphic_signature::{Signature, SigningKey, VerifyingKey},
    commit::Commitment,
    equations,
    proofs::Proofs,
    randomness::{CommitRandomness, SigRandomness},
    Params,
};

/// The function `SigCom` to commit on a signature. It takes a Com commitment and a signing key,
/// and produces a verifiably encrypted signature on the committed value.
pub fn sig_com<E: Pairing, R: Rng>(
    rng: &mut R,
    pp: &Params<E>,
    sk: &SigningKey<E>,
    c: &Commitment<E>,
) -> Option<(SigCommitment<E>, Proofs<E>, PreSignature<E>)> {
    // verify pi_mn, pi_pq, pi_u
    if !c.verify_proofs(pp) {
        return None;
    }

    let sig_randomness = SigRandomness::rand(rng);
    let VerifyingKey(_x, y) = sk.verifying_key(&pp.pps);
    let Signature { a, b, d, r, s } = sk.sign_m(rng, &pp.pps, &c.u);
    let SigRandomness(alpha, beta, delta, rho, sigma) = sig_randomness;

    // a = (K + T^r + U)^(1 / (X + C))
    // c_a = Com(ck, A, rand_a)
    let var_a = Variable::with_randomness(a, alpha);
    let c_a = pp.cks.u.commit(&var_a);
    // c_b = Com(ck, F^c, rand_b)
    let var_b = Variable::with_randomness(b, beta);
    let c_b = pp.cks.u.commit(&var_b);
    // c_d = Com(ck, H^c, rand_d)
    let var_d = Variable::with_randomness(d, delta);
    let c_d = pp.cks.v.commit(&var_d);
    // c_r = c_p + Com(ck, G^r, rand_r)
    let c_r = c.c_p + pp.cks.u.commit(&Variable::with_randomness(r, rho));
    // c_s = c_q + Com(ck, H^r, rand_s)
    let c_s = c.c_q + pp.cks.v.commit(&Variable::with_randomness(s, sigma));

    // X1 = a, and Y1 = d
    let e_at = equations::equation_at(y);
    // pi_a_prime = pi_u + Prove(ck, E_at, (a, rand_a), (d, rand_d))
    let mut pi_a = c.pi_u.clone() + Proof::<E>::new(rng, &pp.cks, &e_at, &[var_a], &[var_d]);

    // X1 = a, X2 = m, Y1 = s, and Y2 = d
    let e_a = equations::equation_a(pp, y);
    // pi_a = RdProof(ck, E_a, (c_a, 0), (c_d, 0), (c_m, 0), (c_s, rand_s), pi_a_prime)
    pi_a.randomize(
        rng,
        &pp.cks,
        &e_a,
        &[(c_a, Randomness::zero()), (c.c_m, Randomness::zero())],
        &[(c_s, sigma), (c_d, Randomness::zero())],
    );

    // ***
    // X1 = b, and Y1 = d
    let e_b = equations::equation_b(pp);
    // pi_b =  Prove(ck, E_dh, (b, rand_b), (d, rand_d))
    let pi_b = Proof::<E>::new(rng, &pp.cks, &e_b, &[var_b], &[var_d]);

    // X1 = R, Y1 = S
    let e_r = equations::equation_dh(pp);
    // pi_r = RdProof(ck, E_r = E_dh, (c_r, rand_r), (c_s, rand_s), pi_p)
    let mut pi_r = c.pi_pq.clone();
    pi_r.randomize(rng, &pp.cks, &e_r, &[(c_r, rho)], &[(c_s, sigma)]);

    Some((
        SigCommitment {
            c_a,
            c_b,
            c_d,
            c_r,
            c_s,
        },
        Proofs(pi_a, pi_b, pi_r),
        PreSignature {
            sig_randomness,
            a,
            b,
            d,
            r_prime: r,
            s_prime: s,
        },
    ))
}

/// The function `SmSigCom` to commit on a signature. It takes a Com commitment and a verifying key,
/// and produces a verifiably encrypted signature on the committed value.
///
/// ## Panics
/// panics if the parameters `pp` does not contain the extraction key `ek`.
pub fn sm_sig_com<E: Pairing, R: Rng>(
    rng: &mut R,
    pp: &Params<E>,
    vk: &VerifyingKey<E>,
    c: &Commitment<E>,
    sig: &Signature<E>,
) -> Option<(SigCommitment<E>, Proofs<E>)> {
    let ek = pp.ek.unwrap();
    // verify pi_mn, pi_pq, pi_u
    if !c.verify_proofs(pp) {
        return None;
    }

    let y = vk.1;
    let Signature { a, b, d, r, s } = *sig;
    // (rho and sigma are not used because the later computed commitments `c_r` and `c_s` have already contained the actual randomness `rho` and `sigma`.
    let SigRandomness(alpha, beta, delta, _rho, _sigma) = SigRandomness::<E>::rand(rng);

    // c_a = Com(ck, A, rand_a)
    let var_a = Variable::with_randomness(a, alpha);
    let c_a = pp.cks.u.commit(&var_a);
    // c_b = Com(ck, F^c, rand_b)
    let var_b = Variable::with_randomness(b, beta);
    let c_b = pp.cks.u.commit(&var_b);
    // c_d = Com(ck, H^c, rand_d)
    let var_d = Variable::with_randomness(d, delta);
    let c_d = pp.cks.v.commit(&var_d);

    // extract P and Q
    let p = ek.extract_1(&c.c_p);
    let q = ek.extract_2(&c.c_q);

    // c_r = c_p + Com(ck, R + P^-1, 0)
    let var_rp1 = Variable::with_randomness((r - p).into(), Randomness::zero());
    let c_r = c.c_p + pp.cks.u.commit(&var_rp1);
    // c_s = c_q + Com(ck, S + Q^-1, 0)
    let var_sq1 = Variable::with_randomness((s - q).into(), Randomness::zero());
    let c_s = c.c_q + pp.cks.v.commit(&var_sq1);

    // X1 = a, and Y1 = d
    let e_at = equations::equation_at(y);
    // pi_a_prime = pi_u + Prove(ck, E_at, (a, rand_a), (d, rand_d))
    let mut pi_a = c.pi_u.clone() + Proof::<E>::new(rng, &pp.cks, &e_at, &[var_a], &[var_d]);

    // X1 = a, X2 = m, Y1 = s, and Y2 = d
    let e_a = equations::equation_a(pp, y);
    // pi_a = RdProof(ck, E_a, (c_a, 0), (c_d, 0), (c_m, 0), (c_s, rand_s), pi_a_prime)
    pi_a.randomize(
        rng,
        &pp.cks,
        &e_a,
        &[(c_a, Randomness::zero()), (c.c_m, Randomness::zero())],
        &[(c_s, Randomness::zero()), (c_d, Randomness::zero())], // different from SigCom, sigma is not used.
    );

    // ***
    // X1 = b, and Y1 = d
    let e_b = equations::equation_b(pp);
    // pi_b =  Prove(ck, E_dh, (b, rand_b), (d, rand_d))
    let pi_b = Proof::<E>::new(rng, &pp.cks, &e_b, &[var_b], &[var_d]);

    // X1 = R, Y1 = S
    let e_r = equations::equation_dh(pp);
    // pi_r = RdProof(ck, E_r = E_dh, (c_r, rand_r), (c_s, rand_s), pi_p)
    let mut pi_r = c.pi_pq.clone();
    pi_r.randomize(
        rng,
        &pp.cks,
        &e_r,
        &[(c_r, Randomness::zero())], // different from SigCom, rho is not used.
        &[(c_s, Randomness::zero())], // different from SigCom, sigma is not used.
    );

    Some((
        SigCommitment {
            c_a,
            c_b,
            c_d,
            c_r,
            c_s,
        },
        Proofs(pi_a, pi_b, pi_r),
    ))
}

/// Commitment on a signature = (A, B, D, R, S).
#[derive(Clone, Debug)]
pub struct SigCommitment<E: Pairing> {
    // (c_a, c_b, c_d, c_r, c_s) are commitments on the actual signature = (A, B, D, R, S).
    pub(crate) c_a: Com<<E as Pairing>::G1>,
    pub(crate) c_b: Com<<E as Pairing>::G1>,
    pub(crate) c_d: Com<<E as Pairing>::G2>,
    pub(crate) c_r: Com<<E as Pairing>::G1>,
    pub(crate) c_s: Com<<E as Pairing>::G2>,
}

impl<E: Pairing> SigCommitment<E> {
    /// Verifies the proofs (`pi_a`, `pi_b` and `pi_r`) of this commitment.
    pub fn verify_proofs(
        &self,
        pp: &Params<E>,
        vk: &VerifyingKey<E>,
        c: &Commitment<E>,
        pi: &Proofs<E>,
    ) -> bool {
        if !c.verify_proofs(pp) {
            return false;
        }

        let Proofs(pi_a, pi_b, pi_r) = pi;

        let y = vk.1;

        let e_a = equations::equation_a(pp, y);
        let e_dh = equations::equation_dh(pp);
        let e_b = equations::equation_b(pp);

        e_a.verify(&pp.cks, &[self.c_a, c.c_m], &[self.c_s, self.c_d], pi_a)
            && e_b.verify(&pp.cks, &[self.c_b], &[self.c_d], pi_b)
            && e_dh.verify(&pp.cks, &[self.c_r], &[self.c_s], pi_r)
    }
}

#[derive(Clone, Debug)]
pub struct PreSignature<E: Pairing> {
    // (alpha, beta, delta, rho', sigma')
    pub(crate) sig_randomness: SigRandomness<E>,
    // (a, b, d, r', s')
    pub(crate) a: <E as Pairing>::G1Affine,
    pub(crate) b: <E as Pairing>::G1Affine,
    pub(crate) d: <E as Pairing>::G2Affine,
    pub(crate) r_prime: <E as Pairing>::G1Affine,
    pub(crate) s_prime: <E as Pairing>::G2Affine,
}

impl<E: Pairing> PreSignature<E> {
    /// Given the randomness used in message commitment, return:
    /// 1. the equivalent signature to be committed by the algorithm `sigcom`. i.e. (A, B, D, R, S)
    /// 2. the associated randomness used for the signature commitment. i.e. (alpha, beta, delta, rho, sigma)
    pub fn to_precommit_signature(
        self,
        pp: &Params<E>,
        com_randomness: CommitRandomness<E>,
    ) -> PrecommitSignature<E> {
        let tau = com_randomness.0;
        let signature = Signature {
            a: self.a,
            b: self.b,
            d: self.d,
            r: (self.r_prime + pp.pps.g.mul(tau)).into(),
            s: (self.s_prime + pp.pps.h.mul(tau)).into(),
        };
        let randomness = SigRandomness(
            self.sig_randomness.0,
            self.sig_randomness.1,
            self.sig_randomness.2,
            self.sig_randomness.3 + com_randomness.3,
            self.sig_randomness.4 + com_randomness.4,
        );

        PrecommitSignature {
            signature,
            randomness,
        }
    }
}

/// Represents a state that the signature will/is expected to be committed with a randomness.
pub struct PrecommitSignature<E: Pairing> {
    pub signature: Signature<E>,
    pub randomness: SigRandomness<E>,
}

impl<E: Pairing> PrecommitSignature<E> {
    /// Straightforwardly commit on the signature by the given randomness, by using the commitment scheme
    /// in GS proof system.
    pub fn commit(&self, pp: &Params<E>) -> SigCommitment<E> {
        let Signature { a, b, d, r, s } = self.signature;
        let SigRandomness(alpha, beta, delta, rho, sigma) = self.randomness;

        let a = Variable::with_randomness(a, alpha);
        let b = Variable::with_randomness(b, beta);
        let d = Variable::with_randomness(d, delta);
        let r = Variable::with_randomness(r, rho);
        let s = Variable::with_randomness(s, sigma);

        let c_a = pp.cks.u.commit(&a);
        let c_b = pp.cks.u.commit(&b);
        let c_d = pp.cks.v.commit(&d);
        let c_r = pp.cks.u.commit(&r);
        let c_s = pp.cks.v.commit(&s);

        SigCommitment {
            c_a,
            c_b,
            c_d,
            c_r,
            c_s,
        }
    }
}
