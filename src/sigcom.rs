use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use gs_ppe::{Com, Proof, Randomness, Variable};

use crate::{
    automorphic_signature::{Signature, SigningKey, VerifyingKey},
    equations,
    proofs::Proofs,
    Commitment, Params, SigRandomness,
};

/// Commitment on a signature = (A, B, D, R, S).
pub struct SigCommitment<E: Pairing> {
    // (c_a, c_b, c_d, c_r, c_s) are commitments on the actual signature = (A, B, D, R, S).
    pub(crate) c_a: Com<<E as Pairing>::G1>,
    pub(crate) c_b: Com<<E as Pairing>::G1>,
    pub(crate) c_d: Com<<E as Pairing>::G2>,
    pub(crate) c_r: Com<<E as Pairing>::G1>,
    pub(crate) c_s: Com<<E as Pairing>::G2>,
}

impl<E: Pairing> SigCommitment<E> {
    /// The function `SigCom` to commit on a signature. It takes a Com commitment and a signing key,
    /// and produces a verifiably encrypted signature on the committed value.
    pub fn new<R: Rng>(
        rng: &mut R,
        pp: &Params<E>,
        sk: &SigningKey<E>,
        c: &Commitment<E>,
        randomness: SigRandomness<E>,
    ) -> Result<(SigCommitment<E>, Proofs<E>), ()> {
        // verify pi_mn, pi_pq, pi_u
        if !c.verify_proofs(&pp) {
            return Err(());
        }

        let VerifyingKey(_x, y) = sk.verifying_key(&pp.pps);
        let Signature { a, b, d, r, s } = sk.sign_m(rng, &pp.pps, &c.u);

        let SigRandomness(alpha, beta, delta, rho, sigma) = randomness;

        // a = (K + T^r + M)^(1 / (X + C))
        let a = Variable::with_randomness(a, alpha);
        // c_a = Com(ck, A, rand_a)
        let c_a = pp.cks.u.commit(&a);
        // c_b = Com(ck, F^c, rand_b)
        let b = Variable::with_randomness(b, beta);
        let c_b = pp.cks.u.commit(&b);
        // c_a = Com(ck, H^c, rand_d)
        let d = Variable::with_randomness(d, delta);
        let c_d = pp.cks.v.commit(&d);
        // c_r = c_p + Com(ck, G^r, rand_r)
        let c_r = c.c_p + pp.cks.u.commit(&Variable::with_randomness(r, rho));
        // c_s = c_q + Com(ck, H^r, rand_s)
        let c_s = c.c_q + pp.cks.v.commit(&Variable::with_randomness(s, sigma));

        // X1 = a, and Y1 = d
        let e_at = equations::equation_at(y);
        // pi_a_prime = pi_u + Prove(ck, E_at, (a, rand_a), (d, rand_d))
        let mut pi_a = c.pi_u.clone() + Proof::<E>::new(rng, &pp.cks, &e_at, &[a], &[d]);

        // X1 = a, X2 = m, Y1 = s, and Y2 = d
        let e_a = equations::equation_a(&pp, y);
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
        let e_b = equations::equation_b(&pp);
        // pi_b =  Prove(ck, E_dh, (b, rand_b), (d, rand_d))
        let pi_b = Proof::<E>::new(rng, &pp.cks, &e_b, &[b], &[d]);
        assert!(e_b.verify(&pp.cks, &[c_b], &[c_d], &pi_b));

        // X1 = R, Y1 = S
        let e_r = equations::equation_dh(pp);
        // pi_r = RdProof(ck, E_r = E_dh, (c_r, rand_r), (c_s, rand_s), pi_p)
        let mut pi_r = c.pi_pq.clone();
        pi_r.randomize(rng, &pp.cks, &e_r, &[(c_r, rho)], &[(c_s, sigma)]);

        Ok((
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

        let e_a = equations::equation_a(&pp, y);
        let e_dh = equations::equation_dh(&pp);
        let e_b = equations::equation_b(&pp);

        e_a.verify(&pp.cks, &[self.c_a, c.c_m], &[self.c_s, self.c_d], &pi_a)
            && e_b.verify(&pp.cks, &[self.c_b], &[self.c_d], &pi_b)
            && e_dh.verify(&pp.cks, &[self.c_r], &[self.c_s], &pi_r)
    }
}
