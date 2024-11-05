use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::{One, Zero};
use ark_std::{rand::Rng, UniformRand};
use gs_ppe::{Com, Equation, Matrix, Proof, Variable};
use std::ops::{Mul, Neg};

use crate::{Message, Params};

pub struct Commitment<E: Pairing> {
    pub(crate) c_m: Com<<E as Pairing>::G1>,
    pub(crate) c_n: Com<<E as Pairing>::G2>,
    pub(crate) pi_mn: Proof<E>,

    pub(crate) c_p: Com<<E as Pairing>::G1>,
    pub(crate) c_q: Com<<E as Pairing>::G2>,
    pub(crate) pi_pq: Proof<E>,

    pub(crate) u: <E as Pairing>::G1Affine,
    pub(crate) pi_u: Proof<E>,
}

impl<E: Pairing> Commitment<E> {
    pub fn new<R: Rng>(rng: &mut R, pp: &Params<E>, mn: &Message<E>) -> Self {
        let scalar_t = E::ScalarField::rand(rng);
        let pq = Message::<E>::new(&pp.pps, scalar_t);

        let m = Variable::<_>::new(rng, mn.0);
        let n = Variable::<_>::new(rng, mn.1);
        // c_m = Com(ck, M, _)
        let c_m = pp.cks.u.commit(&m);
        // c_n = Com(ck, N, _)
        let c_n = pp.cks.v.commit(&n);
        // pi_mn = Prove(ck, E_dh, (M, _), (N, _))
        let equation_dh = Self::equation_dh(pp);
        let pi_mn = Proof::new(rng, &pp.cks, &equation_dh, &[m], &[n]);

        let p = Variable::<_>::new(rng, pq.0);
        let q = Variable::<_>::new(rng, pq.1);
        // c_p = Com(ck, P, _)
        let c_p = pp.cks.u.commit(&p);
        // c_q = Com(ck, Q, _)
        let c_q = pp.cks.v.commit(&q);
        // pi_pq = Prove(ck, E_dh, (P, _), (Q, _))
        let equation_pq = Self::equation_dh(pp);
        let pi_pq = Proof::new(rng, &pp.cks, &equation_pq, &[p], &[q]);

        // u = T^t + M
        let u = (pp.pps.t.mul(scalar_t) + m.value).into();

        // pi_u = Prove(ck, E_u, (M, _), (Q, _))
        let equation_u = Self::equation_u(pp, &u);
        let pi_u = Proof::new(rng, &pp.cks, &equation_u, &[m], &[q]);

        Commitment {
            c_m,
            c_n,
            pi_mn,
            c_p,
            c_q,
            pi_pq,
            u,
            pi_u,
        }
    }

    pub fn randomize<R: Rng>(mut self, rng: &mut R, pp: &Params<E>) -> Self {
        let scalar_t_prime = E::ScalarField::rand(rng);
        // it is still c_p_cup now in this line, but will be mutated later: c_p_cup -> c_p'
        let mut c_p_prime = self.c_p
            + pp.cks.u.commit(&Variable::<_>::with_zero_randomness(
                pp.pps.g.mul(scalar_t_prime).into(),
            ));
        // it is still c_q_cup in this line, but will be mutated later: c_q_cup -> c_q'
        let mut c_q_prime = self.c_q
            + pp.cks.v.commit(&Variable::<_>::with_zero_randomness(
                pp.pps.h.mul(scalar_t_prime).into(),
            ));
        let u_prime = (self.u + pp.pps.t.mul(scalar_t_prime)).into();

        // c_m' = RdCom(ck, c_m, _)
        // c_n' = RdCom(ck, c_n, _)
        // mutate c_m -> c_m' in Self
        let c_m = self.c_m.randomize(rng, &pp.cks.u);
        // mutate c_n -> c_n' in Self
        let c_n = self.c_n.randomize(rng, &pp.cks.v);
        // pi_mn' = RdProof(ck, E_dh, (c_m, _), (c_n, _), pi_mn)
        let equation_dh = Self::equation_dh(pp);
        // mutate pi_mn -> pi_mn' in Self
        self.pi_mn
            .randomize(rng, &pp.cks, &equation_dh, &[c_m], &[c_n]);

        // c_p' = RdCom(ck, c_p_cup, _)
        // c_q' = RdCom(ck, c_q_cup, _)
        let c_p_cup = c_p_prime.randomize(rng, &pp.cks.u); // c_p_cup_prime -> c_p'
        let c_q_cup = c_q_prime.randomize(rng, &pp.cks.v); // c_q_cup_prime -> c_q'

        // pi_pq' = RdProof(ck, E_dh, (c_p_cup, _), (c_q_cup, _), pi_pq)
        let equation_pq = Self::equation_dh(pp);
        // mutate pi_pq -> pi_pq' in Self
        self.pi_pq
            .randomize(rng, &pp.cks, &equation_pq, &[c_p_cup], &[c_q_cup]);

        // pi_u' = Prove(ck, E_u, (c_m, _), (c_q_cup, _))
        let equation_u = Self::equation_u(pp, &self.u);
        // mutate pi_u -> pi_u' in Self
        self.pi_u
            .randomize(rng, &pp.cks, &equation_u, &[c_m], &[c_q_cup]);

        // mutate u -> u', c_p -> c_p', c_q -> c_q' in Self
        self.u = u_prime;
        self.c_p = c_p_prime;
        self.c_q = c_q_prime;

        self
    }

    /// Verifies the proofs (`pi_mn`, `pi_pq` and `pi_u`) of this commitment.
    pub fn verify_proofs(&self, pp: &Params<E>) -> bool {
        let equation_dh = Self::equation_dh(pp);
        let equation_u = Self::equation_u(pp, &self.u);

        equation_dh.verify(&pp.cks, &[self.c_m], &[self.c_n], &self.pi_mn)
            && equation_dh.verify(&pp.cks, &[self.c_p], &[self.c_q], &self.pi_pq)
            && equation_u.verify(&pp.cks, &[self.c_m], &[self.c_q], &self.pi_u)
    }

    /// E_DH: e(G^-1, Y) e(X, H) = 1
    fn equation_dh(pp: &Params<E>) -> Equation<E> {
        Equation::<E>::new(
            vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h],
            Matrix::new(&[[E::ScalarField::zero()]]),
            PairingOutput::zero(),
        )
    }
    /// E_u: e(T^-1, Y) e(X, H^-1) = e(U, H)^-1
    fn equation_u(pp: &Params<E>, u: &<E as Pairing>::G1Affine) -> Equation<E> {
        Equation::<E>::new(
            vec![pp.pps.t.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
            Matrix::new(&[[E::ScalarField::zero()]]),
            E::pairing(u, pp.pps.h).mul(E::ScalarField::one().neg()),
        )
    }
}
