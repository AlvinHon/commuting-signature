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
        let g = pp.pps.g;
        let h = pp.pps.h;

        let t = pp.pps.t;

        let scalar_t = E::ScalarField::rand(rng);
        let pq = Message::<E>::new(&pp.pps, scalar_t);

        // E_DH: e(G^-1, N) e(M, H) = 1
        let m = Variable::<_>::new(rng, mn.0);
        let n = Variable::<_>::new(rng, mn.1);
        let proof_system_dh = gs_ppe::setup(
            rng,
            &pp.cks,
            &[(g.mul(E::ScalarField::one().neg()).into(), n)],
            &[(m, h)],
            &Matrix::new(&[[E::ScalarField::zero()]]),
        );
        // E_pq: e(G^-1, Q) e(P, H) = 1
        let p = Variable::<_>::new(rng, pq.0);
        let q = Variable::<_>::new(rng, pq.1);
        let proof_system_pq = gs_ppe::setup(
            rng,
            &pp.cks,
            &[(g.mul(E::ScalarField::one().neg()).into(), q)],
            &[(p, h)],
            &Matrix::new(&[[E::ScalarField::zero()]]),
        );
        // u = T^t + M
        let u = (t.mul(scalar_t) + m.value).into();
        // E_u: e(T^-1, Q) e(M, H^-1) = e(U, H)^-1
        let proof_system_u = gs_ppe::setup(
            rng,
            &pp.cks,
            &[(t.mul(E::ScalarField::one().neg()).into(), q)],
            &[(m, h.mul(E::ScalarField::one().neg()).into())],
            &Matrix::new(&[[E::ScalarField::zero()]]),
        );

        Commitment {
            c_m: proof_system_dh.c[0],
            c_n: proof_system_dh.d[0],
            pi_mn: proof_system_dh.proof,

            c_p: proof_system_pq.c[0],
            c_q: proof_system_pq.d[0],
            pi_pq: proof_system_pq.proof,

            u,
            pi_u: proof_system_u.proof,
        }
    }

    pub fn randomize<R: Rng>(mut self, rng: &mut R, pp: &Params<E>) -> Self {
        let scalar_t_prime = E::ScalarField::rand(rng);
        // it is still c_p_cup now in this line, but will be mutated later: c_p_cup -> c_p'
        let mut c_p_cup_prime = self.c_p
            + pp.cks.u.commit(&Variable::<_>::with_zero_randomness(
                pp.pps.g.mul(scalar_t_prime).into(),
            ));
        // it is still c_q_cup in this line, but will be mutated later: c_q_cup -> c_q'
        let mut c_q_cup_prime = self.c_q
            + pp.cks.v.commit(&Variable::<_>::with_zero_randomness(
                pp.pps.h.mul(scalar_t_prime).into(),
            ));
        let u_prime = (self.u + pp.pps.t.mul(scalar_t_prime)).into();

        // E_DH: e(G^-1, N) e(M, H) = 1
        let equation_dh = Equation::<E>::new(
            vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h],
            Matrix::new(&[[E::ScalarField::zero()]]),
            PairingOutput::zero(),
        );
        // mutate c_m -> c_m' in Self
        let c_m = self.c_m.randomize(rng, &pp.cks.u);
        // mutate c_n -> c_n' in Self
        let c_n = self.c_n.randomize(rng, &pp.cks.v);
        // mutate pi_mn -> pi_mn' in Self
        self.pi_mn
            .randomize(rng, &pp.cks, &equation_dh, &[c_m], &[c_n]);

        // E_pq: e(G^-1, Q) e(P, H) = 1
        let c_p_cup = c_p_cup_prime.randomize(rng, &pp.cks.u); // c_p_cup_prime -> c_p'
        let c_q_cup = c_q_cup_prime.randomize(rng, &pp.cks.v); // c_q_cup_prime -> c_q'
        let equation_pq = Equation::<E>::new(
            vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h],
            Matrix::new(&[[E::ScalarField::zero()]]),
            PairingOutput::zero(),
        );
        // mutate pi_pq -> pi_pq' in Self
        self.pi_pq
            .randomize(rng, &pp.cks, &equation_pq, &[c_p_cup], &[c_q_cup]);

        // E_u: e(T^-1, Q) e(M, H^-1) = e(U, H)^-1
        let equation_u = Equation::<E>::new(
            vec![pp.pps.t.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h.mul(E::ScalarField::one().neg()).into()],
            Matrix::new(&[[E::ScalarField::zero()]]),
            E::pairing(self.u, pp.pps.h).mul(E::ScalarField::one().neg()),
        );
        // mutate pi_u -> pi_u' in Self
        self.pi_u
            .randomize(rng, &pp.cks, &equation_u, &[c_m], &[c_q_cup]);

        // mutate u -> u', c_p -> c_p', c_q -> c_q' in Self
        self.u = u_prime;
        self.c_p = c_p_cup_prime;
        self.c_q = c_q_cup_prime;

        self
    }
}
