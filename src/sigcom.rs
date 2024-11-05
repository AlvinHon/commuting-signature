use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr,
};
use ark_ff::{One, Zero};
use ark_std::rand::Rng;
use gs_ppe::{Com, Equation, Matrix, Proof, Randomness, Variable};
use std::ops::{Mul, Neg};

use crate::{
    automorphic_signature::{Signature, SigningKey, VerifyingKey},
    Commitment, Params,
};

// A verifiably encrypted signature on a committed value.
pub struct SigCommitment<E: Pairing> {
    pub(crate) c_a: Com<<E as Pairing>::G1>,
    pub(crate) c_b: Com<<E as Pairing>::G1>,
    pub(crate) c_d: Com<<E as Pairing>::G2>,
    pub(crate) c_r: Com<<E as Pairing>::G1>,
    pub(crate) c_s: Com<<E as Pairing>::G2>,

    pub(crate) pi_a: Proof<E>,
    pub(crate) pi_b: Proof<E>,
    pub(crate) pi_r: Proof<E>,
}

impl<E: Pairing> SigCommitment<E> {
    /// The function `SigCom` to commit on a signature. It takes a Com commitment and a signing key,
    /// and produces a verifiably encrypted signature on the committed value.
    pub fn new<R: Rng>(rng: &mut R, pp: Params<E>, sk: &SigningKey<E>, c: &Commitment<E>) -> Self {
        // verify pi_mn, pi_pq, pi_u
        assert!(c.verify_proofs(&pp));

        let VerifyingKey(_x, y) = sk.verifying_key(&pp.pps);
        let Signature { a, b, d, r, s } = sk.sign_m(rng, &pp.pps, &c.u);

        let rand_a = Randomness::rand(rng);
        let rand_b = Randomness::rand(rng);
        let rand_d = Randomness::rand(rng);
        let rand_r = Randomness::rand(rng);
        let rand_s = Randomness::rand(rng);

        // a = (K + T^r + M)^(1 / (X + C))
        let a = Variable::with_randomness(a, rand_a);
        // c_a = Com(ck, A, rand_a)
        let c_a = pp.cks.u.commit(&a);
        // c_b = Com(ck, F^c, rand_b)
        let b = Variable::with_randomness(b, rand_b);
        let c_b = pp.cks.u.commit(&b);
        // c_a = Com(ck, H^c, rand_d)
        let d = Variable::with_randomness(d, rand_d);
        let c_d = pp.cks.v.commit(&d);
        // c_r = c_p + Com(ck, G^r, rand_r)
        let c_r = c.c_p + pp.cks.u.commit(&Variable::with_randomness(r, rand_r));
        // c_s = c_q + Com(ck, H^r, rand_s)
        let c_s = c.c_q + pp.cks.v.commit(&Variable::with_randomness(s, rand_s));

        // Define E_at(A; D) : e(A, Y) e(A, D) = 1, where A and D are variables
        //
        // From GS Proof notation:
        // e(A1, Y1) e(X1, B1) e(X1, Y1)^1
        // -> e(0, d) e(a, y) e(a, d)
        // -> e(a, y) e(a, d)
        //
        // so we have A1 = 0, B1 = d, X1 = a, and Y1 = d
        let e_at = Equation::<E>::new(
            vec![<E as Pairing>::G1Affine::zero()],
            vec![y],
            Matrix::new(&[[E::ScalarField::one()]]),
            PairingOutput::zero(),
        );
        // pi_a_prime = pi_u + Prove(ck, E_at, (a, rand_a), (d, rand_d))
        let mut pi_a = c.pi_u.clone() + Proof::<E>::new(rng, &pp.cks, &e_at, &[a], &[d]);

        // Define E_a(A, M; S, D) : e(T^-1, S) e(A, Y) e(M, H^-1) e(A, D) = e(K, H),
        // where A, M, S, and D are variables
        //
        // From GS Proof notation:
        // e(A1, Y1) e(A2, Y2) e(X1, B1) e(X2, B2) e(X1, Y2)^1
        // -> e(t^-1, s) e(0, d) e(a, y) e(m, h^-1) e(a, d)
        //
        // so we have:
        // A1 = t^-1, A2 = 0, B1 = y, B2 = h^-1,
        // Y1 = s, Y2 = d, X1 = a, X2 = m
        // gamma is matrix of (2 x 2) = [[1, 0], [0, 1]]
        let e_a = Equation::<E>::new(
            vec![
                pp.pps.t.mul(E::ScalarField::one().neg()).into(),
                <E as Pairing>::G1Affine::zero(),
            ],
            vec![y, pp.pps.h.mul(E::ScalarField::one().neg()).into()],
            Matrix::new(&[
                [E::ScalarField::one(), E::ScalarField::zero()],
                [E::ScalarField::zero(), E::ScalarField::one()],
            ]),
            E::pairing(pp.pps.k, pp.pps.h),
        );

        // pi_a = RdProof(ck, E_a, (c_a, 0), (c_d, 0), (c_m, 0), (c_s, rand_s), pi_a_prime)
        pi_a.randomize(
            rng,
            &pp.cks,
            &e_a,
            &[(c_a, Randomness::zero()), (c.c_m, Randomness::zero())],
            &[(c_d, Randomness::zero()), (c_s, rand_s)],
        );

        // Define E_dh(B; D) : e(G^-1, D) e(B, H) = 1, where B and D are variables
        let e_dh = Equation::<E>::new(
            vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h],
            Matrix::new(&[[E::ScalarField::zero()]]),
            PairingOutput::zero(),
        );
        // pi_b =  Prove(ck, E_dh, (b, rand_b), (d, rand_d))
        let pi_b = Proof::<E>::new(rng, &pp.cks, &e_dh, &[b], &[d]);

        // Define E_r(R; S) : e(G^-1, S) e(R, H) = 1, where R and S are variables
        let e_r = Equation::<E>::new(
            vec![pp.pps.g.mul(E::ScalarField::one().neg()).into()],
            vec![pp.pps.h],
            Matrix::new(&[[E::ScalarField::zero()]]),
            PairingOutput::zero(),
        );
        // pi_r = RdProof(ck, E_r, (c_r, rand_r), (c_s, rand_s), pi_p)
        let mut pi_r = c.pi_pq.clone();
        pi_r.randomize(rng, &pp.cks, &e_r, &[(c_r, rand_r)], &[(c_s, rand_s)]);

        Self {
            c_a,
            c_b,
            c_d,
            c_r,
            c_s,
            pi_a,
            pi_b,
            pi_r,
        }
    }
}
