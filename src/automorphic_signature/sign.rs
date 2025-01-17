//! Defines the [SigningKey] struct for the automorphic signatures.

use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, One, UniformRand};
use std::ops::Mul;

use super::{
    key_gen, message::Message, DHGenerators, Params, ParamsEx, Signature, SignatureEx, Signatures,
    VerifyingKey,
};

/// The signing key for the automorphic signatures, can be used in Scheme 1 and Scheme 2.
#[derive(Clone, Debug)]
pub struct SigningKey<E: Pairing> {
    pub(crate) x: E::ScalarField,
}

impl<E: Pairing> SigningKey<E> {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            x: E::ScalarField::rand(rng),
        }
    }

    /// Get the verifying key from the signing key.
    pub fn verifying_key<G: DHGenerators<E>>(&self, grs: &G) -> VerifyingKey<E> {
        VerifyingKey(grs.g().mul(self.x), grs.h().mul(self.x))
    }

    /// Signing function `Sign` defined in Scheme 1. Signs on a message (M, N) = (G^m, H^m) in DH.
    ///
    /// ## Example
    ///
    /// ```
    /// use ark_bls12_381::Bls12_381 as E;
    /// use ark_ec::pairing::Pairing;
    /// use ark_std::{test_rng, UniformRand};
    ///
    /// use commuting_signature::automorphic_signature::{Message, Params, key_gen};
    ///
    /// type G1Affine = <E as Pairing>::G1Affine;
    /// type Fr = <E as Pairing>::ScalarField;
    ///
    /// let rng = &mut test_rng();
    ///
    /// let pp = Params::<E>::rand(rng);
    /// let (vk, sk) = key_gen(rng, &pp);
    ///
    /// let mn = Message::new(&pp, Fr::rand(rng));
    /// let sig = sk.sign(rng, &pp, &mn);
    ///
    /// assert!(vk.verify(&pp, &mn, &sig));
    /// ```
    pub fn sign<R: Rng>(&self, rng: &mut R, pp: &Params<E>, mn: &Message<E>) -> Signature<E> {
        self.sign_m(rng, pp, &mn.0)
    }

    /// Signing function `Sign` defined in Scheme 1. Signs on a message (M, N) = (G^m, H^m) in DH.
    ///
    /// Compute (a, b, d, r, s) as follows:
    /// - `a = (k + t^r + m)^ (1 / (x + c))`
    /// - `b = f^c`
    /// - `d = h^c`
    /// - `r = g^r`
    /// - `s = h^r`
    ///
    /// where `c, r` are random scalars.
    pub(crate) fn sign_m<R: Rng>(
        &self,
        rng: &mut R,
        pp: &Params<E>,
        m: &<E as Pairing>::G1,
    ) -> Signature<E> {
        let rand_c = E::ScalarField::rand(rng);
        let rand_r = E::ScalarField::rand(rng);

        let a = {
            let exp = E::ScalarField::one() / (self.x + rand_c);
            (pp.k + pp.t.mul(rand_r) + m).mul(exp)
        };
        let b = pp.f.mul(rand_c);
        let d = pp.h.mul(rand_c);
        let r = pp.g.mul(rand_r);
        let s = pp.h.mul(rand_r);

        Signature { a, b, d, r, s }
    }

    /// Signing function `Sign` defined in Scheme 1. Signs on two messages (M, N) and
    /// (V, W) at once.
    ///
    /// ## Example
    ///
    /// ```
    /// use ark_bls12_381::Bls12_381 as E;
    /// use ark_ec::pairing::Pairing;
    /// use ark_std::{test_rng, UniformRand};
    ///
    /// use commuting_signature::automorphic_signature::{Message, Params, key_gen};
    ///
    /// type G1Affine = <E as Pairing>::G1Affine;
    /// type Fr = <E as Pairing>::ScalarField;
    ///
    /// let rng = &mut test_rng();
    ///
    /// let pp = Params::<E>::rand(rng);
    /// let (vk, sk) = key_gen(rng, &pp);
    ///
    /// let mn = Message::new(&pp, Fr::rand(rng));
    /// let vw = Message::new(&pp, Fr::rand(rng));
    /// let sigs = sk.sign_two_messages(rng, &pp, &mn, &vw);
    ///
    /// assert!(vk.verify_two_messages(&pp, &mn, &vw, &sigs));
    /// ```
    pub fn sign_two_messages<R: Rng>(
        &self,
        rng: &mut R,
        pp: &Params<E>,
        mn: &Message<E>,
        vw: &Message<E>,
    ) -> Signatures<E> {
        let (vk2, sk2) = key_gen(rng, pp);
        let sig0 = self.sign(rng, pp, &Message::<E>::from(&vk2));
        let sig1 = sk2.sign(rng, pp, mn);
        let sig2 = sk2.sign(rng, pp, &(mn + vw));
        let sig3 = sk2.sign(rng, pp, &(mn + &vw.mul(E::ScalarField::from(3u64))));

        Signatures {
            vk2,
            sig0,
            sig1,
            sig2,
            sig3,
        }
    }

    /// Signing function `Sign"` defined in Scheme 2. Signs on a message (M, N) = (G^m, H^m) in DH,
    /// together with a scalar `v`.
    ///
    /// ## Example
    ///
    /// ```
    /// use ark_bls12_381::Bls12_381 as E;
    /// use ark_ec::pairing::Pairing;
    /// use ark_std::{test_rng, UniformRand};
    ///
    /// use commuting_signature::automorphic_signature::{Message, ParamsEx, key_gen};
    ///
    /// type G1Affine = <E as Pairing>::G1Affine;
    /// type Fr = <E as Pairing>::ScalarField;
    ///
    /// let rng = &mut test_rng();
    ///
    /// let pp = ParamsEx::<E>::rand(rng);
    /// let (vk, sk) = key_gen(rng, &pp);
    ///
    /// let v = Fr::rand(rng);
    /// let mn = Message::new(&pp, Fr::rand(rng));
    /// let sig_ex = sk.sign_ex(rng, &pp, &v, &mn);
    ///
    /// assert!(vk.verify_ex(&pp, &v, &mn, &sig_ex));
    /// ```
    pub fn sign_ex<R: Rng>(
        &self,
        rng: &mut R,
        pp: &ParamsEx<E>,
        v: &E::ScalarField,
        mn: &Message<E>,
    ) -> SignatureEx<E> {
        let m = &mn.0;

        let rand_c = E::ScalarField::rand(rng);
        let rand_r = E::ScalarField::rand(rng);

        let a = {
            let exp = E::ScalarField::one() / (self.x + rand_c);
            (pp.k + pp.l.mul(v) + pp.t.mul(rand_r) + m).mul(exp)
        };
        let b = pp.f.mul(rand_c);
        let d = pp.h.mul(rand_c);
        let r = pp.g.mul(rand_r);
        let s = pp.h.mul(rand_r);

        SignatureEx { a, b, d, r, s }
    }
}
