use ark_ec::pairing::Pairing;
use std::ops::Mul;

use super::{message::Message, Params, ParamsEx, Signature, SignatureEx, Signatures};

pub struct VerifyingKey<E: Pairing>(pub <E as Pairing>::G1Affine, pub <E as Pairing>::G2Affine);

impl<E: Pairing> VerifyingKey<E> {
    /// Verifying function `Ver` defined in Scheme 1. Verifies a signature on a message (M, N) = (G^m, H^m) in DH.
    /// The input variable `m` refers to `M`, while 'N' is not explicitly passed as an argument.
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
    pub fn verify(&self, pp: &Params<E>, mn: &Message<E>, sig: &Signature<E>) -> bool {
        let m = &mn.0;
        E::pairing(sig.a, self.1 + sig.d) == E::pairing(pp.k + m, pp.h) + E::pairing(pp.t, sig.s)
            && E::pairing(sig.b, pp.h) == E::pairing(pp.f, sig.d)
            && E::pairing(sig.r, pp.h) == E::pairing(pp.g, sig.s)
    }

    /// Verifying function `Ver` defined in Scheme 1. Verifies a signature on messages (M, N) and
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
    pub fn verify_two_messages(
        &self,
        pp: &Params<E>,
        mn: &Message<E>,
        vw: &Message<E>,
        sigs: &Signatures<E>,
    ) -> bool {
        self.verify(pp, &Message::<E>::from(&sigs.vk2), &sigs.sig0)
            && sigs.vk2.verify(pp, mn, &sigs.sig1)
            && sigs.vk2.verify(pp, &(mn + vw), &sigs.sig2)
            && sigs
                .vk2
                .verify(pp, &(mn + &vw.mul(E::ScalarField::from(3u64))), &sigs.sig3)
    }

    /// Verifying function `Ver"` defined in Scheme 2. Verifies a signature on a message (M, N) with a scalar `v`.
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
    pub fn verify_ex(
        &self,
        pp: &ParamsEx<E>,
        v: &E::ScalarField,
        m: &Message<E>,
        sig: &SignatureEx<E>,
    ) -> bool {
        let m = &m.0;

        E::pairing(sig.a, self.1 + sig.d)
            == E::pairing(pp.k + pp.l.mul(v) + m, pp.h) + E::pairing(pp.t, sig.s)
            && E::pairing(sig.b, pp.h) == E::pairing(pp.f, sig.d)
            && E::pairing(sig.r, pp.h) == E::pairing(pp.g, sig.s)
    }
}
