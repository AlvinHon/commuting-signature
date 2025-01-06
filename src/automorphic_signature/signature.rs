//! Defines the signature structs [Signature], [Signatures], and [SignatureEx].

use ark_ec::pairing::Pairing;

use super::VerifyingKey;

/// Signature created by a signing algorithm in scheme 1.
#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub(crate) a: <E as Pairing>::G1,
    pub(crate) b: <E as Pairing>::G1,
    pub(crate) d: <E as Pairing>::G2,
    pub(crate) r: <E as Pairing>::G1,
    pub(crate) s: <E as Pairing>::G2,
}

/// Signature created by the signing algorithm (that signs two messages) in scheme 1.
#[derive(Clone, Debug)]
pub struct Signatures<E: Pairing> {
    pub(crate) vk2: VerifyingKey<E>,
    pub(crate) sig0: Signature<E>,
    pub(crate) sig1: Signature<E>,
    pub(crate) sig2: Signature<E>,
    pub(crate) sig3: Signature<E>,
}

/// Signature created by a signing algorithm in scheme 2.
#[derive(Clone, Debug)]
pub struct SignatureEx<E: Pairing> {
    pub(crate) a: <E as Pairing>::G1,
    pub(crate) b: <E as Pairing>::G1,
    pub(crate) d: <E as Pairing>::G2,
    pub(crate) r: <E as Pairing>::G1,
    pub(crate) s: <E as Pairing>::G2,
}
