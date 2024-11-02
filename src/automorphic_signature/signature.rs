use ark_ec::pairing::Pairing;

use super::VerifyingKey;

pub struct Signature<E: Pairing> {
    pub(crate) a: <E as Pairing>::G1Affine,
    pub(crate) b: <E as Pairing>::G1Affine,
    pub(crate) d: <E as Pairing>::G2Affine,
    pub(crate) r: <E as Pairing>::G1Affine,
    pub(crate) s: <E as Pairing>::G2Affine,
}

pub struct Signatures<E: Pairing> {
    pub(crate) vk2: VerifyingKey<E>,
    pub(crate) sig0: Signature<E>,
    pub(crate) sig1: Signature<E>,
    pub(crate) sig2: Signature<E>,
    pub(crate) sig3: Signature<E>,
}

pub struct SignatureEx<E: Pairing> {
    pub(crate) a: <E as Pairing>::G1Affine,
    pub(crate) b: <E as Pairing>::G1Affine,
    pub(crate) d: <E as Pairing>::G2Affine,
    pub(crate) r: <E as Pairing>::G1Affine,
    pub(crate) s: <E as Pairing>::G2Affine,
}
