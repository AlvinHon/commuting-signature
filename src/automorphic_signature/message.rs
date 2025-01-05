//! Defines the [Message] struct for the automorphic signatures.

use super::{DHGenerators, VerifyingKey};
use ark_ec::pairing::Pairing;
use std::ops::{Add, Mul};

/// Represents a message in the automorphic signatures.
#[derive(Clone, Debug)]
pub struct Message<E: Pairing>(
    pub(crate) <E as Pairing>::G1Affine,
    pub(crate) <E as Pairing>::G2Affine,
);

impl<E: Pairing> Message<E> {
    pub fn new<G: DHGenerators<E>>(grs: &G, m: E::ScalarField) -> Self {
        Self(grs.g().mul(m).into(), grs.h().mul(m).into())
    }
}

impl<E: Pairing> From<&VerifyingKey<E>> for Message<E> {
    fn from(vk: &VerifyingKey<E>) -> Self {
        Self(vk.0, vk.1)
    }
}

impl<E: Pairing> Add for Message<E> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Message((self.0 + other.0).into(), (self.1 + other.1).into())
    }
}

impl<E: Pairing> Add for &Message<E> {
    type Output = Message<E>;

    fn add(self, other: Self) -> Self::Output {
        Message((self.0 + other.0).into(), (self.1 + other.1).into())
    }
}

impl<E: Pairing> Mul<E::ScalarField> for Message<E> {
    type Output = Self;

    fn mul(self, scalar: E::ScalarField) -> Self {
        Self(self.0.mul(scalar).into(), self.1.mul(scalar).into())
    }
}

impl<E: Pairing> Mul<E::ScalarField> for &Message<E> {
    type Output = Message<E>;

    fn mul(self, scalar: E::ScalarField) -> Self::Output {
        Message(self.0.mul(scalar).into(), self.1.mul(scalar).into())
    }
}
