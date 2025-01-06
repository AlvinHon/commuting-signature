//! Defines the [Message] struct for the automorphic signatures.

use super::{DHGenerators, VerifyingKey};
use ark_ec::pairing::Pairing;
use std::ops::{Add, Mul};

/// Represents a message in the automorphic signatures.
#[derive(Clone, Debug)]
pub struct Message<E: Pairing>(pub(crate) <E as Pairing>::G1, pub(crate) <E as Pairing>::G2);

impl<E: Pairing> Message<E> {
    pub fn new<G: DHGenerators<E>>(grs: &G, m: E::ScalarField) -> Self {
        Self(grs.g().mul(m), grs.h().mul(m))
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
        Message(self.0 + other.0, self.1 + other.1)
    }
}

impl<E: Pairing> Add for &Message<E> {
    type Output = Message<E>;

    fn add(self, other: Self) -> Self::Output {
        Message(self.0 + other.0, self.1 + other.1)
    }
}

impl<E: Pairing> Mul<E::ScalarField> for Message<E> {
    type Output = Self;

    fn mul(self, scalar: E::ScalarField) -> Self {
        Self(self.0.mul(scalar), self.1.mul(scalar))
    }
}

impl<E: Pairing> Mul<E::ScalarField> for &Message<E> {
    type Output = Message<E>;

    fn mul(self, scalar: E::ScalarField) -> Self::Output {
        Message(self.0.mul(scalar), self.1.mul(scalar))
    }
}
