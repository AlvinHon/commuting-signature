pub mod message;
pub use message::Message;

pub mod params;
pub use params::{DHGenerators, Params, ParamsEx};

pub mod sign;
pub use sign::SigningKey;

pub mod verify;
pub use verify::VerifyingKey;

pub mod signature;
pub use signature::{Signature, SignatureEx, Signatures};

use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};

pub fn key_gen<E: Pairing, R: Rng, G: DHGenerators<E>>(
    rng: &mut R,
    grs: &G,
) -> (VerifyingKey<E>, SigningKey<E>) {
    let x = E::ScalarField::rand(rng);
    let signing_key = SigningKey { x };
    let verifying_key = signing_key.verifying_key(grs);
    (verifying_key, signing_key)
}
