pub mod automorphic_signature;
pub use automorphic_signature::message::Message;

pub mod commit;
pub use commit::Commitment;

pub mod params;
pub use params::Params;

pub mod sigcom;
pub use sigcom::SigCommitment;

#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, UniformRand};

    // type G1Affine = <E as Pairing>::G1Affine;
    type Fr = <E as Pairing>::ScalarField;

    use super::*;

    #[test]
    fn debug() {
        let rng = &mut test_rng();
        let pp = Params::<E>::rand(rng);

        let m = Message::new(&pp.pps, Fr::rand(rng));
        let com_m = Commitment::<E>::new(rng, &pp, &m);
        assert!(com_m.verify_proofs(&pp));

        let com_m = com_m.randomize(rng, &pp);
        assert!(com_m.verify_proofs(&pp));

        let (_vk, sk) = automorphic_signature::key_gen(rng, &pp.pps);
        SigCommitment::<E>::new(rng, pp, &sk, &com_m);
    }
}
