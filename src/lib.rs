pub mod automorphic_signature;
pub use automorphic_signature::message::Message;

pub mod proofs;

pub mod commit;
pub use commit::Commitment;

pub(crate) mod equations;

pub mod params;
pub use params::Params;

mod randomness;
pub use randomness::{CommitRandomness, SigRandomness};

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

        let mn = Message::new(&pp.pps, Fr::rand(rng));
        let commit_randomness = CommitRandomness::rand(rng);
        let mut com_m = Commitment::<E>::new(rng, &pp, &mn, commit_randomness);
        assert!(com_m.verify_proofs(&pp));

        com_m.randomize(rng, &pp);
        assert!(com_m.verify_proofs(&pp));

        let (vk, sk) = automorphic_signature::key_gen(rng, &pp.pps);
        let sig_randomness = SigRandomness::rand(rng);
        let (sig_com, proofs) =
            SigCommitment::<E>::new_with_proofs(rng, &pp, &sk, &com_m, sig_randomness).unwrap();
        assert!(sig_com.verify_proofs(&pp, &vk, &com_m, &proofs));
    }
}
