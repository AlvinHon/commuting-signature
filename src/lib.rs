pub mod automorphic_signature;
pub use automorphic_signature::message::Message;

pub mod proofs;
pub use proofs::{AdaptProof, Proofs};

pub mod commit;
pub use commit::Commitment;

pub(crate) mod equations;

pub mod params;
pub use params::Params;

mod randomness;
pub use randomness::{CommitRandomness, SigRandomness};

pub mod sigcom;
pub use sigcom::{sig_com, CommittedSignature, SigCommitment};

#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, UniformRand};

    type Fr = <E as Pairing>::ScalarField;

    use super::*;

    #[test]
    fn test_csve_system() {
        let rng = &mut test_rng();
        let pp = Params::<E>::rand(rng);
        let (vk, sk) = automorphic_signature::key_gen(rng, &pp.pps);
        let mn = Message::new(&pp.pps, Fr::rand(rng));

        // (tau, mu, nu, rho, sigma)
        let com_randomness = CommitRandomness::rand(rng);

        // Com_M
        let mut com_m = Commitment::<E>::new(rng, &pp, &mn, com_randomness);
        assert!(com_m.verify_proofs(&pp));

        // RdCom_M
        let com_randomness = com_randomness + com_m.randomize(rng, &pp);
        assert!(com_m.verify_proofs(&pp));

        // SigCom
        let (sig_com, proofs, pre_sig) = sig_com(rng, &pp, &sk, &com_m).unwrap();
        assert!(sig_com.verify_proofs(&pp, &vk, &com_m, &proofs));

        // get (A, B, D, R, S) and (alpha, beta, delta, rho, sigma)
        let committed_sig = pre_sig.to_committed_signature(&pp, com_randomness);

        // AdPrDC_M
        let pi_tide =
            AdaptProof::decommitting_message(rng, &pp, &vk, &mn, com_randomness, &sig_com, &proofs)
                .unwrap();

        // AdPrC_M
        let pi = AdaptProof::committing_message(
            rng,
            &pp,
            &vk,
            &mn,
            com_randomness,
            &sig_com,
            &pi_tide.into(),
        )
        .unwrap();

        // AdPrDC
        let pi_a_bar =
            AdaptProof::decommitting_signature(rng, &pp, &vk, &com_m, &committed_sig, &pi.into())
                .unwrap();

        // AdPrC
        let pi = AdaptProof::committing_signature(rng, &pp, &vk, &com_m, &committed_sig, &pi_a_bar)
            .unwrap();

        // pi is a proof that com_m contains a commitment to a message s.t. E_a, E_b, E_r
        assert!(sig_com.verify_proofs(&pp, &vk, &com_m, &pi.into()));
    }
}
