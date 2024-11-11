#![doc = include_str!("../README.md")]

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
pub use sigcom::{sig_com, PrecommitSignature, SigCommitment};

#[cfg(test)]
mod test {
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, UniformRand};
    use proofs::{prove_message, prove_signature};

    type Fr = <E as Pairing>::ScalarField;

    use super::*;

    // Test the upper flow of commuting signatures illustrated in Figure 1 of the paper.
    #[test]
    fn test_sigcom() {
        let rng = &mut test_rng();
        let pp = Params::<E>::rand(rng);
        let (vk, sk) = automorphic_signature::key_gen(rng, &pp.pps);
        let mn = Message::new(&pp.pps, Fr::rand(rng));

        // (tau, mu, nu, rho, sigma)
        let com_randomness = CommitRandomness::rand(rng);

        // Com_M
        let mut com_m = Commitment::<E>::new(rng, &pp, &mn, com_randomness);
        assert!(com_m.verify_proofs(&pp));

        // RdCom_M (not shown in the figure)
        let com_randomness = com_randomness + com_m.randomize(rng, &pp);
        assert!(com_m.verify_proofs(&pp));

        // SigCom
        let (sig_com, proofs, pre_sig) = sig_com(rng, &pp, &sk, &com_m).unwrap();
        assert!(sig_com.verify_proofs(&pp, &vk, &com_m, &proofs));

        //
        // ... Backward checking for adapt proof algorithms ...
        //

        // get (A, B, D, R, S) and (alpha, beta, delta, rho, sigma)
        let committed_sig = pre_sig.to_precommit_signature(&pp, com_randomness);

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

    // Test the lower flow of commuting signatures illustrated in Figure 1 of the paper.
    #[test]
    fn test_sign_and_then_adpr() {
        let rng = &mut test_rng();
        let pp = Params::<E>::rand(rng);
        let (vk, sk) = automorphic_signature::key_gen(rng, &pp.pps);
        let mn = Message::new(&pp.pps, Fr::rand(rng));

        // (tau, mu, nu, rho, sigma)
        let com_randomness = CommitRandomness::rand(rng);
        // (alpha, beta, delta, rho, sigma)
        let sig_randomness = SigRandomness::rand(rng);

        // Sign
        let sig = sk.sign(rng, &pp.pps, &mn);

        // ComM, Prove
        let c = Commitment::new(rng, &pp, &mn, com_randomness);
        let pi_a_bar = prove_message(rng, &pp, &mn, com_randomness);

        let precommit_sig = PrecommitSignature {
            signature: sig,
            randomness: sig_randomness,
        };

        // AdPrC
        let pi_1 =
            AdaptProof::committing_signature(rng, &pp, &vk, &c, &precommit_sig, &pi_a_bar).unwrap();

        // Com, Prove
        let sig_com = precommit_sig.commit(&pp);
        let pi_tide = prove_signature(rng, &pp, &vk, &precommit_sig);

        // AdPrC_M
        let pi_2 =
            AdaptProof::committing_message(rng, &pp, &vk, &mn, com_randomness, &sig_com, &pi_tide)
                .unwrap();

        // Both proofs generated from different paths should be valid.
        assert!(sig_com.verify_proofs(&pp, &vk, &c, &pi_1.into()));
        assert!(sig_com.verify_proofs(&pp, &vk, &c, &pi_2.into()));
    }
}
