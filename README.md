# Commuting Signatures and Verifiable Encryption

Rust implementation of commuting signatures, a primitive introduced in the paper [Commuting Signatures and Verifiable Encryption and an Application to Non-Interactively Delegatable Credentials](https://eprint.iacr.org/2010/233.pdf).

> a signer can encrypt both signature and message and prove validity; more importantly, given a ciphertext, a signer can create a verifiably encrypted signature on the encrypted message; thus signing and encrypting commute.

## Verifiable Encryption

The scheme uses commitment scheme as an encryption, and a zero knowledge proof to verify the committed (or encrypted) values are actually the message being signed or the signature on that message.

```rust ignore 
// public parameters
let params = Params::<E>::rand(rng);
let signer = Signer::rand(rng);
let verifier = signer.verifier(&params);

// the value being signed
let value = Fr::rand(rng);

// ciphertexts are the commitments and the ZK proofs.
let (message, signature, ciphertexts) = signer.sign(rng, &params, value);

// verify signature
assert!(verifier.verify(&params, &message, &signature));

// verify ciphertexts
assert!(verifier.verify_ciphertexts(&params, &ciphertexts));
```

## Signature on the encrypted message

```rust ignore
// Here is another signer. You can also use the same signer.
let signer2 = Signer::rand(rng);
let verifier2 = signer2.verifier(&params);

// sign on the encrypted message, output another ciphertexts that contains commitment to the signature
let ciphertexts2 = signer2.sign_on_ciphertexts(rng, &params, &ciphertexts);

// verify different ciphertexts
assert!(verifier2.verify_ciphertexts(&params, &ciphertexts2));
```
