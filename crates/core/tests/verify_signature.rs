//! `verify_signature`: one signature over a digest the caller already has,
//! checked with the program's own scheme code.

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as Secp256k1SigningKey};
use sha2::{Digest as _, Sha256};
use vector_core::{
    ed25519_pubkey, secp256k1_compressed_pubkey, signed, verify_signature, VerifyError, ED25519,
    SECP256K1, WINTERNITZ, XMSS,
};

const DIGEST: [u8; 32] = [0x5a; 32];

/// A deterministic stream for key generation and salts: SHA-256 of a
/// counter. Tests need no secrecy, only bytes that vary.
fn stream(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), solana_winternitz::SigningError> {
    let mut counter = 0u64;
    move |buf| {
        for chunk in buf.chunks_mut(32) {
            let block = Sha256::new()
                .chain_update([seed])
                .chain_update(counter.to_le_bytes())
                .finalize();
            counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

#[test]
fn ed25519_signs_the_prefixed_digest() {
    let key = Ed25519SigningKey::from_bytes(&[0x42; 32]);
    let identity = ed25519_pubkey(&key);
    let signature = key.sign(&signed(&DIGEST)).to_bytes();
    assert_eq!(
        verify_signature(&ED25519, &identity, &DIGEST, &signature),
        Ok(())
    );

    // The bare digest, as before the prefix, is not an authorization.
    let bare = key.sign(&DIGEST).to_bytes();
    assert_eq!(
        verify_signature(&ED25519, &identity, &DIGEST, &bare),
        Err(VerifyError::SignatureInvalid)
    );
    assert_eq!(
        verify_signature(&ED25519, &identity, &[0x5b; 32], &signature),
        Err(VerifyError::SignatureInvalid)
    );
}

#[test]
fn secp256k1_signs_the_sha256_of_the_prefixed_digest() {
    let key = Secp256k1SigningKey::from_bytes((&[0x07; 32]).into()).unwrap();
    let identity = secp256k1_compressed_pubkey(&key);
    let (signature, _) = key.sign_prehash(&Sha256::digest(signed(&DIGEST))).unwrap();
    let signature: [u8; 64] = signature.to_bytes().into();
    assert_eq!(
        verify_signature(&SECP256K1, &identity, &DIGEST, &signature),
        Ok(())
    );
    assert_eq!(
        verify_signature(&SECP256K1, &identity, &[0; 32], &signature),
        Err(VerifyError::SignatureInvalid)
    );
}

#[test]
fn winternitz_and_xmss_sign_the_sha256_of_the_prefixed_digest() {
    let message: [u8; 32] = Sha256::digest(signed(&DIGEST)).into();

    let one_time = solana_winternitz::hazmat::SecretKey::generate(stream(1)).unwrap();
    let key = one_time.verifying_key();
    let signature = one_time.sign_at(0, &message, stream(2)).unwrap();
    assert_eq!(
        verify_signature(&WINTERNITZ, key.as_ref(), &DIGEST, signature.as_ref()),
        Ok(())
    );
    assert_eq!(
        verify_signature(&WINTERNITZ, key.as_ref(), &[1; 32], signature.as_ref()),
        Err(VerifyError::SignatureInvalid)
    );

    let tree = solana_xmss::hazmat::SecretKey::generate(stream(3)).unwrap();
    let key = tree.verifying_key();
    // Any leaf of the tree verifies: nothing is recorded.
    for leaf in [0, 17, 255] {
        let signature = tree
            .sign_at(leaf, &message, stream((leaf % 200) as u8 + 4))
            .unwrap();
        assert_eq!(
            verify_signature(&XMSS, key.as_ref(), &DIGEST, signature.as_ref()),
            Ok(())
        );
    }
}

#[test]
fn lengths_are_checked_first() {
    assert_eq!(
        verify_signature(&ED25519, &[0; 31], &DIGEST, &[0; 64]),
        Err(VerifyError::InvalidIdentity)
    );
    let key = ed25519_pubkey(&Ed25519SigningKey::from_bytes(&[0x42; 32]));
    assert_eq!(
        verify_signature(&ED25519, &key, &DIGEST, &[0; 63]),
        Err(VerifyError::MalformedSignature)
    );
}
