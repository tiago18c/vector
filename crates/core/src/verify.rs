//! Check a signature offline with the program's own code: the account is
//! initialized and advanced as on chain, so the check cannot disagree with
//! the program.

use core::mem::size_of;

use pinocchio::error::ProgramError;
use solana_address::Address;
use solana_instruction::Instruction;
use vector::error::VectorError;
use vector::scheme::SigningScheme;
use vector::schemes::{
    ed25519::Ed25519, eip191::Eip191, falcon512::Falcon512, mldsa44::MlDsa44, secp256k1::Secp256k1,
    winternitz::Winternitz, xmss::Xmss,
};

use crate::digest::advance_message;
use crate::instructions::AdvanceSigner;
use crate::scheme::{find_vector_pda, Scheme, VectorAccount};

/// Why an offline check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The identity is not a key of its scheme: `initialize` refuses it.
    InvalidIdentity,
    /// The signature is not one the scheme can read.
    MalformedSignature,
    /// The signature does not verify over the recomputed digest.
    SignatureInvalid,
    /// Winternitz and XMSS: the signature covers a next key, which
    /// [`verify_advance_signature`] does not take. Check them with
    /// [`verify_signature`] over a
    /// [`rotating_advance_vector_digest`](crate::rotating_advance_vector_digest).
    RotatingKey,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            VerifyError::InvalidIdentity => "the identity is not a key of its scheme",
            VerifyError::MalformedSignature => "the signature is not one its scheme can read",
            VerifyError::SignatureInvalid => {
                "the signature does not verify over the recomputed advance digest: the signed \
                 payload differs from this instruction layout, nonce, or identity"
            }
            VerifyError::RotatingKey => {
                "Winternitz and XMSS advances cover a next key: check them with verify_signature"
            }
        })
    }
}

impl std::error::Error for VerifyError {}

/// Verify an advance signature: recompute the digest and check `signature`
/// over it, as the program would for a new account. Returns the digest,
/// which is the account's next nonce.
///
/// `fee_payer` is as in [`advance_vector_digest`](crate::advance_vector_digest).
pub fn verify_advance_signature(
    scheme: &Scheme,
    identity: &[u8],
    nonce: &[u8; 32],
    pre_instructions: &[Instruction],
    post_instructions: &[Instruction],
    fee_payer: Option<&Address>,
    signature: &[u8],
) -> Result<[u8; 32], VerifyError> {
    if scheme.next_key_len != 0 {
        return Err(VerifyError::RotatingKey);
    }
    if identity.len() != scheme.identity_len {
        return Err(VerifyError::InvalidIdentity);
    }
    if signature.len() != scheme.signature_len {
        return Err(VerifyError::MalformedSignature);
    }

    // The account as on chain: 8-byte aligned, the identity after the
    // header. Falcon-512 and ML-DSA-44 read their prepared key in place.
    let mut account = vec![0u64; scheme.account_len.div_ceil(8)];
    // SAFETY: any `u64` buffer is a valid byte buffer of 8 times its length.
    let account = unsafe {
        core::slice::from_raw_parts_mut(account.as_mut_ptr().cast::<u8>(), scheme.account_len)
    };
    let stored = &mut account[VectorAccount::HEADER_LEN..];
    (scheme.initialize)(identity, stored).map_err(|_| VerifyError::InvalidIdentity)?;

    let message = advance_message(
        &[AdvanceSigner::new(scheme, identity)],
        pre_instructions,
        post_instructions,
        fee_payer,
    );
    let (vector, _) = find_vector_pda(scheme, identity);
    let mut nonce = *nonce;
    (scheme.advance)(
        stored,
        &mut nonce,
        &message,
        vector.as_array(),
        &mut &signature[..],
    )
    .map_err(|error| match error {
        pinocchio::error::ProgramError::MissingRequiredSignature => VerifyError::SignatureInvalid,
        _ => VerifyError::MalformedSignature,
    })?;
    Ok(nonce)
}

/// Verify `signature` over a digest the caller already has, for every
/// scheme, with the scheme's own `advance` on a new account.
///
/// `identity` is the key the scheme checks. For Winternitz and XMSS that is
/// the account's current key, which a rotation can move off the key the
/// account was created with.
///
/// Nothing is recorded. The program spends a Winternitz key by replacing it
/// and an XMSS leaf by moving `next_leaf`; here a spent key still verifies,
/// and so does any leaf of the tree.
pub fn verify_signature(
    scheme: &Scheme,
    identity: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), VerifyError> {
    if identity.len() != scheme.identity_len {
        return Err(VerifyError::InvalidIdentity);
    }
    if signature.len() != scheme.signature_len {
        return Err(VerifyError::MalformedSignature);
    }

    match scheme.id {
        Ed25519::ID => check::<Ed25519>(scheme, identity, digest, signature),
        Eip191::ID => check::<Eip191>(scheme, identity, digest, signature),
        Secp256k1::ID => check::<Secp256k1>(scheme, identity, digest, signature),
        Falcon512::ID => check::<Falcon512>(scheme, identity, digest, signature),
        MlDsa44::ID => check::<MlDsa44>(scheme, identity, digest, signature),
        Winternitz::ID => check::<Winternitz>(scheme, identity, digest, signature),
        Xmss::ID => check::<Xmss>(scheme, identity, digest, signature),
        _ => Err(VerifyError::InvalidIdentity),
    }
}

/// [`verify_signature`] for one scheme. The lengths are checked.
fn check<T: SigningScheme>(
    scheme: &Scheme,
    identity: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), VerifyError> {
    // The stored identity as on chain, 8-byte aligned.
    let mut stored = vec![0u64; size_of::<T>().div_ceil(8)];
    // SAFETY: any `u64` buffer is a valid byte buffer of 8 times its length.
    let stored = unsafe {
        core::slice::from_raw_parts_mut(stored.as_mut_ptr().cast::<u8>(), size_of::<T>())
    };
    (scheme.initialize)(identity, stored).map_err(|_| VerifyError::InvalidIdentity)?;

    // SAFETY: `SigningScheme` promises `T`, `T::Signature` and `T::NextKey`
    // are plain bytes of alignment 1, and the lengths are theirs.
    let (account, signature, next_key) = unsafe {
        (
            &mut *stored.as_mut_ptr().cast::<T>(),
            &*signature.as_ptr().cast::<T::Signature>(),
            core::mem::zeroed::<T::NextKey>(),
        )
    };
    // A zeroed next key replaces a Winternitz or XMSS key, so a valid
    // signature never trips over the tree running out. Winternitz refuses
    // it only for an all-zero key, after the signature verified.
    match account.advance(digest, signature, &next_key) {
        Ok(()) => Ok(()),
        Err(error) if error == VectorError::KeyReused.into() => Ok(()),
        Err(ProgramError::MissingRequiredSignature) => Err(VerifyError::SignatureInvalid),
        Err(_) => Err(VerifyError::MalformedSignature),
    }
}
