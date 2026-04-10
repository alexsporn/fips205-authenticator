// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// This module implements an IOTA Abstract Account authenticator using FIPS 205 (SLH-DSA)
/// post-quantum digital signatures for transaction authentication.
///
/// It supports two parameter sets:
/// - SLH-DSA-SHA2-128s (small signatures, 7,856 bytes)
/// - SLH-DSA-SHA2-128f (fast verification, 17,088 bytes)
module fips205_authenticator::fips205_authenticator;

use iota::account;
use iota::authenticator_function;
use iota::dynamic_field as df;
use iota::package_metadata::PackageMetadataV1;
use std::ascii;

use fips205::slh_dsa_sha2_128s;
use fips205::slh_dsa_sha2_128f;

// === Errors ===

#[error(code = 0)]
const EPublicKeyAlreadyAttached: vector<u8> = b"Public key already attached.";
#[error(code = 1)]
const EPublicKeyMissing: vector<u8> = b"Public key missing.";
#[error(code = 2)]
const ESlhDsaSha2128sVerificationFailed: vector<u8> =
    b"SLH-DSA-SHA2-128s signature verification failed.";
#[error(code = 3)]
const ESlhDsaSha2128fVerificationFailed: vector<u8> =
    b"SLH-DSA-SHA2-128f signature verification failed.";
#[error(code = 4)]
const EInvalidPublicKeyLength: vector<u8> =
    b"Public key must be exactly 32 bytes (pk_seed || pk_root).";
#[error(code = 5)]
const EInvalidSigRForsLength: vector<u8> =
    b"sig_r_fors must be exactly 3,712 bytes (R || sig_fors).";
#[error(code = 6)]
const EInvalidSigHtLength: vector<u8> =
    b"sig_ht must be exactly 13,376 bytes (hypertree signature).";

// === Structs ===

/// The abstract account object that holds the owner's public key as a dynamic field.
public struct Fips205Account has key {
    id: UID,
}

/// A dynamic field name for the account owner's FIPS 205 public key.
public struct PublicKeyFieldName has copy, drop, store {}

// === Public Functions ===

/// Create a new FIPS 205 abstract account with the given authenticator function and public key.
public fun create(
    public_key: vector<u8>,
    package_metadata: &PackageMetadataV1,
    module_name: ascii::String,
    function_name: ascii::String,
    ctx: &mut TxContext,
): address {
    let authenticator = authenticator_function::create_auth_function_ref_v1<Fips205Account>(
        package_metadata,
        module_name,
        function_name,
    );

    let mut account = Fips205Account { id: object::new(ctx) };

    attach_public_key(&mut account.id, public_key);

    let account_address = object::id_address(&account);

    account::create_account_v1(account, authenticator);

    account_address
}

/// Create a new FIPS 205 abstract account with the SLH-DSA-SHA2-128s authenticator and the given public key.
public entry fun create_slh_dsa_sha2_128s(
    public_key: vector<u8>,
    package_metadata: &PackageMetadataV1,
    ctx: &mut TxContext,
): address {
    create(
        public_key,
        package_metadata,
        ascii::string(b"fips205_authenticator"),
        ascii::string(b"authenticate_slh_dsa_sha2_128s"),
        ctx,
    )
}

/// Create a new FIPS 205 abstract account with the SLH-DSA-SHA2-128f authenticator and the given public key.
public entry fun create_slh_dsa_sha2_128f(
    public_key: vector<u8>,
    package_metadata: &PackageMetadataV1,
    ctx: &mut TxContext,
): address {
    create(
        public_key,
        package_metadata,
        ascii::string(b"fips205_authenticator"),
        ascii::string(b"authenticate_slh_dsa_sha2_128f"),
        ctx,
    )
}

// === Public Key Management ===

/// Attach public key data to the account with the provided `public_key`.
/// The key must be exactly 32 bytes (pk_seed || pk_root).
public fun attach_public_key(account_id: &mut UID, public_key: vector<u8>) {
    assert!(!has_public_key(account_id), EPublicKeyAlreadyAttached);
    assert!(public_key.length() == slh_dsa_sha2_128s::pk_len(), EInvalidPublicKeyLength);

    df::add(account_id, PublicKeyFieldName {}, public_key)
}

/// Update the public key attached to the account.
/// The new key must be exactly 32 bytes (pk_seed || pk_root).
public fun rotate_public_key(account_id: &mut UID, public_key: vector<u8>): vector<u8> {
    assert!(has_public_key(account_id), EPublicKeyMissing);
    assert!(public_key.length() == slh_dsa_sha2_128s::pk_len(), EInvalidPublicKeyLength);

    let prev_public_key = df::remove(account_id, PublicKeyFieldName {});
    df::add(account_id, PublicKeyFieldName {}, public_key);
    prev_public_key
}

/// Detach public key data from the account.
public fun detach_public_key(account_id: &mut UID): vector<u8> {
    assert!(has_public_key(account_id), EPublicKeyMissing);

    df::remove(account_id, PublicKeyFieldName {})
}

// === View Functions ===

/// An utility function to check if the account has a public key set.
public fun has_public_key(account_id: &UID): bool {
    df::exists_(account_id, PublicKeyFieldName {})
}

/// An utility function to borrow the account-related public key.
public fun borrow_public_key(account_id: &UID): &vector<u8> {
    df::borrow(account_id, PublicKeyFieldName {})
}

// === Authenticators ===

/// SLH-DSA-SHA2-128s signature authenticator.
///
/// Verifies a FIPS 205 SLH-DSA-SHA2-128s signature over the transaction digest,
/// using the account address as the FIPS 205 context string for domain separation.
/// This binds signatures to a specific account, preventing cross-account replay.
#[authenticator]
public fun authenticate_slh_dsa_sha2_128s(
    account: &Fips205Account,
    signature: vector<u8>,
    _auth_ctx: &AuthContext,
    ctx: &TxContext,
) {
    assert!(has_public_key(&account.id), EPublicKeyMissing);
    assert!(
        slh_dsa_sha2_128s::verify_with_context(
            ctx.digest(),
            &signature,
            borrow_public_key(&account.id),
            &account.id.to_address().to_bytes(),
        ),
        ESlhDsaSha2128sVerificationFailed,
    );
}

/// SLH-DSA-SHA2-128f signature authenticator.
///
/// Verifies a FIPS 205 SLH-DSA-SHA2-128f signature over the transaction digest,
/// using the account address as the FIPS 205 context string for domain separation.
/// This binds signatures to a specific account, preventing cross-account replay.
///
/// The 17,088-byte signature is split at the natural FORS/HT boundary to stay
/// within the 16,384-byte auth-call-arg size limit without needing concatenation:
/// - `sig_r_fors`: R(16) || sig_fors(3,696) = 3,712 bytes
/// - `sig_ht`: hypertree signature = 13,376 bytes
#[authenticator]
public fun authenticate_slh_dsa_sha2_128f(
    account: &Fips205Account,
    sig_r_fors: vector<u8>,
    sig_ht: vector<u8>,
    _auth_ctx: &AuthContext,
    ctx: &TxContext,
) {
    assert!(has_public_key(&account.id), EPublicKeyMissing);
    assert!(sig_r_fors.length() == slh_dsa_sha2_128f::sig_r_fors_len(), EInvalidSigRForsLength);
    assert!(sig_ht.length() == slh_dsa_sha2_128f::sig_ht_len(), EInvalidSigHtLength);
    assert!(
        slh_dsa_sha2_128f::verify_with_context_split(
            ctx.digest(),
            &sig_r_fors,
            &sig_ht,
            borrow_public_key(&account.id),
            &account.id.to_address().to_bytes(),
        ),
        ESlhDsaSha2128fVerificationFailed,
    );
}
