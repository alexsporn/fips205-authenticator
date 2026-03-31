# FIPS 205 Authenticator for IOTA

A post-quantum [IOTA Account Abstraction (AA)](https://docs.iota.org/developer/account-abstraction/) authenticator using [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final) for transaction authentication, along with a companion Rust CLI for key management and signing.

## Overview

This project provides two components:

1. **Move Authenticator** (`sources/`) — An on-chain IOTA AA module that verifies SLH-DSA signatures against the transaction digest.
2. **Rust CLI** (`cli/`) — An off-chain tool for generating keypairs and signing transaction digests.

### Supported Parameter Sets

| Parameter Set | Signature Size | Description |
|---|---|---|
| SLH-DSA-SHA2-128s | 7,856 bytes | Smaller signatures, more computation |
| SLH-DSA-SHA2-128f | 17,088 bytes | Larger signatures, faster verification |

Both use 32-byte public keys and SHA2-based hashing.

## Move Authenticator

### Dependencies

- [IOTA Framework](https://github.com/iotaledger/iota) (Account Abstraction APIs)
- [fips205-move](https://github.com/alexsporn/fips205-move) (On-chain SLH-DSA verification)

### Build

```bash
iota move build
```

### Module: `fips205_authenticator::fips205_authenticator`

#### Structs

- **`Fips205Account`** — A `key` object representing the abstract account. Stores the owner's FIPS 205 public key as a dynamic field.
- **`PublicKeyFieldName`** — Dynamic field name marker for the public key.

#### Account Creation

- **`create(public_key, package_metadata, module_name, function_name, ctx) -> address`**
  Creates a new abstract account with the specified authenticator function and public key. Returns the account address.

- **`create_slh_dsa_sha2_128s(public_key, package_metadata, ctx) -> address`**
  Entry function helper that creates an account with the SLH-DSA-SHA2-128s authenticator.

- **`create_slh_dsa_sha2_128f(public_key, package_metadata, ctx) -> address`**
  Entry function helper that creates an account with the SLH-DSA-SHA2-128f authenticator.

#### Public Key Management

- **`attach_public_key(account_id, public_key)`**
  Attaches a public key to an account. Aborts if a key is already attached.

- **`rotate_public_key(account_id, public_key) -> vector<u8>`**
  Replaces the public key on an account. Returns the previous key. Aborts if no key is attached.

- **`detach_public_key(account_id) -> vector<u8>`**
  Removes and returns the public key from an account. Aborts if no key is attached.

- **`has_public_key(account_id) -> bool`**
  Returns whether a public key is attached to the account.

- **`borrow_public_key(account_id) -> &vector<u8>`**
  Returns a reference to the stored public key.

#### Authenticators

- **`authenticate_slh_dsa_sha2_128s(account, signature, auth_ctx, ctx)`**
  Verifies an SLH-DSA-SHA2-128s signature over the transaction digest (`ctx.digest()`), using the account address as the FIPS 205 context string.

- **`authenticate_slh_dsa_sha2_128f(account, signature, auth_ctx, ctx)`**
  Verifies an SLH-DSA-SHA2-128f signature over the transaction digest (`ctx.digest()`), using the account address as the FIPS 205 context string.

Both authenticator functions are marked with `#[authenticator]` and abort with a descriptive error if verification fails. The account address is used as the FIPS 205 context string for domain separation, which binds each signature to a specific account and prevents cross-account replay attacks.

### Usage

To create an account using the entry function helper:

```move
use fips205_authenticator::fips205_authenticator;

// Using the entry helper (recommended)
let account_address = fips205_authenticator::create_slh_dsa_sha2_128s(
    public_key_bytes,
    &package_metadata,
    ctx,
);

// Or using the generic create function
let account_address = fips205_authenticator::create(
    public_key_bytes,
    &package_metadata,
    ascii::string(b"fips205_authenticator"),
    ascii::string(b"authenticate_slh_dsa_sha2_128s"),
    ctx,
);
```

## Rust CLI

A companion tool for off-chain key generation, signing, and verification.

### Build

```bash
cd cli
cargo build --release
```

### Commands

#### `keygen` — Generate a new SLH-DSA keypair

```bash
fips205-cli keygen -p 128s -o ./keys
```

| Flag | Description | Default |
|---|---|---|
| `-p, --param` | Parameter set (`128s` or `128f`) | `128s` |
| `-o, --output` | Output directory for key files | `.` |

Generates `public_key.bin` and `secret_key.bin` in the output directory, and prints the hex-encoded public key.

#### `sign` — Sign a transaction digest

```bash
fips205-cli sign -d <tx-digest-hex> -s ./keys/secret_key.bin -a <account-address-hex> -p 128s
```

| Flag | Description | Default |
|---|---|---|
| `-d, --digest` | Hex-encoded transaction digest (32 bytes, optional `0x` prefix) | required |
| `-s, --secret-key` | Path to secret key file | required |
| `-a, --address` | Hex-encoded account address (32 bytes) used as FIPS 205 context | required |
| `-p, --param` | Parameter set (`128s` or `128f`) | `128s` |

Outputs the hex-encoded signature to stdout.

#### `verify` — Verify a signature locally

```bash
fips205-cli verify -d <tx-digest-hex> --signature <sig-hex> -k ./keys/public_key.bin -a <account-address-hex> -p 128s
```

| Flag | Description | Default |
|---|---|---|
| `-d, --digest` | Hex-encoded transaction digest (32 bytes, optional `0x` prefix) | required |
| `--signature` | Hex-encoded signature | required |
| `-k, --public-key` | Path to public key file | required |
| `-a, --address` | Hex-encoded account address (32 bytes) used as FIPS 205 context | required |
| `-p, --param` | Parameter set (`128s` or `128f`) | `128s` |

Prints `Signature is VALID` on success, or `Signature is INVALID` and exits with code 1 on failure.

### End-to-End Example

```bash
# Generate a keypair
fips205-cli keygen -p 128s -o ./keys

# Create the account on-chain (returns the account address)
# ACCOUNT_ADDR=0x...

# Sign a transaction digest with the account address as context
SIG=$(fips205-cli sign -d 0x<tx-digest> -s ./keys/secret_key.bin -a $ACCOUNT_ADDR)

# Verify locally
fips205-cli verify -d 0x<tx-digest> --signature "$SIG" -k ./keys/public_key.bin -a $ACCOUNT_ADDR
```

The hex-encoded public key from `keygen` is what you pass as `public_key` when calling `fips205_authenticator::create` on-chain. The hex-encoded signature from `sign` is what you provide as the `signature` argument in the authenticator transaction.

## Compatibility

The account address (32 bytes) is used as the FIPS 205 context string for domain separation, binding each signature to a specific account. Both the CLI and the Move authenticator use `verify_with_context` with the account address bytes. The FIPS 205 "pure" message wrapping is: `M' = 0x00 || len(ctx) || ctx || msg`.

## License

Apache-2.0
