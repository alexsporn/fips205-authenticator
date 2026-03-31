# FIPS 205 Authenticator

## Project Structure

- `sources/fips205_authenticator.move` — IOTA Move AA authenticator module
- `cli/` — Rust CLI for key generation and signing (`cargo build` from `cli/`)
- `Move.toml` — Move package config (depends on IOTA framework + fips205-move)
- `cli/Cargo.toml` — Rust CLI dependencies (fips205 0.4.1, clap, hex)

## Build Commands

- Move: `iota move build`
- CLI: `cd cli && cargo build --release`

## Key Design Decisions

- The Move authenticator verifies signatures against `ctx.digest()` (the transaction digest), following the standard IOTA AA pattern.
- The account address (32 bytes) is used as the FIPS 205 context string via `verify_with_context`, binding signatures to a specific account and preventing cross-account replay.
- Public key management follows the IOTA AA pattern: `attach_public_key`, `rotate_public_key`, `detach_public_key`, `has_public_key`, `borrow_public_key` operate on `&UID`/`&mut UID`.
- Authenticators assert `has_public_key` before verifying, producing a clear error if the key is missing.
- The CLI signs with the account address as context and deterministic mode (`hedged: false`).
- FIPS 205 "pure" message wrapping is handled internally by both the Rust crate and the Move library: `M' = 0x00 || len(ctx) || ctx || msg`.
- The IOTA framework dependency is pinned to commit `b1b37ed9d5ff64cbbfb3aa1ebd9b9431a0337311` to match fips205-move's pinned version.

## Dependencies

- [fips205-move](https://github.com/alexsporn/fips205-move) — On-chain SLH-DSA verification in Move
- [fips205 crate](https://crates.io/crates/fips205) v0.4.1 — Rust FIPS 205 implementation (uses `PrivateKey`, not `SecretKey`)
- IOTA framework AA APIs: `iota::account`, `iota::authenticator_function`, `AuthContext`
