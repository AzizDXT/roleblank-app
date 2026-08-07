//! Cryptographic building blocks.
//!
//! Every primitive here comes from the audited RustCrypto stack. The only
//! construction written locally is RFC 6238 TOTP, which is validated against the
//! standard's own published test vectors — see `totp` and ADR-002.
pub mod aead;
pub mod password;
pub mod tokens;
pub mod totp;
