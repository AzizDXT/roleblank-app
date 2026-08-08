//! Authenticated encryption for secrets that must be recoverable — currently only
//! TOTP shared secrets.
//!
//! XChaCha20-Poly1305 from the RustCrypto stack. Chosen over AES-GCM because its
//! 192-bit nonce makes random nonce generation safe without a counter: with a
//! 96-bit GCM nonce, birthday-bound collisions become a real concern at scale and
//! a nonce reuse in a counter-mode cipher is catastrophic (it leaks the XOR of two
//! plaintexts and breaks the authenticator). A 192-bit random nonce removes that
//! failure mode from the design rather than managing it.
//!
//! Every ciphertext stores a `key_version` alongside it so the master key can be
//! rotated without eagerly re-encrypting every row (ADR-002).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::collections::HashMap;

use crate::platform::crypto::tokens;
use crate::platform::errors::AppError;
use crate::shared::secret::Secret;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;

/// A versioned set of master keys.
///
/// Rotation procedure: add the new key with a higher version and set it as
/// `current`; keep the previous versions available for decryption until a
/// background pass has re-encrypted everything. Removing a version before that
/// makes the affected rows permanently unreadable, so `decrypt` reports an unknown
/// version distinctly rather than as a generic failure.
pub struct KeyRing {
    keys: HashMap<u32, Secret<Vec<u8>>>,
    current_version: u32,
}

/// A ciphertext together with everything needed to decrypt it later.
#[derive(Debug, Clone)]
pub struct SealedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: u32,
}

impl KeyRing {
    pub fn new(current_version: u32, current_key: Secret<Vec<u8>>) -> Result<Self, AppError> {
        if current_key.expose().len() != KEY_BYTES {
            return Err(AppError::Internal(format!(
                "encryption key must be exactly {KEY_BYTES} bytes, got {}",
                current_key.expose().len()
            )));
        }
        if current_version == 0 {
            return Err(AppError::Internal(
                "encryption key version must be >= 1".into(),
            ));
        }
        let mut keys = HashMap::new();
        keys.insert(current_version, current_key);
        Ok(Self {
            keys,
            current_version,
        })
    }

    /// Register a retired key so existing ciphertexts stay readable during rotation.
    pub fn with_previous(mut self, version: u32, key: Secret<Vec<u8>>) -> Result<Self, AppError> {
        if key.expose().len() != KEY_BYTES {
            return Err(AppError::Internal(
                "previous encryption key has the wrong length".into(),
            ));
        }
        self.keys.insert(version, key);
        Ok(self)
    }

    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    fn cipher_for(&self, version: u32) -> Result<XChaCha20Poly1305, AppError> {
        let key = self.keys.get(&version).ok_or_else(|| {
            // Distinct from a decryption failure: this is an operational error
            // (a key was removed too early), not a tampering signal.
            AppError::Internal(format!(
                "no encryption key registered for version {version}"
            ))
        })?;
        Ok(XChaCha20Poly1305::new(Key::from_slice(key.expose())))
    }

    /// Encrypt with the current key.
    ///
    /// `associated_data` is authenticated but not encrypted. Passing the owning
    /// user's id binds the ciphertext to that row: an attacker with UPDATE on
    /// `mfa_factors` cannot move Alice's encrypted TOTP secret onto Bob's record
    /// and have it decrypt, because the AAD would no longer match.
    pub fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<SealedSecret, AppError> {
        let nonce_bytes = tokens::random_bytes(NONCE_BYTES)?;
        let cipher = self.cipher_for(self.current_version)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| AppError::Internal("AEAD sealing failed".into()))?;
        Ok(SealedSecret {
            ciphertext,
            nonce: nonce_bytes,
            key_version: self.current_version,
        })
    }

    /// Decrypt and verify. A failure here means either tampering or a wrong AAD;
    /// the caller must treat it as a security event, never as "try again".
    pub fn open(
        &self,
        sealed: &SealedSecret,
        associated_data: &[u8],
    ) -> Result<Secret<Vec<u8>>, AppError> {
        if sealed.nonce.len() != NONCE_BYTES {
            return Err(AppError::Internal(
                "stored nonce has the wrong length".into(),
            ));
        }
        let cipher = self.cipher_for(sealed.key_version)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| {
                // No detail: distinguishing "wrong key" from "modified ciphertext"
                // from "wrong AAD" would be an oracle.
                AppError::Internal("AEAD verification failed".into())
            })?;
        Ok(Secret::new(plaintext))
    }
}

/// Parse a base64 (standard alphabet, padded or not) master key from configuration.
pub fn parse_key(encoded: &str) -> Result<Secret<Vec<u8>>, String> {
    let trimmed = encoded.trim();
    let decoded = data_encoding::BASE64
        .decode(trimmed.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(trimmed.as_bytes()))
        .map_err(|_| "value is not valid base64".to_string())?;
    if decoded.len() != KEY_BYTES {
        return Err(format!(
            "decoded key is {} bytes, expected {KEY_BYTES}",
            decoded.len()
        ));
    }
    Ok(Secret::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> KeyRing {
        KeyRing::new(1, Secret::new(vec![7u8; KEY_BYTES])).expect("keyring")
    }

    #[test]
    fn seal_then_open_round_trips() {
        let r = ring();
        let secret = b"JBSWY3DPEHPK3PXP";
        let sealed = r.seal(secret, b"user-1").expect("seal");
        assert_eq!(sealed.key_version, 1);
        assert_eq!(sealed.nonce.len(), NONCE_BYTES);
        assert_ne!(sealed.ciphertext.as_slice(), secret.as_slice());
        let opened = r.open(&sealed, b"user-1").expect("open");
        assert_eq!(opened.expose().as_slice(), secret.as_slice());
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let r = ring();
        let a = r.seal(b"same plaintext", b"aad").unwrap();
        let b = r.seal(b"same plaintext", b"aad").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    /// The control that stops an attacker moving one user's encrypted TOTP secret
    /// onto another user's row.
    #[test]
    fn wrong_associated_data_fails_verification() {
        let r = ring();
        let sealed = r.seal(b"secret", b"user-1").unwrap();
        assert!(r.open(&sealed, b"user-2").is_err());
        assert!(r.open(&sealed, b"").is_err());
    }

    #[test]
    fn modified_ciphertext_fails_verification() {
        let r = ring();
        let mut sealed = r.seal(b"secret", b"user-1").unwrap();
        sealed.ciphertext[0] ^= 0xFF;
        assert!(r.open(&sealed, b"user-1").is_err());
    }

    #[test]
    fn modified_nonce_fails_verification() {
        let r = ring();
        let mut sealed = r.seal(b"secret", b"user-1").unwrap();
        sealed.nonce[0] ^= 0xFF;
        assert!(r.open(&sealed, b"user-1").is_err());
    }

    #[test]
    fn a_different_key_cannot_decrypt() {
        let a = ring();
        let b = KeyRing::new(1, Secret::new(vec![9u8; KEY_BYTES])).unwrap();
        let sealed = a.seal(b"secret", b"aad").unwrap();
        assert!(b.open(&sealed, b"aad").is_err());
    }

    #[test]
    fn rotation_keeps_old_ciphertexts_readable() {
        let old = KeyRing::new(1, Secret::new(vec![1u8; KEY_BYTES])).unwrap();
        let sealed_with_v1 = old.seal(b"secret", b"aad").unwrap();

        let rotated = KeyRing::new(2, Secret::new(vec![2u8; KEY_BYTES]))
            .unwrap()
            .with_previous(1, Secret::new(vec![1u8; KEY_BYTES]))
            .unwrap();

        // Old ciphertext still opens under its recorded version...
        assert_eq!(
            rotated
                .open(&sealed_with_v1, b"aad")
                .unwrap()
                .expose()
                .as_slice(),
            b"secret"
        );
        // ...and new writes use the new version.
        assert_eq!(rotated.seal(b"x", b"aad").unwrap().key_version, 2);
    }

    #[test]
    fn a_missing_key_version_is_reported_distinctly() {
        let r = ring();
        let sealed = SealedSecret {
            ciphertext: vec![0; 32],
            nonce: vec![0; NONCE_BYTES],
            key_version: 99,
        };
        let err = r.open(&sealed, b"aad").unwrap_err();
        assert!(format!("{err}").contains("no encryption key registered"));
    }

    #[test]
    fn key_parsing_enforces_length() {
        let good = data_encoding::BASE64.encode(&[3u8; KEY_BYTES]);
        assert!(parse_key(&good).is_ok());
        assert!(parse_key(&data_encoding::BASE64.encode(&[3u8; 16])).is_err());
        assert!(parse_key("not base64 !!!").is_err());
        // Whitespace from a copy-pasted secret is tolerated.
        assert!(parse_key(&format!("  {good}\n")).is_ok());
    }

    #[test]
    fn keyring_rejects_a_wrong_length_key() {
        assert!(KeyRing::new(1, Secret::new(vec![0u8; 16])).is_err());
        assert!(KeyRing::new(0, Secret::new(vec![0u8; KEY_BYTES])).is_err());
    }
}
