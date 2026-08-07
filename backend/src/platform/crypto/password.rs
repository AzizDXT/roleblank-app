//! Argon2id password hashing, with a bounded amount of concurrent work.
//!
//! Two things have to be true at once:
//!   * hashing must be expensive enough that an offline attacker with the database
//!     gains little (OWASP password-storage guidance), and
//!   * hashing must not be so expensive that a login flood turns our own KDF into
//!     an amplification weapon against us (TH-34).
//!
//! The second is why `Hasher` owns a semaphore. Argon2id at 19 MiB × 24 concurrent
//! logins is 456 MiB of resident memory doing nothing but rejecting an attacker.
//! The semaphore caps that; the rate limiter in front of the endpoint keeps the
//! queue from growing.

use argon2::{Algorithm, Argon2, Params, Version};
use data_encoding::BASE64_NOPAD;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::platform::crypto::tokens;
use crate::platform::errors::AppError;
use crate::shared::secret::Secret;

/// Argon2id cost parameters. Defaults meet current OWASP guidance and were
/// benchmarked on the target hardware rather than copied — see
/// `docs/backend/PERFORMANCE_REPORT.md`.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Argon2Params {
    /// Refuse configurations that are meaningfully weaker than current guidance.
    /// A misconfigured work factor is a silent, permanent downgrade of every
    /// password in the database, so it fails startup rather than logging a warning.
    pub fn validate(&self) -> Result<(), String> {
        if self.memory_kib < 19_456 {
            return Err(format!(
                "argon2 memory cost {} KiB is below the 19456 KiB minimum",
                self.memory_kib
            ));
        }
        if self.iterations < 2 {
            return Err(format!(
                "argon2 iterations {} is below the minimum of 2",
                self.iterations
            ));
        }
        if self.parallelism == 0 || self.parallelism > 16 {
            return Err(format!(
                "argon2 parallelism {} is out of range 1..=16",
                self.parallelism
            ));
        }
        Ok(())
    }
}

pub struct Hasher {
    params: Argon2Params,
    /// Bounds concurrent Argon2 work. See the module comment.
    permits: Arc<Semaphore>,
    /// A real hash of a fixed dummy password, verified against when the account
    /// does not exist so that the unknown-user path costs the same as the
    /// known-user path (TH-23).
    dummy_hash: String,
}

impl Hasher {
    pub fn new(params: Argon2Params, max_concurrency: usize) -> Result<Self, AppError> {
        params.validate().map_err(AppError::Internal)?;
        let permits = Arc::new(Semaphore::new(max_concurrency.max(1)));
        let mut hasher = Self {
            params,
            permits,
            dummy_hash: String::new(),
        };
        // Computed once at startup, not per request: the point is to spend the
        // same time as a real verification, and a real verification does not
        // include hashing.
        hasher.dummy_hash =
            hasher.hash_blocking("roleblank-dummy-password-for-timing-equalisation")?;
        Ok(hasher)
    }

    fn argon2(&self) -> Result<Argon2<'static>, AppError> {
        let params = Params::new(
            self.params.memory_kib,
            self.params.iterations,
            self.params.parallelism,
            Some(32),
        )
        .map_err(|e| AppError::Internal(format!("argon2 parameters rejected: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    fn hash_blocking(&self, password: &str) -> Result<String, AppError> {
        // A 16-byte salt from the OS CSPRNG. `SaltString::generate` is not used
        // because it takes an RNG from an older `rand_core` line than the one this
        // crate depends on; encoding our own bytes avoids a duplicate RNG stack.
        let salt_bytes = tokens::random_bytes(16)?;
        let salt = SaltString::from_b64(&BASE64_NOPAD.encode(&salt_bytes))
            .map_err(|e| AppError::Internal(format!("salt encoding failed: {e}")))?;
        let hash = self
            .argon2()?
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("argon2 hashing failed: {e}")))?;
        Ok(hash.to_string())
    }

    fn verify_blocking(&self, password: &str, phc: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(phc) else {
            // A corrupt stored hash must fail closed, and must fail as an ordinary
            // authentication failure so it is not an oracle for "this account has
            // a broken record".
            return false;
        };
        match self.argon2() {
            Ok(a) => a.verify_password(password.as_bytes(), &parsed).is_ok(),
            Err(_) => false,
        }
    }

    /// Hash a password. Runs on the blocking pool because Argon2id holds a core
    /// for milliseconds and would otherwise stall the async executor.
    pub async fn hash(&self, password: &Secret<String>) -> Result<String, AppError> {
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AppError::Internal("hashing semaphore closed".into()))?;
        let params = self.params;
        let password = password.expose().clone();
        tokio::task::spawn_blocking(move || {
            let h = Hasher {
                params,
                permits: Arc::new(Semaphore::new(1)),
                dummy_hash: String::new(),
            };
            h.hash_blocking(&password)
        })
        .await
        .map_err(|e| AppError::Internal(format!("hashing task failed: {e}")))?
    }

    /// Verify a password against a stored PHC string.
    pub async fn verify(&self, password: &Secret<String>, phc: &str) -> Result<bool, AppError> {
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AppError::Internal("hashing semaphore closed".into()))?;
        let params = self.params;
        let password = password.expose().clone();
        let phc = phc.to_string();
        tokio::task::spawn_blocking(move || {
            let h = Hasher {
                params,
                permits: Arc::new(Semaphore::new(1)),
                dummy_hash: String::new(),
            };
            h.verify_blocking(&password, &phc)
        })
        .await
        .map_err(|e| AppError::Internal(format!("verification task failed: {e}")))
    }

    /// Perform the same work as a real verification, against a fixed dummy hash,
    /// and discard the result.
    ///
    /// Called on the login path when the account does not exist. Without it, the
    /// "no such user" response returns in microseconds while a real password check
    /// takes tens of milliseconds — a trivially measurable account-existence oracle.
    pub async fn verify_dummy(&self, password: &Secret<String>) {
        let _ = self.verify(password, &self.dummy_hash).await;
    }
}

/// Minimum length. Long enough to make online guessing hopeless given the rate
/// limiter, short enough not to push users towards writing passwords down.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// Maximum length, measured in Unicode scalar values.
///
/// A cap is required because Argon2's cost is bounded but the *input hashing* of a
/// 200 MB "password" is not. 256 is far above any real passphrase.
pub const MAX_PASSWORD_CHARS: usize = 256;

/// Passwords so common that allowing them is negligent. Deliberately tiny and
/// embedded: a full breach corpus belongs behind an operator-configured service,
/// and shipping a 100 MB list would be a dependency, not a control.
const CATASTROPHIC_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "letmein",
    "welcome",
    "admin",
    "administrator",
    "iloveyou",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "abc123",
    "passw0rd",
    "p@ssw0rd",
    "changeme",
    "secret",
    "trustno1",
    "master",
    "hello123",
    "welcome123",
    "admin123",
    "root",
    "toor",
    "test",
    "guest",
    "qwertyuiop",
    "1q2w3e4r",
];

/// Validate a candidate password.
///
/// Deliberately absent: composition rules ("must contain an uppercase letter and a
/// symbol"). They measurably push users towards `Password1!` while excluding
/// genuinely strong passphrases, and current NIST/OWASP guidance advises against
/// them. Length plus a known-bad check is the guidance actually followed here.
///
/// Also deliberately absent: trimming, case folding, and Unicode normalisation.
/// The bytes the user typed are the bytes that get hashed — silently mutating a
/// credential means a password that works on one client fails on another.
pub fn validate_password(password: &str, email: &str, display_name: &str) -> Result<(), AppError> {
    let chars = password.chars().count();

    if chars < MIN_PASSWORD_CHARS {
        return Err(AppError::field(
            "password",
            "TOO_SHORT",
            format!("Password must be at least {MIN_PASSWORD_CHARS} characters."),
        ));
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err(AppError::field(
            "password",
            "TOO_LONG",
            format!("Password must be at most {MAX_PASSWORD_CHARS} characters."),
        ));
    }

    let lowered = password.to_lowercase();
    if CATASTROPHIC_PASSWORDS.contains(&lowered.as_str()) {
        return Err(AppError::field(
            "password",
            "TOO_COMMON",
            "This password appears on well-known breach lists. Choose another.",
        ));
    }

    // A password equal to an identifier the attacker already has is not a secret.
    let email_local = email.split('@').next().unwrap_or(email).to_lowercase();
    if lowered == email.to_lowercase() || (!email_local.is_empty() && lowered == email_local) {
        return Err(AppError::field(
            "password",
            "CONTAINS_IDENTITY",
            "Password must not be your email address.",
        ));
    }
    if !display_name.trim().is_empty() && lowered == display_name.trim().to_lowercase() {
        return Err(AppError::field(
            "password",
            "CONTAINS_IDENTITY",
            "Password must not be your display name.",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> Hasher {
        // Minimum permitted cost keeps the unit suite fast while still exercising
        // the real algorithm and the real PHC encoding.
        Hasher::new(Argon2Params::default(), 4).expect("hasher")
    }

    #[tokio::test]
    async fn hash_then_verify_round_trips() {
        let h = hasher();
        let pw = Secret::new("correct horse battery staple".to_string());
        let phc = h.hash(&pw).await.expect("hash");
        assert!(
            phc.starts_with("$argon2id$"),
            "PHC string must identify argon2id"
        );
        assert!(h.verify(&pw, &phc).await.expect("verify"));
    }

    #[tokio::test]
    async fn wrong_password_fails() {
        let h = hasher();
        let phc = h
            .hash(&Secret::new("correct horse battery staple".into()))
            .await
            .unwrap();
        assert!(!h
            .verify(&Secret::new("correct horse battery stapl".into()), &phc)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn each_hash_uses_a_fresh_salt() {
        let h = hasher();
        let pw = Secret::new("correct horse battery staple".to_string());
        let a = h.hash(&pw).await.unwrap();
        let b = h.hash(&pw).await.unwrap();
        assert_ne!(
            a, b,
            "identical passwords must not produce identical hashes"
        );
        assert!(h.verify(&pw, &a).await.unwrap());
        assert!(h.verify(&pw, &b).await.unwrap());
    }

    #[tokio::test]
    async fn passwords_are_not_trimmed_or_case_folded() {
        let h = hasher();
        let phc = h
            .hash(&Secret::new(" Correct Horse Battery ".into()))
            .await
            .unwrap();
        assert!(!h
            .verify(&Secret::new("Correct Horse Battery".into()), &phc)
            .await
            .unwrap());
        assert!(!h
            .verify(&Secret::new(" correct horse battery ".into()), &phc)
            .await
            .unwrap());
        assert!(h
            .verify(&Secret::new(" Correct Horse Battery ".into()), &phc)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn unicode_and_long_passphrases_are_supported() {
        let h = hasher();
        let pw = Secret::new("قلعة الرمل الزرقاء 🏰 mit Ümläut".to_string());
        let phc = h.hash(&pw).await.unwrap();
        assert!(h.verify(&pw, &phc).await.unwrap());
    }

    #[tokio::test]
    async fn a_corrupt_stored_hash_fails_closed() {
        let h = hasher();
        assert!(!h
            .verify(&Secret::new("anything".into()), "not-a-phc-string")
            .await
            .unwrap());
        assert!(!h.verify(&Secret::new("anything".into()), "").await.unwrap());
    }

    #[test]
    fn policy_enforces_length_bounds() {
        assert!(validate_password("short", "a@b.com", "A").is_err());
        assert!(validate_password(&"a".repeat(11), "a@b.com", "A").is_err());
        assert!(validate_password(&"a".repeat(12), "a@b.com", "A").is_ok());
        assert!(validate_password(&"a".repeat(256), "a@b.com", "A").is_ok());
        assert!(validate_password(&"a".repeat(257), "a@b.com", "A").is_err());
    }

    #[test]
    fn policy_rejects_catastrophic_and_identity_passwords() {
        assert!(validate_password("password123", "a@b.com", "A").is_err());
        assert!(
            validate_password("PASSWORD123", "a@b.com", "A").is_err(),
            "case-insensitive"
        );
        assert!(validate_password("alice@example.com", "alice@example.com", "Alice").is_err());
        assert!(validate_password("Alice Anderson", "a@b.com", "Alice Anderson").is_err());
    }

    #[test]
    fn policy_imposes_no_composition_rules() {
        // A long all-lowercase passphrase with no digits or symbols is fine.
        assert!(
            validate_password("the quiet river runs past the old mill", "a@b.com", "A").is_ok()
        );
    }

    #[test]
    fn weak_argon2_parameters_are_refused() {
        assert!(Argon2Params {
            memory_kib: 4096,
            iterations: 2,
            parallelism: 1
        }
        .validate()
        .is_err());
        assert!(Argon2Params {
            memory_kib: 19_456,
            iterations: 1,
            parallelism: 1
        }
        .validate()
        .is_err());
        assert!(Argon2Params {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 0
        }
        .validate()
        .is_err());
        assert!(Argon2Params::default().validate().is_ok());
    }
}
