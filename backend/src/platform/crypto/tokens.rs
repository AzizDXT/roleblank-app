//! Opaque credential tokens: generation, hashing and constant-time comparison.
//!
//! Every credential-shaped value in RoleBlank — access tokens, refresh tokens,
//! password-reset tokens, invitation tokens, recovery codes — is 32 bytes drawn
//! from the operating system CSPRNG, handed to the user exactly once, and stored
//! only as a SHA-256 digest.
//!
//! **Why SHA-256 rather than Argon2 here.** The input is already 256 bits of
//! uniform randomness. A password KDF exists to compensate for low-entropy human
//! input; against a uniformly random 256-bit preimage it adds per-request latency
//! to the hottest query in the system and buys nothing. A stolen database yields
//! digests, not usable tokens.

use data_encoding::BASE64URL_NOPAD;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::platform::errors::AppError;
use crate::shared::secret::Secret;

/// 256 bits. Guessing is not a threat model at this size; the rate limiter exists
/// for the endpoints, not for the token space.
pub const TOKEN_BYTES: usize = 32;

/// Human-visible prefixes.
///
/// They exist so that (a) a leaked token is recognisable to secret-scanning
/// tooling, and (b) presenting a refresh token where an access token is expected
/// fails loudly and identifiably rather than as an ambiguous lookup miss.
pub const ACCESS_TOKEN_PREFIX: &str = "rb_at_";
pub const REFRESH_TOKEN_PREFIX: &str = "rb_rt_";
pub const RESET_TOKEN_PREFIX: &str = "rb_pr_";
pub const INVITE_TOKEN_PREFIX: &str = "rb_iv_";

/// A freshly minted token: the plaintext to hand to the caller exactly once, and
/// the digest to persist.
pub struct GeneratedToken {
    /// Wrapped so it cannot reach a log through a derived `Debug`.
    pub plaintext: Secret<String>,
    pub hash: Vec<u8>,
}

/// Fill a buffer from the OS CSPRNG.
///
/// A failure here means the operating system could not provide entropy. There is
/// no safe fallback — deriving key material from a clock or a PID would be a
/// silent catastrophic downgrade — so this fails the request instead.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, AppError> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| AppError::Internal("operating system CSPRNG unavailable".into()))?;
    Ok(buf)
}

/// Mint a prefixed opaque token and its digest.
pub fn generate(prefix: &str) -> Result<GeneratedToken, AppError> {
    let raw = random_bytes(TOKEN_BYTES)?;
    let plaintext = format!("{prefix}{}", BASE64URL_NOPAD.encode(&raw));
    let hash = hash_token(&plaintext);
    Ok(GeneratedToken {
        plaintext: Secret::new(plaintext),
        hash,
    })
}

/// SHA-256 of the full presented token *including its prefix*.
///
/// Hashing the prefix too means a token minted for one purpose can never collide
/// with one minted for another, even if the random component were somehow repeated.
pub fn hash_token(presented: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(presented.as_bytes());
    hasher.finalize().to_vec()
}

/// Reject anything that is not shaped like one of our tokens before it reaches the
/// database.
///
/// This is a cheap denial-of-service guard: without it, a flood of 100 KB garbage
/// bearer values would each cost an indexed lookup. It is *not* a security
/// boundary — a well-formed but wrong token still fails at lookup.
pub fn is_well_formed(token: &str, expected_prefix: &str) -> bool {
    // 32 bytes base64url without padding is exactly 43 characters.
    const ENCODED_LEN: usize = 43;
    if token.len() != expected_prefix.len() + ENCODED_LEN {
        return false;
    }
    let Some(body) = token.strip_prefix(expected_prefix) else {
        return false;
    };
    body.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Constant-time digest comparison.
///
/// Used where a digest is compared in application code rather than by an indexed
/// database lookup (recovery codes, the bootstrap secret). A `==` on byte slices
/// short-circuits on the first differing byte and leaks a position oracle.
pub fn digests_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison of a presented secret against a configured one.
/// Compares digests rather than raw bytes so that inputs of differing length do
/// not leak their length through the comparison cost.
pub fn secret_matches(presented: &str, expected: &str) -> bool {
    digests_equal(&hash_token(presented), &hash_token(expected))
}

/// Recovery codes are formatted for a human to read off a screen and type back:
/// `XXXXX-XXXXX-XXXXX-XXXXX` in Crockford-free base32 uppercase.
///
/// 20 groups of 5 base32 characters is 100 bits of the underlying 160, which is
/// far beyond brute-force reach given the per-account attempt limiter.
pub fn generate_recovery_code() -> Result<GeneratedToken, AppError> {
    let raw = random_bytes(20)?;
    let encoded = data_encoding::BASE32_NOPAD.encode(&raw);
    let grouped: Vec<String> = encoded
        .as_bytes()
        .chunks(5)
        .take(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let plaintext = grouped.join("-");
    let hash = hash_token(&plaintext);
    Ok(GeneratedToken {
        plaintext: Secret::new(plaintext),
        hash,
    })
}

/// Normalise a recovery code as typed by a human: uppercase, and tolerate missing
/// or extra separators and whitespace.
///
/// Normalisation is safe here — unlike a password — because the value is a
/// server-generated alphabet-restricted code, not user-chosen secret text.
pub fn normalize_recovery_code(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    cleaned
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_tokens_have_the_expected_shape() {
        let t = generate(ACCESS_TOKEN_PREFIX).expect("csprng");
        let plaintext = t.plaintext.expose();
        assert!(plaintext.starts_with(ACCESS_TOKEN_PREFIX));
        assert_eq!(plaintext.len(), ACCESS_TOKEN_PREFIX.len() + 43);
        assert_eq!(t.hash.len(), 32);
        assert!(is_well_formed(plaintext, ACCESS_TOKEN_PREFIX));
    }

    #[test]
    fn tokens_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let t = generate(ACCESS_TOKEN_PREFIX).expect("csprng");
            assert!(
                seen.insert(t.plaintext.expose().clone()),
                "CSPRNG produced a duplicate"
            );
        }
    }

    #[test]
    fn hash_is_deterministic_and_prefix_sensitive() {
        assert_eq!(hash_token("rb_at_abc"), hash_token("rb_at_abc"));
        assert_ne!(hash_token("rb_at_abc"), hash_token("rb_rt_abc"));
    }

    #[test]
    fn well_formed_rejects_wrong_prefix_length_and_alphabet() {
        let t = generate(ACCESS_TOKEN_PREFIX).expect("csprng");
        let good = t.plaintext.expose();
        assert!(!is_well_formed(good, REFRESH_TOKEN_PREFIX));
        assert!(!is_well_formed("rb_at_short", ACCESS_TOKEN_PREFIX));
        assert!(!is_well_formed(&format!("{good}x"), ACCESS_TOKEN_PREFIX));
        assert!(!is_well_formed(&"x".repeat(100_000), ACCESS_TOKEN_PREFIX));
        // Same length, illegal alphabet.
        let bad = format!("{ACCESS_TOKEN_PREFIX}{}", "!".repeat(43));
        assert!(!is_well_formed(&bad, ACCESS_TOKEN_PREFIX));
    }

    #[test]
    fn digest_comparison_rejects_mismatch_and_length_difference() {
        let a = hash_token("one");
        let b = hash_token("two");
        assert!(digests_equal(&a, &a));
        assert!(!digests_equal(&a, &b));
        assert!(!digests_equal(&a, &a[..31]));
    }

    #[test]
    fn secret_matches_is_exact() {
        assert!(secret_matches("correct horse", "correct horse"));
        assert!(!secret_matches("correct horse", "correct horse "));
        assert!(!secret_matches("", "x"));
    }

    #[test]
    fn recovery_codes_are_grouped_and_normalise_round_trip() {
        let c = generate_recovery_code().expect("csprng");
        let plaintext = c.plaintext.expose();
        assert_eq!(plaintext.len(), 23, "XXXXX-XXXXX-XXXXX-XXXXX");
        assert_eq!(plaintext.matches('-').count(), 3);
        // A human retyping it with lowercase, spaces and no dashes still matches.
        let mangled = plaintext.to_lowercase().replace('-', " ");
        assert_eq!(normalize_recovery_code(&mangled), *plaintext);
        assert_eq!(hash_token(&normalize_recovery_code(&mangled)), c.hash);
    }
}
