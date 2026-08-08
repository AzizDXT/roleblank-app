//! TOTP (RFC 6238) over HOTP (RFC 4226).
//!
//! **Scope of what is implemented here.** The cryptographic primitive — HMAC-SHA1 —
//! comes from the audited RustCrypto `hmac` and `sha1` crates. What lives in this
//! file is only the RFC's counter derivation and dynamic-truncation construction,
//! which is roughly thirty lines fully specified by the standard. It is validated
//! against the **official RFC 6238 Appendix B test vectors** in the tests below.
//! No cryptographic primitive is invented here. See ADR-002 for why a third-party
//! TOTP crate was not taken.
//!
//! Replay is prevented by the caller, not by this module: `mfa_factors.last_used_step`
//! records the highest accepted counter and any code at or below it is refused,
//! which kills reuse of a code captured in transit within its own time window.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::platform::crypto::tokens;
use crate::platform::errors::AppError;
use crate::shared::secret::Secret;

type HmacSha1 = Hmac<Sha1>;

/// The interoperable profile. Every mainstream authenticator implements exactly
/// this; deviating would produce secrets users cannot enrol.
pub const STEP_SECONDS: u64 = 30;
pub const DIGITS: u32 = 6;

/// Accepted clock skew, in steps, on either side of the current one.
///
/// ±1 step is ±30 s. Widening this multiplies the number of simultaneously valid
/// codes and therefore the online guessing surface; it is a security parameter,
/// not a usability knob.
pub const SKEW_STEPS: i64 = 1;

/// RFC 4288 recommends at least 128 bits; 160 matches the SHA-1 block structure
/// and is what authenticator apps expect.
pub const SECRET_BYTES: usize = 20;

pub fn generate_secret() -> Result<Secret<Vec<u8>>, AppError> {
    Ok(Secret::new(tokens::random_bytes(SECRET_BYTES)?))
}

/// Base32 (RFC 4648, no padding) — the encoding every authenticator app accepts.
pub fn encode_secret(secret: &Secret<Vec<u8>>) -> Secret<String> {
    Secret::new(data_encoding::BASE32_NOPAD.encode(secret.expose()))
}

/// Build the `otpauth://` provisioning URI shown once at enrolment.
///
/// The label and issuer are percent-encoded; without that, a display name
/// containing `?` or `&` would let a user inject provisioning parameters (for
/// example a different `secret`) into their own — or a colleague's — QR payload.
pub fn provisioning_uri(issuer: &str, account: &str, secret: &Secret<Vec<u8>>) -> Secret<String> {
    let encoded = encode_secret(secret);
    Secret::new(format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        percent_encode(issuer),
        percent_encode(account),
        encoded.expose(),
        percent_encode(issuer),
        DIGITS,
        STEP_SECONDS
    ))
}

/// Minimal RFC 3986 unreserved-set encoder. Kept local rather than pulling a
/// dependency for one function used in one place.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The time step for a Unix timestamp.
pub fn step_at(unix_seconds: u64) -> u64 {
    unix_seconds / STEP_SECONDS
}

/// HOTP (RFC 4226 §5.3): HMAC, dynamic truncation, modulo 10^digits.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    // `new_from_slice` only fails for key lengths HMAC cannot accept; HMAC accepts
    // any length, so this cannot fail in practice. It is still handled rather than
    // unwrapped, because a panic in an authentication path is a denial of service.
    let Ok(mut mac) = HmacSha1::new_from_slice(secret) else {
        return u32::MAX; // never equal to a valid code, which is < 10^digits
    };
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Dynamic truncation: the low nibble of the last byte selects the offset.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    binary % 10u32.pow(digits)
}

/// Render a code for a given step, zero-padded to `DIGITS`.
pub fn code_for_step(secret: &Secret<Vec<u8>>, step: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret.expose(), step, DIGITS),
        width = DIGITS as usize
    )
}

/// Outcome of a verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpVerdict {
    /// The code is valid at this step. The caller MUST persist the step as
    /// `last_used_step` before returning success, or replay remains possible.
    Valid {
        step: u64,
    },
    Invalid,
    /// Correct code, but for a step already consumed — a replay attempt.
    /// Distinguished so it can be audited as a security event rather than as an
    /// ordinary typo.
    Replayed,
}

/// Verify a presented code against the ±`SKEW_STEPS` window.
///
/// `last_used_step` is the highest step previously accepted for this factor;
/// `None` for a factor that has never been used.
pub fn verify(
    secret: &Secret<Vec<u8>>,
    presented: &str,
    now_unix_seconds: u64,
    last_used_step: Option<u64>,
) -> TotpVerdict {
    let cleaned: String = presented.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() != DIGITS as usize {
        return TotpVerdict::Invalid;
    }

    let current = step_at(now_unix_seconds) as i64;
    let mut matched: Option<u64> = None;

    // Every candidate step is evaluated even after a match, so that the number of
    // HMAC operations does not depend on which step matched. Comparison is
    // constant-time for the same reason.
    for delta in -SKEW_STEPS..=SKEW_STEPS {
        let candidate = current + delta;
        if candidate < 0 {
            continue;
        }
        let step = candidate as u64;
        let expected = code_for_step(secret, step);
        if tokens::digests_equal(expected.as_bytes(), cleaned.as_bytes()) {
            matched = Some(step);
        }
    }

    match (matched, last_used_step) {
        (None, _) => TotpVerdict::Invalid,
        (Some(step), Some(last)) if step <= last => TotpVerdict::Replayed,
        (Some(step), _) => TotpVerdict::Valid { step },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA-1 column.
    ///
    /// The shared secret is the ASCII string "12345678901234567890". These are the
    /// standard's own published values; matching them is what makes this
    /// implementation interoperable with every authenticator app rather than
    /// merely self-consistent.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn rfc_code(unix: u64) -> String {
        // The RFC's table uses 8 digits; our profile uses 6, so compare the last 6.
        let s = Secret::new(RFC_SECRET.to_vec());
        format!("{:08}", hotp(s.expose(), step_at(unix), 8))
    }

    #[test]
    fn matches_rfc6238_appendix_b_test_vectors() {
        // (unix time, expected 8-digit TOTP, expected value of T)
        // Both columns are transcribed from the RFC's own table.
        let vectors: &[(u64, &str, u64)] = &[
            (59, "94287082", 0x0000_0000_0000_0001),
            (1_111_111_109, "07081804", 0x0000_0000_0235_23EC),
            (1_111_111_111, "14050471", 0x0000_0000_0235_23ED),
            (1_234_567_890, "89005924", 0x0000_0000_0273_EF07),
            (2_000_000_000, "69279037", 0x0000_0000_03F9_40AA),
            (20_000_000_000, "65353130", 0x0000_0000_27BC_86AA),
        ];
        for (unix, expected, expected_step) in vectors {
            assert_eq!(
                step_at(*unix),
                *expected_step,
                "step derivation at t={unix}"
            );
            assert_eq!(rfc_code(*unix), *expected, "RFC 6238 vector at t={unix}");
        }
    }

    #[test]
    fn six_digit_profile_is_the_low_six_digits_of_the_rfc_value() {
        let s = Secret::new(RFC_SECRET.to_vec());
        assert_eq!(code_for_step(&s, step_at(59)), "287082");
        assert_eq!(code_for_step(&s, step_at(1_111_111_109)), "081804");
    }

    #[test]
    fn codes_are_always_zero_padded_to_six_digits() {
        // A code with leading zeros must not be rendered as a short string, or a
        // client comparing lengths would reject a legitimate code.
        let s = Secret::new(RFC_SECRET.to_vec());
        for step in 0..2000 {
            let c = code_for_step(&s, step);
            assert_eq!(c.len(), 6, "step {step} produced {c}");
            assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        }
    }

    #[test]
    fn accepts_the_current_step_and_one_step_either_side() {
        let s = generate_secret().unwrap();
        let now = 1_700_000_000u64;
        let step = step_at(now);
        for offset in [-1i64, 0, 1] {
            let candidate_step = (step as i64 + offset) as u64;
            let code = code_for_step(&s, candidate_step);
            assert!(
                matches!(verify(&s, &code, now, None), TotpVerdict::Valid { .. }),
                "offset {offset} should be inside the window"
            );
        }
    }

    #[test]
    fn rejects_codes_outside_the_window() {
        let s = generate_secret().unwrap();
        let now = 1_700_000_000u64;
        let step = step_at(now);
        for offset in [-5i64, -2, 2, 5, 100] {
            let code = code_for_step(&s, (step as i64 + offset) as u64);
            assert_eq!(
                verify(&s, &code, now, None),
                TotpVerdict::Invalid,
                "offset {offset} should be outside the window"
            );
        }
    }

    /// TH-26: a code captured in transit must not be usable a second time even
    /// while it is still inside its own validity window.
    #[test]
    fn replay_within_the_window_is_detected() {
        let s = generate_secret().unwrap();
        let now = 1_700_000_000u64;
        let code = code_for_step(&s, step_at(now));

        let first = verify(&s, &code, now, None);
        let TotpVerdict::Valid { step } = first else {
            panic!("expected the first use to succeed, got {first:?}");
        };
        assert_eq!(verify(&s, &code, now, Some(step)), TotpVerdict::Replayed);
        // A newer step is still accepted after the replay attempt.
        let next = code_for_step(&s, step + 1);
        assert!(matches!(
            verify(&s, &next, now + 30, Some(step)),
            TotpVerdict::Valid { .. }
        ));
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        let s = generate_secret().unwrap();
        let now = 1_700_000_000u64;
        for bad in [
            "",
            "12345",
            "1234567",
            "abcdef",
            "12 34 56",
            "٠١٢٣٤٥",
            &"9".repeat(100_000),
        ] {
            assert_eq!(
                verify(&s, bad, now, None),
                TotpVerdict::Invalid,
                "input {bad:?}"
            );
        }
    }

    #[test]
    fn separators_and_spaces_typed_by_a_human_are_tolerated() {
        let s = generate_secret().unwrap();
        let now = 1_700_000_000u64;
        let code = code_for_step(&s, step_at(now));
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(matches!(
            verify(&s, &spaced, now, None),
            TotpVerdict::Valid { .. }
        ));
    }

    #[test]
    fn a_different_secret_never_validates() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        let now = 1_700_000_000u64;
        assert_eq!(
            verify(&b, &code_for_step(&a, step_at(now)), now, None),
            TotpVerdict::Invalid
        );
    }

    #[test]
    fn provisioning_uri_percent_encodes_untrusted_labels() {
        let s = Secret::new(RFC_SECRET.to_vec());
        // A display name that tries to inject an extra parameter.
        let uri = provisioning_uri("RoleBlank OS", "eve@x.com?secret=ATTACKER", &s);
        let uri = uri.expose();
        assert!(uri.starts_with("otpauth://totp/RoleBlank%20OS:"));
        assert!(
            !uri.contains("?secret=ATTACKER"),
            "injection was not encoded: {uri}"
        );
        assert!(uri.contains("%3Fsecret%3DATTACKER"));
        // Exactly one query separator.
        assert_eq!(uri.matches('?').count(), 1);
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn secrets_are_the_expected_size_and_do_not_repeat() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        assert_eq!(a.expose().len(), SECRET_BYTES);
        assert_ne!(a.expose(), b.expose());
        assert_eq!(
            encode_secret(&a).expose().len(),
            32,
            "20 bytes base32 = 32 chars"
        );
    }
}
