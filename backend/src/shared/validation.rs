//! Input validation primitives.
//!
//! Deliberately plain functions rather than a derive-macro validation framework:
//! the brief forbids macro ceremony that obscures security behaviour, and a
//! reviewer reading a handler should be able to see exactly what was checked.
//!
//! Every bound here exists because something unbounded is a denial-of-service or a
//! storage-corruption vector (TH-33), and every length limit matches the `CHECK`
//! constraint on the corresponding column so the two cannot drift apart.

use crate::platform::errors::AppError;

pub const MAX_EMAIL_LEN: usize = 254;
pub const MAX_DISPLAY_NAME_LEN: usize = 200;
pub const MAX_NAME_LEN: usize = 200;
pub const MAX_CODE_LEN: usize = 50;
pub const MAX_DESCRIPTION_LEN: usize = 1000;
pub const MAX_LONG_TEXT_LEN: usize = 5000;
pub const MAX_TASK_DESCRIPTION_LEN: usize = 10_000;
pub const MAX_TITLE_LEN: usize = 300;
pub const MAX_REASON_LEN: usize = 500;
/// Upper bound on any array the API accepts, so a single request cannot ask for
/// ten thousand role assignments.
pub const MAX_ARRAY_LEN: usize = 100;

/// Normalise an email to its identity form.
///
/// `lower(trim(..))` and **nothing else**. Deliberately no dot-stripping and no
/// plus-address folding: `a.b@gmail.com` and `ab@gmail.com` are the same mailbox
/// at one provider and different mailboxes at most others, so folding them merges
/// distinct real accounts. The same function is mirrored by the database `CHECK`
/// on `users.email_normalized`.
pub fn normalize_email(input: &str) -> String {
    input.trim().to_lowercase()
}

/// Validate an email address.
///
/// This is a *deliverability-agnostic* structural check, not RFC 5322 parsing.
/// Full RFC 5322 accepts addresses no mail system in practice handles, and trying
/// to implement it precisely is a well-known source of ReDoS bugs. The real
/// verification is the confirmation email.
pub fn validate_email(field: &'static str, input: &str) -> Result<String, AppError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AppError::field(
            field,
            "REQUIRED",
            "An email address is required.",
        ));
    }
    if trimmed.len() > MAX_EMAIL_LEN {
        return Err(AppError::field(
            field,
            "TOO_LONG",
            format!("Email must be at most {MAX_EMAIL_LEN} characters."),
        ));
    }

    let mut parts = trimmed.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some() || local.is_empty() || domain.is_empty() {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Email address is not valid.",
        ));
    }
    if !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Email address is not valid.",
        ));
    }
    // Control characters and whitespace inside the address would reach logs and
    // the outbox payload; reject rather than sanitise, because a sanitised email
    // is a different address.
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Email address is not valid.",
        ));
    }
    if domain
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Email address is not valid.",
        ));
    }

    Ok(normalize_email(trimmed))
}

/// A required free-text field with a length bound, measured in Unicode scalar
/// values so a name in Arabic or Japanese is not penalised for its byte length.
pub fn required_text(
    field: &'static str,
    input: &str,
    max_chars: usize,
) -> Result<String, AppError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AppError::field(
            field,
            "REQUIRED",
            "This field is required.",
        ));
    }
    let count = trimmed.chars().count();
    if count > max_chars {
        return Err(AppError::field(
            field,
            "TOO_LONG",
            format!("Must be at most {max_chars} characters."),
        ));
    }
    // Control characters in stored text end up in logs, CSV exports and audit
    // metadata. There is no legitimate use for them in a name or a description.
    if trimmed
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "This field contains control characters.",
        ));
    }
    Ok(trimmed.to_string())
}

pub fn optional_text(
    field: &'static str,
    input: Option<&str>,
    max_chars: usize,
) -> Result<String, AppError> {
    match input {
        None => Ok(String::new()),
        Some(v) if v.trim().is_empty() => Ok(String::new()),
        Some(v) => required_text(field, v, max_chars),
    }
}

/// A machine-facing identifier: `^[a-z0-9][a-z0-9_-]{0,49}$`.
///
/// Restricted to exactly what the database `CHECK` accepts, so an invalid code
/// fails here with a useful message rather than as an opaque constraint violation.
pub fn validate_code(field: &'static str, input: &str) -> Result<String, AppError> {
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err(AppError::field(field, "REQUIRED", "A code is required."));
    }
    if trimmed.len() > MAX_CODE_LEN {
        return Err(AppError::field(
            field,
            "TOO_LONG",
            format!("Code must be at most {MAX_CODE_LEN} characters."),
        ));
    }
    let mut chars = trimmed.chars();
    let first = chars.next().unwrap_or(' ');
    if !first.is_ascii_alphanumeric() {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Code must start with a letter or digit.",
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Code may contain only lowercase letters, digits, `_` and `-`.",
        ));
    }
    Ok(trimmed)
}

/// A role code is stricter still: `^[a-z][a-z0-9_]*$` — no hyphens, must start
/// with a letter. Matches `roles.code`'s CHECK constraint.
pub fn validate_role_code(field: &'static str, input: &str) -> Result<String, AppError> {
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err(AppError::field(
            field,
            "REQUIRED",
            "A role code is required.",
        ));
    }
    if trimmed.len() > MAX_CODE_LEN {
        return Err(AppError::field(field, "TOO_LONG", "Role code is too long."));
    }
    let mut chars = trimmed.chars();
    if !chars
        .next()
        .map(|c| c.is_ascii_lowercase())
        .unwrap_or(false)
    {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Role code must start with a letter.",
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(AppError::field(
            field,
            "INVALID_FORMAT",
            "Role code may contain only lowercase letters, digits and `_`.",
        ));
    }
    Ok(trimmed)
}

/// Bound the length of any incoming array.
pub fn validate_array_len<T>(field: &'static str, items: &[T], max: usize) -> Result<(), AppError> {
    if items.len() > max {
        return Err(AppError::field(
            field,
            "TOO_MANY",
            format!("At most {max} items are allowed in one request."),
        ));
    }
    Ok(())
}

/// Parse a closed enum, refusing anything outside it.
pub fn parse_enum<T>(
    field: &'static str,
    input: &str,
    parse: impl Fn(&str) -> Option<T>,
    allowed: &[&str],
) -> Result<T, AppError> {
    parse(input.trim()).ok_or_else(|| {
        AppError::field(
            field,
            "INVALID_VALUE",
            format!("Must be one of: {}", allowed.join(", ")),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_of(err: AppError) -> String {
        match err {
            AppError::Validation { errors } => errors[0].code.to_string(),
            other => panic!("expected a validation error, got {other}"),
        }
    }

    #[test]
    fn email_normalisation_lowercases_and_trims_only() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
        // Deliberately NOT folded — these are different accounts at most providers.
        assert_ne!(normalize_email("a.b@x.com"), normalize_email("ab@x.com"));
        assert_ne!(normalize_email("a+tag@x.com"), normalize_email("a@x.com"));
    }

    #[test]
    fn valid_emails_are_accepted_and_normalised() {
        for input in ["a@b.co", "Alice.Smith+tag@Sub.Example.COM", "  x@y.org  "] {
            let out = validate_email("email", input).expect(input);
            assert_eq!(out, input.trim().to_lowercase());
        }
    }

    #[test]
    fn structurally_invalid_emails_are_rejected() {
        for bad in [
            "",
            "   ",
            "no-at-sign",
            "@nolocal.com",
            "nodomain@",
            "a@b",
            "a@@b.com",
            "a@.com",
            "a@com.",
            "a@b..com",
            "a b@c.com",
            "a@b .com",
            "a\n@b.com",
            "a\0@b.com",
            "a@b.com\r\nBcc: x@y.com",
        ] {
            assert!(validate_email("email", bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            code_of(validate_email("email", "").unwrap_err()),
            "REQUIRED"
        );
    }

    /// CRLF in an address is a header-injection attempt against the future mail
    /// provider.
    #[test]
    fn email_header_injection_is_rejected() {
        let attack = "victim@example.com\nBcc: attacker@evil.com";
        assert!(validate_email("email", attack).is_err());
    }

    #[test]
    fn emails_are_length_bounded() {
        let long = format!("{}@example.com", "a".repeat(300));
        assert_eq!(
            code_of(validate_email("email", &long).unwrap_err()),
            "TOO_LONG"
        );
        assert!(validate_email("email", &"a".repeat(1_000_000)).is_err());
    }

    #[test]
    fn required_text_bounds_by_characters_not_bytes() {
        // 200 Arabic characters is well over 200 bytes but is a legitimate name.
        let arabic = "م".repeat(200);
        assert!(required_text("name", &arabic, 200).is_ok());
        assert!(required_text("name", &"م".repeat(201), 200).is_err());
        assert_eq!(
            code_of(required_text("name", "  ", 200).unwrap_err()),
            "REQUIRED"
        );
    }

    #[test]
    fn required_text_rejects_control_characters() {
        assert!(required_text("name", "Alice\0Smith", 200).is_err());
        assert!(required_text("name", "Alice\x1b[31m", 200).is_err());
        // Newlines and tabs are permitted in multi-line fields.
        assert!(required_text("description", "line one\nline two\tindented", 200).is_ok());
    }

    #[test]
    fn optional_text_maps_absent_and_blank_to_empty() {
        assert_eq!(optional_text("d", None, 100).unwrap(), "");
        assert_eq!(optional_text("d", Some("   "), 100).unwrap(), "");
        assert_eq!(optional_text("d", Some(" hi "), 100).unwrap(), "hi");
        assert!(optional_text("d", Some(&"x".repeat(101)), 100).is_err());
    }

    #[test]
    fn codes_match_the_database_constraint() {
        assert_eq!(validate_code("code", " ACME-1 ").unwrap(), "acme-1");
        assert_eq!(validate_code("code", "a").unwrap(), "a");
        assert_eq!(validate_code("code", "9lives").unwrap(), "9lives");
        for bad in [
            "",
            "-leading",
            "_leading",
            "has space",
            "has.dot",
            "üml",
            &"a".repeat(51),
        ] {
            assert!(validate_code("code", bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn role_codes_are_stricter_than_general_codes() {
        assert_eq!(
            validate_role_code("code", "Field_Manager").unwrap(),
            "field_manager"
        );
        // Hyphens are fine in a general code but not in a role code.
        assert!(validate_code("code", "field-manager").is_ok());
        assert!(validate_role_code("code", "field-manager").is_err());
        assert!(validate_role_code("code", "1role").is_err());
    }

    #[test]
    fn arrays_are_bounded() {
        let ok: Vec<u8> = vec![0; 100];
        let too_many: Vec<u8> = vec![0; 101];
        assert!(validate_array_len("ids", &ok, 100).is_ok());
        assert_eq!(
            code_of(validate_array_len("ids", &too_many, 100).unwrap_err()),
            "TOO_MANY"
        );
    }

    #[test]
    fn enum_parsing_refuses_anything_outside_the_set() {
        let parse = |s: &str| match s {
            "ACTIVE" => Some(1u8),
            "ARCHIVED" => Some(2u8),
            _ => None,
        };
        assert_eq!(
            parse_enum("status", " ACTIVE ", parse, &["ACTIVE", "ARCHIVED"]).unwrap(),
            1
        );
        for bad in ["active", "DELETED", "", "ACTIVE; DROP TABLE users"] {
            assert!(
                parse_enum("status", bad, parse, &["ACTIVE", "ARCHIVED"]).is_err(),
                "{bad:?}"
            );
        }
    }
}
