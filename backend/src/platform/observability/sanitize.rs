//! Log sanitisation.
//!
//! Threat: a user controls a value that reaches a log line (a display name, an
//! email, a user agent, an error message). If that value can contain `\n` or `\r`
//! it can forge additional log records — an attacker names themselves
//! `"x\n{\"level\":\"INFO\",\"msg\":\"admin approved\"}"` and the log now contains a
//! line nobody wrote. See `docs/backend/02-threat-model.md` TH-32.
//!
//! Two independent defences:
//!   1. Logs are emitted as JSON, so a newline inside a string value is escaped by
//!      the serialiser and cannot terminate the record.
//!   2. These helpers strip control characters anyway, because defence 1 only
//!      holds while the JSON formatter is in use, and a human reading `docker
//!      logs` with a text formatter should not see forged lines either.
//!
//! They also bound length, so a 10 MB display name cannot become a 10 MB log line.

/// Maximum length of any single sanitised value written to a log or stored as a
/// `*_hint` column.
pub const MAX_LOGGED_LEN: usize = 200;

/// Replace every control character with `·` and truncate on a character boundary.
///
/// Truncation is by `char`, not by byte, so a multi-byte sequence is never cut in
/// half — a split UTF-8 sequence would produce a replacement character in the log
/// and, worse, could be used to smuggle bytes past a naive byte-level filter.
pub fn log_value(input: impl AsRef<str>) -> String {
    sanitize_bounded(input.as_ref(), MAX_LOGGED_LEN)
}

pub fn sanitize_bounded(input: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_chars * 4));
    let mut truncated = false;

    for (taken, ch) in input.chars().enumerate() {
        if taken >= max_chars {
            truncated = true;
            break;
        }
        // `is_control` covers C0 (including \n, \r, \t, NUL) and C1.
        // U+2028/U+2029 are line separators that some log viewers honour, so they
        // are folded too even though Rust does not class them as control chars.
        if ch.is_control() || ch == '\u{2028}' || ch == '\u{2029}' {
            out.push('\u{00B7}'); // MIDDLE DOT
        } else {
            out.push(ch);
        }
    }

    if truncated {
        out.push('…');
    }
    out
}

/// Sanitise an optional client-supplied header for storage as a `*_hint` column.
/// Returns `None` for absent or empty input so the column stays NULL rather than
/// holding an empty string that a query would have to special-case.
pub fn header_hint(value: Option<&str>, max_chars: usize) -> Option<String> {
    let v = value?.trim();
    if v.is_empty() {
        return None;
    }
    Some(sanitize_bounded(v, max_chars))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_crlf_so_log_lines_cannot_be_forged() {
        let attack = "alice\r\n{\"level\":\"INFO\",\"message\":\"admin approved payment\"}";
        let out = log_value(attack);
        assert!(!out.contains('\n'));
        assert!(!out.contains('\r'));
        assert!(out.starts_with("alice··"));
    }

    #[test]
    fn strips_nul_and_escape() {
        let out = log_value("a\0b\x1b[31mc");
        assert!(!out.contains('\0'));
        assert!(!out.contains('\x1b'));
        assert_eq!(out, "a·b·[31mc");
    }

    #[test]
    fn strips_unicode_line_separators() {
        let out = log_value("a\u{2028}b\u{2029}c");
        assert_eq!(out, "a·b·c");
    }

    #[test]
    fn truncates_on_a_character_boundary() {
        let long = "é".repeat(500);
        let out = sanitize_bounded(&long, 10);
        // 10 chars plus the ellipsis marker.
        assert_eq!(out.chars().count(), 11);
        assert!(out.ends_with('…'));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn preserves_ordinary_unicode() {
        assert_eq!(log_value("محمد Ünïcode 名前"), "محمد Ünïcode 名前");
    }

    #[test]
    fn header_hint_normalises_empty_to_none() {
        assert_eq!(header_hint(None, 45), None);
        assert_eq!(header_hint(Some("   "), 45), None);
        assert_eq!(
            header_hint(Some(" 1.2.3.4 "), 45),
            Some("1.2.3.4".to_string())
        );
    }
}
