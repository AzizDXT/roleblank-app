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

/// Sanitise `input` to **at most `max_chars` characters**, marker included.
///
/// The marker counting against the budget is not cosmetic. `header_hint` is called
/// with the width of a database column — `sessions.user_agent_hint` is
/// `CHECK (length(...) <= 200)` — so a function that returned `max_chars + 1`
/// characters produced a row the schema refused. That surfaced as SQLSTATE 23514,
/// which nothing maps, so it became a `500` on `POST /api/v1/auth/login` for any
/// client whose `User-Agent` was longer than 200 characters. Found by
/// `tests/hardening/log_injection.rs`; see
/// `docs/backend/audit/SECTION_9_13_FINDINGS.md` §11 finding H-2.
pub fn sanitize_bounded(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut out = String::with_capacity(input.len().min(max_chars * 4));
    let mut chars = input.chars();

    for taken in 0..max_chars {
        let Some(ch) = chars.next() else { break };

        // On the last slot we may write, spend it on the marker rather than on a
        // character — but only if there is genuinely more input after `ch`.
        // Cloning `Chars` is a pointer copy, so the lookahead costs nothing.
        if taken == max_chars - 1 && chars.clone().next().is_some() {
            out.push('…');
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
        // Ten characters *including* the marker: callers pass the width of a
        // database column, so returning `max_chars + 1` produced a row the schema
        // refused and a `500` in its place.
        assert_eq!(out.chars().count(), 10);
        assert!(out.ends_with('…'));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    /// The boundary, from both sides. Exactly `max_chars` characters of input must
    /// survive whole — appending a marker to a value that was not truncated would
    /// be both a lie and, at a column's exact width, an error.
    #[test]
    fn the_bound_is_never_exceeded_at_any_input_length() {
        for max in [1usize, 2, 10, 45, 200] {
            for length in [0usize, 1, max.saturating_sub(1), max, max + 1, max * 10] {
                let out = sanitize_bounded(&"a".repeat(length), max);
                assert!(
                    out.chars().count() <= max,
                    "max={max} length={length} produced {} characters",
                    out.chars().count()
                );
                if length <= max {
                    assert_eq!(out, "a".repeat(length), "max={max} length={length}");
                } else {
                    assert!(out.ends_with('…'), "max={max} length={length}");
                }
            }
        }
        assert_eq!(sanitize_bounded("anything", 0), "");
    }

    /// The width every session hint is stored at. `sessions.user_agent_hint` is
    /// `CHECK (length(user_agent_hint) <= 200)`, so this is the assertion that the
    /// row is insertable.
    #[test]
    fn a_header_hint_always_fits_the_column_it_is_stored_in() {
        for length in [199usize, 200, 201, 1_000, 100_000] {
            let hint = header_hint(Some(&"u".repeat(length)), MAX_LOGGED_LEN)
                .expect("non-empty input yields a hint");
            assert!(
                hint.chars().count() <= MAX_LOGGED_LEN,
                "a {length}-character header produced a {}-character hint",
                hint.chars().count()
            );
        }
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
