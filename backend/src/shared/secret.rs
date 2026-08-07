//! A wrapper that makes accidental disclosure of a secret hard.
//!
//! `Secret<T>` redacts itself in `Debug` and has no `Display`, so a secret cannot
//! reach a log line, a `dbg!`, a panic message, or a `#[derive(Debug)]` struct
//! print by accident. Reading the real value requires calling `expose()`, which is
//! deliberately ugly and greppable: `rg 'expose\(\)'` enumerates every place a
//! secret is unwrapped, and that list is short enough to review.
//!
//! It also zeroises on drop, which limits how long the plaintext lingers in
//! memory after use. That is hardening, not a guarantee — the value may have been
//! copied during a move before the wrapper ever existed.

use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T: Zeroize + Default>(T);

impl<T: Zeroize + Default> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Read the protected value.
    ///
    /// Every call site is a place where a secret becomes ordinary data. Keep them
    /// few, keep them short, and never pass the result to anything that formats.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Take the value out, leaving a default behind so `Drop` has nothing to wipe.
    pub fn into_inner(mut self) -> T {
        std::mem::take(&mut self.0)
    }
}

impl<T: Zeroize + Default> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<T: Zeroize + Default> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Deliberately NOT implemented, and this list is the whole point of the type:
//   - Display          would let `{}` print it
//   - Serialize        would let it enter a JSON response or an audit payload
//   - Deref / AsRef    would make `expose()` avoidable and un-greppable
//   - PartialEq<&str>  would encourage non-constant-time comparison

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_the_value() {
        let s = Secret::new("hunter2-super-secret".to_string());
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn debug_of_a_containing_struct_is_also_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Config {
            name: &'static str,
            key: Secret<String>,
        }
        let c = Config {
            name: "db",
            key: Secret::new("p@ssw0rd".into()),
        };
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains("p@ssw0rd"),
            "secret leaked through a derived Debug"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn expose_and_into_inner_return_the_value() {
        let s = Secret::new(vec![1u8, 2, 3]);
        assert_eq!(s.expose(), &vec![1u8, 2, 3]);
        assert_eq!(Secret::new("abc".to_string()).into_inner(), "abc");
    }
}
