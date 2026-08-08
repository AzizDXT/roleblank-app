//! Cursor pagination with allowlisted sorting.
//!
//! Two things this module refuses to do, and why:
//!
//! **Offset pagination.** `OFFSET 100000` makes PostgreSQL walk and discard a
//! hundred thousand rows, so a client can turn a cheap endpoint into an expensive
//! one by incrementing a number (TH-33). Cursors are keyset-based and cost the
//! same at page 1 and page 10 000.
//!
//! **Client-supplied sort columns.** `ORDER BY $user_input` cannot be
//! parameterised, so it is either an allowlist or it is SQL injection. Every
//! sortable field here maps to a `&'static str` chosen at compile time; the user's
//! string is only ever *compared*, never interpolated.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::platform::errors::AppError;

pub const DEFAULT_PAGE_SIZE: u32 = 25;
pub const MAX_PAGE_SIZE: u32 = 100;

/// A keyset cursor: the sort key of the last row on the previous page.
///
/// `(created_at, id)` because `created_at` alone is not unique — two rows created
/// in the same microsecond would make a page boundary ambiguous and could silently
/// skip or repeat a row. UUIDv7 as the tiebreaker keeps the pair total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub timestamp_micros: i64,
    pub id: Uuid,
}

impl Cursor {
    /// Opaque to the client on purpose: an encoded blob discourages hand-crafting
    /// cursors, and lets the internal representation change without breaking
    /// clients. It is *not* a security boundary — it is not signed, and a forged
    /// cursor can only reposition a query the caller was already authorised to run.
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(24);
        raw.extend_from_slice(&self.timestamp_micros.to_be_bytes());
        raw.extend_from_slice(self.id.as_bytes());
        data_encoding::BASE64URL_NOPAD.encode(&raw)
    }

    pub fn decode(encoded: &str) -> Result<Self, AppError> {
        // Bound the input before decoding: an unbounded base64 blob is free work
        // for an attacker.
        if encoded.len() > 64 {
            return Err(AppError::field(
                "cursor",
                "INVALID",
                "Malformed pagination cursor.",
            ));
        }
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| AppError::field("cursor", "INVALID", "Malformed pagination cursor."))?;
        if raw.len() != 24 {
            return Err(AppError::field(
                "cursor",
                "INVALID",
                "Malformed pagination cursor.",
            ));
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&raw[..8]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&raw[8..]);
        Ok(Self {
            timestamp_micros: i64::from_be_bytes(ts),
            id: Uuid::from_bytes(id),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    /// A `&'static str`, never a formatted user string.
    pub fn sql(self) -> &'static str {
        match self {
            SortDirection::Asc => "ASC",
            SortDirection::Desc => "DESC",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "asc" => Some(SortDirection::Asc),
            "desc" => Some(SortDirection::Desc),
            _ => None,
        }
    }
}

/// Raw query parameters, exactly as they arrive. Deliberately all `Option<String>`
/// so that a malformed value produces a validation error rather than a serde
/// rejection with a less useful message.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    pub cursor: Option<String>,
    pub limit: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
}

/// A validated page request. Constructing one is the only way to reach the SQL.
#[derive(Debug, Clone)]
pub struct PageRequest {
    pub cursor: Option<Cursor>,
    pub limit: u32,
    /// Guaranteed to be one of the caller's allowlisted `&'static str` values.
    pub sort_column: &'static str,
    pub direction: SortDirection,
}

impl PageRequest {
    /// Validate raw parameters against an allowlist.
    ///
    /// `allowed_sorts` maps the public field name to the **compile-time** SQL
    /// column expression. The user's string never reaches the query — only the
    /// static value it selected does.
    pub fn resolve(
        query: &PageQuery,
        allowed_sorts: &[(&'static str, &'static str)],
        default_sort: &'static str,
        max_page_size: u32,
    ) -> Result<Self, AppError> {
        let limit = match &query.limit {
            None => DEFAULT_PAGE_SIZE.min(max_page_size),
            Some(raw) => {
                let parsed: u32 = raw.trim().parse().map_err(|_| {
                    AppError::field("limit", "INVALID", "`limit` must be a positive integer.")
                })?;
                if parsed == 0 {
                    return Err(AppError::field(
                        "limit",
                        "OUT_OF_RANGE",
                        "`limit` must be at least 1.",
                    ));
                }
                if parsed > max_page_size {
                    return Err(AppError::field(
                        "limit",
                        "OUT_OF_RANGE",
                        format!("`limit` must not exceed {max_page_size}."),
                    ));
                }
                parsed
            }
        };

        let sort_column = match &query.sort {
            None => default_sort,
            Some(requested) => allowed_sorts
                .iter()
                .find(|(public, _)| *public == requested.trim())
                .map(|(_, column)| *column)
                .ok_or_else(|| {
                    // The allowed set is echoed because it is public API surface,
                    // not internal schema. The rejected value is NOT echoed.
                    AppError::field(
                        "sort",
                        "NOT_ALLOWED",
                        format!(
                            "Sortable fields: {}",
                            allowed_sorts
                                .iter()
                                .map(|(p, _)| *p)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                })?,
        };

        let direction = match &query.direction {
            None => SortDirection::Desc,
            Some(raw) => SortDirection::parse(raw.trim()).ok_or_else(|| {
                AppError::field(
                    "direction",
                    "INVALID",
                    "`direction` must be `asc` or `desc`.",
                )
            })?,
        };

        let cursor = match &query.cursor {
            None => None,
            Some(raw) => Some(Cursor::decode(raw)?),
        };

        Ok(Self {
            cursor,
            limit,
            sort_column,
            direction,
        })
    }

    /// Fetch one extra row to determine whether another page exists, without a
    /// second `COUNT(*)` query.
    pub fn fetch_limit(&self) -> i64 {
        i64::from(self.limit) + 1
    }
}

/// The envelope every collection endpoint returns.
#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl<T> Page<T> {
    /// Build a page from `limit + 1` rows.
    pub fn build(
        mut rows: Vec<T>,
        request: &PageRequest,
        cursor_of: impl Fn(&T) -> Cursor,
    ) -> Self {
        let has_more = rows.len() > request.limit as usize;
        if has_more {
            rows.truncate(request.limit as usize);
        }
        let next_cursor = if has_more {
            rows.last().map(|row| cursor_of(row).encode())
        } else {
            None
        };
        Self {
            items: rows,
            next_cursor,
            has_more,
        }
    }

    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            has_more: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: &[(&str, &str)] = &[
        ("created_at", "p.created_at"),
        ("name", "p.name"),
        ("status", "p.status"),
    ];

    fn q(
        limit: Option<&str>,
        sort: Option<&str>,
        dir: Option<&str>,
        cursor: Option<&str>,
    ) -> PageQuery {
        PageQuery {
            cursor: cursor.map(str::to_string),
            limit: limit.map(str::to_string),
            sort: sort.map(str::to_string),
            direction: dir.map(str::to_string),
        }
    }

    #[test]
    fn cursors_round_trip() {
        let c = Cursor {
            timestamp_micros: 1_700_000_000_123_456,
            id: Uuid::now_v7(),
        };
        assert_eq!(Cursor::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn malformed_cursors_are_rejected_without_panicking() {
        for bad in [
            "",
            "!!!",
            "AAAA",
            "x",
            &"A".repeat(1000),
            &"A".repeat(100_000),
        ] {
            assert!(Cursor::decode(bad).is_err(), "accepted {bad:?}");
        }
        // Right alphabet, wrong length.
        assert!(Cursor::decode(&data_encoding::BASE64URL_NOPAD.encode(&[0u8; 23])).is_err());
        assert!(Cursor::decode(&data_encoding::BASE64URL_NOPAD.encode(&[0u8; 25])).is_err());
    }

    /// The single most important test in this file.
    #[test]
    fn sort_fields_outside_the_allowlist_are_refused() {
        let attacks = [
            "created_at; DROP TABLE users--",
            "(SELECT password_hash FROM credentials)",
            "created_at, (SELECT 1)",
            "p.internal_note",
            "1",
            "*",
            "",
            " created_at ; --",
        ];
        for attack in attacks {
            let err = PageRequest::resolve(
                &q(None, Some(attack), None, None),
                ALLOWED,
                "p.created_at",
                100,
            )
            .unwrap_err();
            let AppError::Validation { errors } = &err else {
                panic!("expected validation error for {attack:?}");
            };
            assert_eq!(errors[0].code, "NOT_ALLOWED");
            // The rejected value must not be reflected back.
            assert!(
                !errors[0].message.contains("DROP"),
                "rejected input was echoed"
            );
        }
    }

    #[test]
    fn an_allowlisted_sort_resolves_to_the_static_column() {
        let r = PageRequest::resolve(
            &q(None, Some("name"), None, None),
            ALLOWED,
            "p.created_at",
            100,
        )
        .unwrap();
        assert_eq!(r.sort_column, "p.name");
        // Whitespace around a legitimate value is tolerated.
        let r = PageRequest::resolve(
            &q(None, Some("  status "), None, None),
            ALLOWED,
            "p.created_at",
            100,
        )
        .unwrap();
        assert_eq!(r.sort_column, "p.status");
    }

    #[test]
    fn limits_are_bounded_at_both_ends() {
        assert_eq!(
            PageRequest::resolve(&q(None, None, None, None), ALLOWED, "p.created_at", 100)
                .unwrap()
                .limit,
            DEFAULT_PAGE_SIZE
        );
        assert!(PageRequest::resolve(
            &q(Some("0"), None, None, None),
            ALLOWED,
            "p.created_at",
            100
        )
        .is_err());
        assert!(PageRequest::resolve(
            &q(Some("101"), None, None, None),
            ALLOWED,
            "p.created_at",
            100
        )
        .is_err());
        assert!(PageRequest::resolve(
            &q(Some("999999999"), None, None, None),
            ALLOWED,
            "p.created_at",
            100
        )
        .is_err());
        assert!(PageRequest::resolve(
            &q(Some("-1"), None, None, None),
            ALLOWED,
            "p.created_at",
            100
        )
        .is_err());
        assert!(PageRequest::resolve(
            &q(Some("abc"), None, None, None),
            ALLOWED,
            "p.created_at",
            100
        )
        .is_err());
        assert!(PageRequest::resolve(
            &q(Some("1e9"), None, None, None),
            ALLOWED,
            "p.created_at",
            100
        )
        .is_err());
        assert_eq!(
            PageRequest::resolve(
                &q(Some("100"), None, None, None),
                ALLOWED,
                "p.created_at",
                100
            )
            .unwrap()
            .limit,
            100
        );
    }

    #[test]
    fn the_configured_maximum_is_honoured() {
        // A deployment that lowers the cap must not be overridden by a client.
        assert!(PageRequest::resolve(
            &q(Some("50"), None, None, None),
            ALLOWED,
            "p.created_at",
            25
        )
        .is_err());
        assert_eq!(
            PageRequest::resolve(&q(None, None, None, None), ALLOWED, "p.created_at", 10)
                .unwrap()
                .limit,
            10,
            "the default is clamped to the configured maximum"
        );
    }

    #[test]
    fn direction_is_an_enum_not_a_string() {
        assert_eq!(
            PageRequest::resolve(
                &q(None, None, Some("asc"), None),
                ALLOWED,
                "p.created_at",
                100
            )
            .unwrap()
            .direction
            .sql(),
            "ASC"
        );
        for bad in ["ASC", "ascending", "asc; DROP TABLE users", ""] {
            assert!(PageRequest::resolve(
                &q(None, None, Some(bad), None),
                ALLOWED,
                "p.created_at",
                100
            )
            .is_err());
        }
    }

    #[test]
    fn page_building_detects_more_and_trims_the_probe_row() {
        let req = PageRequest::resolve(
            &q(Some("3"), None, None, None),
            ALLOWED,
            "p.created_at",
            100,
        )
        .unwrap();
        assert_eq!(req.fetch_limit(), 4);

        let rows: Vec<i64> = vec![1, 2, 3, 4];
        let page = Page::build(rows, &req, |n| Cursor {
            timestamp_micros: *n,
            id: Uuid::from_u128(*n as u128),
        });
        assert!(page.has_more);
        assert_eq!(page.items, vec![1, 2, 3]);
        assert!(page.next_cursor.is_some());

        let page = Page::build(vec![1i64, 2], &req, |n| Cursor {
            timestamp_micros: *n,
            id: Uuid::from_u128(*n as u128),
        });
        assert!(!page.has_more);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn an_empty_page_is_well_formed() {
        let p: Page<i64> = Page::empty();
        assert!(p.items.is_empty());
        assert!(!p.has_more);
        assert_eq!(p.next_cursor, None);
    }
}
