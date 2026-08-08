//! Does the code actually serve exactly what the route table claims?
//!
//! ## Why this file exists
//!
//! `tests/openapi_contract.rs` compares `ROUTE_TABLE` against `api/openapi.yaml`.
//! That catches a route declared in one and missing from the other — but a route
//! that exists **in the router and in neither artefact** is invisible to it.
//!
//! That is not hypothetical. `GET /api/v1/users/{id}/permission-overrides` was
//! mounted, reachable, and absent from both. It had no declared permission, the
//! drift test could not see it, and it was found by a human reading the code
//! months of hypothetical production later. This test closes that gap.
//!
//! ## Why it scans source text
//!
//! axum does not expose the composed router's paths for inspection — there is no
//! `router.routes()`. The alternatives were: probe every conceivable URL (unbounded
//! and cannot prove absence), or read what the module actually wrote. The second is
//! deterministic, needs no network, and fails loudly when the two disagree.
//!
//! The sources are pulled in with `include_str!`, so a module file that is renamed
//! or deleted breaks the build rather than silently dropping out of the check.

use std::collections::BTreeSet;

use roleblank_backend::routes::ROUTE_TABLE;

/// Each module's router source, with the prefix `routes::build` mounts it under.
///
/// This mirrors the composition in `src/routes.rs` exactly. If a module's mount
/// point changes there and not here, the paths will not line up and this test
/// fails — which is the intended behaviour, not a maintenance burden.
const MODULE_ROUTERS: &[(&str, &str, &str)] = &[
    // (module name, mount prefix, source text)
    (
        "system",
        "",
        include_str!("../src/modules/system/routes.rs"),
    ),
    (
        "bootstrap",
        "",
        include_str!("../src/modules/bootstrap/routes.rs"),
    ),
    (
        "identity",
        "",
        include_str!("../src/modules/identity/routes.rs"),
    ),
    (
        "departments",
        "",
        include_str!("../src/modules/departments/routes.rs"),
    ),
    (
        "clients",
        "",
        include_str!("../src/modules/clients/routes.rs"),
    ),
    (
        "projects",
        "",
        include_str!("../src/modules/projects/routes.rs"),
    ),
    ("tasks", "", include_str!("../src/modules/tasks/routes.rs")),
    (
        "authentication",
        "/api/v1/auth",
        include_str!("../src/modules/authentication/routes.rs"),
    ),
    (
        "authorization",
        "/api/v1",
        include_str!("../src/modules/authorization/routes.rs"),
    ),
    (
        "settings",
        "/api/v1",
        include_str!("../src/modules/settings/routes.rs"),
    ),
    (
        "audit",
        "/api/v1",
        include_str!("../src/modules/audit/routes.rs"),
    ),
];

/// One `(METHOD, path)` pair a module's source actually registers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Mounted {
    method: String,
    path: String,
    module: &'static str,
}

/// Extract every `.route("<path>", <method>(handler)...)` from a router source.
///
/// Deliberately a small hand-written scanner rather than a Rust parser: pulling in
/// `syn` to read eleven files would add a large dependency to the test build, and
/// the pattern being matched is narrow and stable. The scanner is strict — it
/// understands exactly the form the codebase uses — and `no_module_registers_zero_routes`
/// below fails if the scanner ever stops matching a file, so it cannot silently
/// return nothing and make the whole test vacuous.
fn scan(module: &'static str, prefix: &str, source: &str) -> Vec<Mounted> {
    let mut found = Vec::new();
    let mut rest = source;

    while let Some(at) = rest.find(".route(") {
        rest = &rest[at + ".route(".len()..];

        // Skip whitespace and newlines that rustfmt may have inserted between the
        // opening parenthesis and the path literal.
        let after_paren = rest.trim_start();
        let Some(quoted) = after_paren.strip_prefix('"') else {
            continue; // not a string literal — e.g. `.route(SOME_CONST, ...)`
        };
        let Some(end) = quoted.find('"') else {
            continue;
        };
        let path = &quoted[..end];

        // The methods live between the path literal and the `.route(` call's own
        // closing parenthesis. That boundary is found by matching parentheses, not
        // by looking for the next `.route(`.
        //
        // The looser rule was wrong and produced false positives: the *last*
        // `.route(` in a file has no following one, so its scan ran to end-of-file
        // and picked up `patch(` from an unrelated handler further down — inventing
        // a `PATCH /api/v1/client-portal/projects/{id}` that does not exist. A test
        // that reports a phantom write endpoint on the client portal is worse than
        // no test: it burns the reader's trust on a false alarm.
        //
        // `end + 1` skips the path literal's own closing quote. Starting *on* it
        // flips the parenthesis walker into string mode immediately, and it then
        // treats the whole remaining file as one string literal — the second bug
        // this scanner had, and the reason it now has a test of its own.
        let tail = &quoted[end + 1..];
        let segment = &tail[..route_call_extent(tail)];

        for (needle, method) in [
            ("get(", "GET"),
            ("post(", "POST"),
            ("put(", "PUT"),
            ("patch(", "PATCH"),
            ("delete(", "DELETE"),
        ] {
            if contains_call(segment, needle) {
                found.push(Mounted {
                    method: method.to_string(),
                    path: format!("{prefix}{path}"),
                    module,
                });
            }
        }
    }

    found
}

/// How far the enclosing `.route(...)` call extends, starting from the closing quote
/// of its path literal.
///
/// Walks forward matching parentheses at depth 1 (the `.route(` itself is already
/// open), skipping anything inside a string literal so a `)` in a path or a comment
/// string cannot close the call early.
fn route_call_extent(tail: &str) -> usize {
    let bytes = tail.as_bytes();
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    // Unbalanced source would not compile, so this is unreachable in practice.
    tail.len()
}

/// `segment.contains("get(")` would also match `budget(` or `target(`. Require the
/// character before the needle to be a non-identifier one.
fn contains_call(segment: &str, needle: &str) -> bool {
    let bytes = segment.as_bytes();
    let mut from = 0usize;
    while let Some(at) = segment[from..].find(needle) {
        let absolute = from + at;
        let preceded_by_identifier_char = absolute > 0
            && (bytes[absolute - 1].is_ascii_alphanumeric() || bytes[absolute - 1] == b'_');
        if !preceded_by_identifier_char {
            return true;
        }
        from = absolute + needle.len();
    }
    false
}

fn mounted_routes() -> Vec<Mounted> {
    MODULE_ROUTERS
        .iter()
        .flat_map(|(module, prefix, source)| scan(module, prefix, source))
        .collect()
}

/// Normalise a path parameter name so `{user_id}` and `{id}` at the same position
/// compare equal.
///
/// axum requires consistent parameter names across merged routers at the same
/// position, but the *declared* table and the module may legitimately use different
/// names for the same slot. The names are not part of the contract; the shape is.
fn normalise(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "{param}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn key(method: &str, path: &str) -> String {
    format!("{method} {}", normalise(path))
}

/// The scanner must never silently stop working. If a module's source changes shape
/// and the scanner matches nothing, every other assertion in this file becomes
/// vacuously true — so that condition is itself a failure.
#[test]
fn no_module_registers_zero_routes() {
    for (module, prefix, source) in MODULE_ROUTERS {
        let routes = scan(module, prefix, source);
        assert!(
            !routes.is_empty(),
            "the route scanner matched nothing in `{module}`. Either the module \
             genuinely registers no routes, or its source no longer uses the \
             `.route(\"path\", method(handler))` form this scanner understands — in \
             which case the scanner must be updated, because every other assertion \
             in this file depends on it working."
        );
    }
}

/// **The point of this file.** Every route the code mounts must be declared.
#[test]
fn every_mounted_route_is_declared_in_the_route_table() {
    let declared: BTreeSet<String> = ROUTE_TABLE.iter().map(|r| key(r.method, r.path)).collect();

    let undeclared: Vec<String> = mounted_routes()
        .into_iter()
        .filter(|m| !declared.contains(&key(&m.method, &m.path)))
        .map(|m| format!("{} {}  (mounted by `{}`)", m.method, m.path, m.module))
        .collect();

    assert!(
        undeclared.is_empty(),
        "these routes are served but are NOT in ROUTE_TABLE, so they have no \
         declared permission, are absent from api/openapi.yaml, and the OpenAPI \
         drift test cannot see them:\n  {}\n\n\
         Add them to ROUTE_TABLE and to the OpenAPI document, or remove the handler.",
        undeclared.join("\n  ")
    );
}

/// The other direction: a table entry with no handler is a documented endpoint that
/// returns `404`, which is worse than an undocumented one — a client will build
/// against it.
#[test]
fn every_declared_route_is_actually_mounted() {
    let mounted: BTreeSet<String> = mounted_routes()
        .into_iter()
        .map(|m| key(&m.method, &m.path))
        .collect();

    let phantom: Vec<String> = ROUTE_TABLE
        .iter()
        .map(|r| (r.method, r.path))
        .filter(|(method, path)| !mounted.contains(&key(method, path)))
        .map(|(method, path)| format!("{method} {path}"))
        .collect();

    assert!(
        phantom.is_empty(),
        "these routes are declared in ROUTE_TABLE and documented in the OpenAPI \
         contract, but no module mounts them — a client building against the spec \
         would get 404:\n  {}",
        phantom.join("\n  ")
    );
}

/// A sanity check on the scanner itself, so a bug in it cannot make the two tests
/// above pass by matching nothing useful.
#[test]
fn the_scanner_understands_the_forms_the_codebase_uses() {
    let source = r#"
        Router::new()
            .route("/thing", get(list_things).post(create_thing))
            .route(
                "/thing/{id}",
                get(read_thing).patch(update_thing).delete(remove_thing),
            )
            .route("/budget", get(read_budget))
    }

    // Deliberately placed after the last `.route(`. An earlier version of this
    // scanner ran to end-of-file and attributed these methods to `/budget`,
    // inventing a `PATCH` endpoint that did not exist. Kept balanced so the
    // parenthesis walker sees realistic input.
    async fn unrelated_handler() {
        something.patch(x).post(y).delete(z);
    }
    "#;

    let found = scan("test", "/api/v1", source);
    let keys: BTreeSet<String> = found.iter().map(|m| key(&m.method, &m.path)).collect();

    assert!(keys.contains("GET /api/v1/thing"));
    assert!(keys.contains("POST /api/v1/thing"));
    assert!(keys.contains("GET /api/v1/thing/{param}"));
    assert!(keys.contains("PATCH /api/v1/thing/{param}"));
    assert!(keys.contains("DELETE /api/v1/thing/{param}"));
    assert!(keys.contains("GET /api/v1/budget"));
    // `budget(` must not be mistaken for `get(`, which would invent a phantom route.
    assert_eq!(
        keys.len(),
        6,
        "the scanner produced unexpected entries: {keys:?}"
    );
}

#[test]
fn path_parameter_normalisation_ignores_only_the_name() {
    assert_eq!(
        normalise("/api/v1/users/{user_id}"),
        normalise("/api/v1/users/{id}")
    );
    assert_ne!(
        normalise("/api/v1/users/{id}"),
        normalise("/api/v1/users/{id}/roles")
    );
    assert_ne!(normalise("/api/v1/users"), normalise("/api/v1/clients"));
}
