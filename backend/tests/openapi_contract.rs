//! Drift test: `api/openapi.yaml` must describe exactly the surface that
//! `ROUTE_TABLE` composes — no more, no less (ADR-001).
//!
//! Three properties are asserted, and each of them has caught a different class
//! of mistake in review:
//!
//!   1. **Set equality of `(METHOD, path)`.** Shipping an endpoint nobody
//!      documented is a failure; documenting an endpoint that does not exist is
//!      equally a failure, because a reviewer reading the spec would believe the
//!      attack surface is larger or smaller than it is.
//!   2. **`security: []` exactly on the anonymous routes.** The anonymous
//!      surface is the part an unauthenticated attacker can reach. It is pinned
//!      in `routes.rs` and pinned again here, so widening it silently in one
//!      place fails in the other.
//!   3. **`x-required-permission` agrees with the table.** Without this the
//!      vendor extension is decoration; with it, a reviewer can read the spec
//!      instead of the router and be right.
//!
//! ## Why there is no YAML parser here
//!
//! A full YAML implementation is a large dependency with a wide parsing surface,
//! and pulling one into the build for a single test would mean shipping it in
//! every developer's and every CI job's dependency graph forever. What this test
//! needs is far narrower: the keys at two known indentation levels inside one
//! block of one file we generate ourselves and control the shape of. That is a
//! line scanner, and a line scanner is auditable in one screen.
//!
//! The scanner is deliberately strict about indentation — two spaces for a path,
//! four for a method, six for an operation-level key — so that a reformatted
//! spec fails loudly rather than being silently misread. If the spec is ever
//! restructured, fix the scanner; do not loosen it.
//!
//! This test depends on `roleblank_backend::routes` and nothing else in the
//! crate, so that it keeps compiling while the modules around it are in flux.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use roleblank_backend::routes::{Access, ROUTE_TABLE};

/// What the scanner recovers about one documented operation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SpecOperation {
    /// True when the operation carries `security: []`, i.e. it opts out of the
    /// global bearer requirement.
    security_is_empty: bool,
    /// True when the operation carries a `security:` key at all.
    declares_security: bool,
    /// The value of `x-required-permission`: `None` for the literal `null`.
    required_permission: Option<String>,
    /// The value of `x-requires-step-up`.
    requires_step_up: Option<bool>,
}

type Key = (String, String); // (METHOD, path)

const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

fn spec_path() -> PathBuf {
    // `../api/openapi.yaml`, resolved from the crate root so the test does not
    // depend on the working directory the runner happens to use.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../api/openapi.yaml")
}

/// Extract the operations from the top-level `paths:` block.
///
/// Scanning is confined to that block: it starts at a line that is exactly
/// `paths:` at column zero and stops at the next key at column zero. Everything
/// under `components:` — where descriptions freely mention URL patterns and
/// method names — is therefore never looked at.
fn scan(spec: &str) -> BTreeMap<Key, SpecOperation> {
    let mut out: BTreeMap<Key, SpecOperation> = BTreeMap::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;
    let mut current_key: Option<Key> = None;

    for (number, raw) in spec.lines().enumerate() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }

        // A key at column zero ends the paths block and starts (or continues)
        // some other top-level section.
        if !line.starts_with(' ') {
            in_paths = line.trim_end() == "paths:";
            current_path = None;
            current_key = None;
            continue;
        }
        if !in_paths {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();

        match indent {
            // `  /api/v1/users:`
            2 => {
                let name = body.strip_suffix(':').unwrap_or_else(|| {
                    panic!(
                        "line {}: expected a path key ending in ':', got `{line}`",
                        number + 1
                    )
                });
                assert!(
                    name.starts_with('/'),
                    "line {}: `{name}` is at path-key indentation but is not a path",
                    number + 1
                );
                current_path = Some(name.to_string());
                current_key = None;
            }
            // `    get:`
            4 => {
                let name = body.strip_suffix(':').unwrap_or(body);
                if METHODS.contains(&name) {
                    let path = current_path.clone().unwrap_or_else(|| {
                        panic!("line {}: method `{name}` outside any path", number + 1)
                    });
                    let key = (name.to_ascii_uppercase(), path);
                    assert!(
                        out.insert(key.clone(), SpecOperation::default()).is_none(),
                        "the spec documents {} {} twice",
                        key.0,
                        key.1
                    );
                    current_key = Some(key);
                } else {
                    // A non-method key directly under a path (`parameters:`,
                    // `summary:`) is not an operation.
                    current_key = None;
                }
            }
            // Operation-level keys.
            6 => {
                let Some(key) = current_key.clone() else {
                    continue;
                };
                let entry = out.get_mut(&key).expect("operation was inserted above");
                if let Some(rest) = body.strip_prefix("security:") {
                    entry.declares_security = true;
                    entry.security_is_empty = rest.trim() == "[]";
                } else if let Some(rest) = body.strip_prefix("x-required-permission:") {
                    entry.required_permission = parse_optional_string(rest.trim());
                } else if let Some(rest) = body.strip_prefix("x-requires-step-up:") {
                    entry.requires_step_up = match rest.trim() {
                        "true" => Some(true),
                        "false" => Some(false),
                        other => panic!(
                            "line {}: x-requires-step-up must be true or false, got `{other}`",
                            number + 1
                        ),
                    };
                }
            }
            _ => {}
        }
    }

    out
}

/// `null` -> `None`; `"iam.users.read"` or `iam.users.read` -> `Some(..)`.
fn parse_optional_string(value: &str) -> Option<String> {
    if value == "null" || value == "~" {
        return None;
    }
    let unquoted = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
    Some(unquoted.to_string())
}

fn load() -> BTreeMap<Key, SpecOperation> {
    let path = spec_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "could not read the API contract at {}: {e}\n\
             Every route must be documented before it can be served (ADR-001).",
            path.display()
        )
    });
    let scanned = scan(&text);
    assert!(
        !scanned.is_empty(),
        "no operations were found in {} — the scanner expects two-space indentation for \
         path keys and four for method keys; if the spec was reformatted, fix the scanner",
        path.display()
    );
    scanned
}

fn table() -> BTreeMap<Key, &'static roleblank_backend::routes::RouteSpec> {
    ROUTE_TABLE
        .iter()
        .map(|r| ((r.method.to_string(), r.path.to_string()), r))
        .collect()
}

fn render(keys: &BTreeSet<&Key>) -> String {
    keys.iter().map(|(m, p)| format!("\n    {m} {p}")).collect()
}

#[test]
fn the_spec_documents_exactly_the_routes_the_application_serves() {
    let spec = load();
    let table = table();

    let spec_keys: BTreeSet<&Key> = spec.keys().collect();
    let table_keys: BTreeSet<&Key> = table.keys().collect();

    let undocumented: BTreeSet<&Key> = table_keys.difference(&spec_keys).copied().collect();
    let phantom: BTreeSet<&Key> = spec_keys.difference(&table_keys).copied().collect();

    assert!(
        undocumented.is_empty(),
        "{} route(s) are served but not documented in api/openapi.yaml. Add them to the \
         spec — an endpoint nobody documented is an endpoint nobody reviewed:{}",
        undocumented.len(),
        render(&undocumented)
    );

    assert!(
        phantom.is_empty(),
        "{} operation(s) are documented in api/openapi.yaml but are not in ROUTE_TABLE. \
         Remove them — a spec that describes endpoints which do not exist misleads every \
         reviewer who uses it to reason about the attack surface:{}",
        phantom.len(),
        render(&phantom)
    );

    assert_eq!(
        spec.len(),
        ROUTE_TABLE.len(),
        "the spec and the route table have the same members but different sizes, which \
         means one of them contains a duplicate"
    );
}

#[test]
fn security_is_empty_exactly_on_the_anonymous_routes() {
    let spec = load();

    let mut problems: Vec<String> = Vec::new();
    for route in ROUTE_TABLE {
        let key = (route.method.to_string(), route.path.to_string());
        let Some(op) = spec.get(&key) else { continue }; // reported by the test above
        let anonymous = route.access == Access::Anonymous;

        if anonymous && !op.security_is_empty {
            problems.push(format!(
                "    {} {} is Anonymous in ROUTE_TABLE but the spec {}. Anonymous routes \
                 must carry `security: []` so a reader can see the unauthenticated surface \
                 at a glance.",
                route.method,
                route.path,
                if op.declares_security {
                    "declares a non-empty `security`"
                } else {
                    "inherits the global bearer requirement"
                }
            ));
        }

        if !anonymous && op.declares_security {
            problems.push(format!(
                "    {} {} is {:?} in ROUTE_TABLE but the spec overrides `security`. Only \
                 anonymous routes may opt out of the global bearer requirement.",
                route.method, route.path, route.access
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "{} route(s) disagree with ROUTE_TABLE about authentication:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn the_documented_permission_matches_the_route_table() {
    let spec = load();

    let mut problems: Vec<String> = Vec::new();
    for route in ROUTE_TABLE {
        let key = (route.method.to_string(), route.path.to_string());
        let Some(op) = spec.get(&key) else { continue };

        let documented = op.required_permission.as_deref();
        if documented != route.permission {
            problems.push(format!(
                "    {} {}: ROUTE_TABLE says {:?}, the spec says {:?}",
                route.method, route.path, route.permission, documented
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "{} operation(s) document the wrong `x-required-permission`. This extension is what \
         makes the spec reviewable against the code, so a stale value is worse than no \
         value:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn the_documented_step_up_requirement_matches_the_route_table() {
    let spec = load();

    let mut problems: Vec<String> = Vec::new();
    for route in ROUTE_TABLE {
        let key = (route.method.to_string(), route.path.to_string());
        let Some(op) = spec.get(&key) else { continue };

        match op.requires_step_up {
            None => problems.push(format!(
                "    {} {}: the spec omits `x-requires-step-up`",
                route.method, route.path
            )),
            Some(documented) if documented != route.step_up => problems.push(format!(
                "    {} {}: ROUTE_TABLE says step_up={}, the spec says {}",
                route.method, route.path, route.step_up, documented
            )),
            Some(_) => {}
        }
    }

    assert!(
        problems.is_empty(),
        "{} operation(s) document the wrong `x-requires-step-up`:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A guard on the scanner rather than on the spec: if this stops holding, the
/// three tests above may be passing vacuously.
#[test]
fn the_scanner_recovers_the_extensions_it_claims_to() {
    let spec = load();

    let missing_permission_key: Vec<&Key> = spec
        .iter()
        .filter(|(_, op)| op.required_permission.is_none() && op.requires_step_up.is_none())
        .map(|(k, _)| k)
        .collect();
    assert!(
        missing_permission_key.len() < spec.len(),
        "the scanner recovered no vendor extensions at all — it is almost certainly not \
         reading the file it thinks it is"
    );

    let with_permission = spec
        .values()
        .filter(|o| o.required_permission.is_some())
        .count();
    let expected = ROUTE_TABLE
        .iter()
        .filter(|r| r.permission.is_some())
        .count();
    assert_eq!(
        with_permission, expected,
        "the scanner found {with_permission} operations carrying a permission but \
         ROUTE_TABLE declares {expected}"
    );

    let anonymous_in_spec = spec.values().filter(|o| o.security_is_empty).count();
    let anonymous_in_table = ROUTE_TABLE
        .iter()
        .filter(|r| r.access == Access::Anonymous)
        .count();
    assert_eq!(
        anonymous_in_spec, anonymous_in_table,
        "the spec marks {anonymous_in_spec} operations anonymous, ROUTE_TABLE has \
         {anonymous_in_table}"
    );
}
