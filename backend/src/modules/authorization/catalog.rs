//! The canonical permission catalogue.
//!
//! This table and the `permissions` table in migration `0008_seed_catalog.sql` must
//! agree exactly. `verify_against_database` is called at startup and **refuses to
//! boot on divergence**, because either direction of drift is a security problem:
//!
//!   * in code but not in the database → every check for it denies, silently
//!     breaking a feature in a way that looks like a permissions misconfiguration;
//!   * in the database but not in code → an ungoverned grant that nothing enforces.

use super::domain::{MaxPrincipalType, PrincipalType};

#[derive(Debug, Clone, Copy)]
pub struct PermissionDef {
    pub code: &'static str,
    pub module: &'static str,
    /// The ceiling on who may hold it. This is the client security envelope.
    pub max_principal_type: MaxPrincipalType,
    /// Granting or exercising it requires a recent step-up, and mandates that the
    /// holder has MFA enrolled.
    pub is_dangerous: bool,
}

use MaxPrincipalType::{Any, Internal};

/// Sorted by module, then code. Keep it sorted — the startup diff reports
/// differences positionally and an unsorted table makes that noise.
pub const PERMISSIONS: &[PermissionDef] = &[
    // --- audit ---------------------------------------------------------------
    PermissionDef {
        code: "audit.read",
        module: "audit",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    // --- client portal (the ONLY codes an external principal can ever hold) ---
    PermissionDef {
        code: "client.portal.projects.read",
        module: "client_portal",
        max_principal_type: Any,
        is_dangerous: false,
    },
    PermissionDef {
        code: "client.portal.tasks.read",
        module: "client_portal",
        max_principal_type: Any,
        is_dangerous: false,
    },
    // --- clients -------------------------------------------------------------
    PermissionDef {
        code: "clients.archive",
        module: "clients",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "clients.create",
        module: "clients",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "clients.members.manage",
        module: "clients",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "clients.read",
        module: "clients",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "clients.update",
        module: "clients",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    // --- departments ---------------------------------------------------------
    PermissionDef {
        code: "departments.archive",
        module: "departments",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "departments.create",
        module: "departments",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "departments.members.manage",
        module: "departments",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "departments.read",
        module: "departments",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "departments.update",
        module: "departments",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    // --- iam -----------------------------------------------------------------
    // `delegate` and `assign` are how authority actually reaches a person, so both
    // are dangerous. `sessions.revoke` is dangerous because it is an availability
    // weapon as well as a security control.
    PermissionDef {
        code: "iam.permissions.delegate",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: true,
    },
    PermissionDef {
        code: "iam.permissions.read",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.roles.assign",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: true,
    },
    PermissionDef {
        code: "iam.roles.create",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.roles.delete",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.roles.read",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.roles.update",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.sessions.read",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.sessions.revoke",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: true,
    },
    PermissionDef {
        code: "iam.users.archive",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.users.create",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.users.invite",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.users.read",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.users.suspend",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "iam.users.update",
        module: "iam",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    // --- projects ------------------------------------------------------------
    // Sharing is the control that moves company data across the external trust
    // boundary — the most consequential business permission in the system.
    PermissionDef {
        code: "projects.archive",
        module: "projects",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "projects.clients.share",
        module: "projects",
        max_principal_type: Internal,
        is_dangerous: true,
    },
    PermissionDef {
        code: "projects.create",
        module: "projects",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "projects.members.manage",
        module: "projects",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "projects.read",
        module: "projects",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "projects.update",
        module: "projects",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    // --- settings ------------------------------------------------------------
    PermissionDef {
        code: "settings.features.write",
        module: "settings",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "settings.read",
        module: "settings",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "settings.security.write",
        module: "settings",
        max_principal_type: Internal,
        is_dangerous: true,
    },
    // --- tasks ---------------------------------------------------------------
    PermissionDef {
        code: "tasks.assign",
        module: "tasks",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "tasks.create",
        module: "tasks",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "tasks.delete",
        module: "tasks",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "tasks.read",
        module: "tasks",
        max_principal_type: Internal,
        is_dangerous: false,
    },
    PermissionDef {
        code: "tasks.update",
        module: "tasks",
        max_principal_type: Internal,
        is_dangerous: false,
    },
];

/// Look up a permission. `None` is a hard DENY at the evaluator, never a fallthrough.
pub fn get(code: &str) -> Option<&'static PermissionDef> {
    PERMISSIONS.iter().find(|p| p.code == code)
}

pub fn exists(code: &str) -> bool {
    get(code).is_some()
}

pub fn is_dangerous(code: &str) -> bool {
    get(code).map(|p| p.is_dangerous).unwrap_or(false)
}

/// Whether a principal type could hold this permission at all, ignoring grants.
pub fn envelope_permits(code: &str, principal: PrincipalType) -> bool {
    match get(code) {
        // Unknown permission: deny. Never "permit and let a later check catch it".
        None => false,
        Some(p) => p.max_principal_type.permits(principal),
    }
}

/// Compare the compiled catalogue with what the database holds.
///
/// Returns a human-readable description of every difference, or `None` when they
/// agree. The caller aborts startup on `Some`.
pub fn diff_against(
    db_rows: &[(String, String, String, bool)], // (code, module, max_principal_type, is_dangerous)
) -> Option<String> {
    let mut problems: Vec<String> = Vec::new();

    for def in PERMISSIONS {
        match db_rows.iter().find(|(code, _, _, _)| code == def.code) {
            None => problems.push(format!(
                "`{}` exists in the code catalogue but not in the permissions table",
                def.code
            )),
            Some((_, module, max_principal, dangerous)) => {
                if module != def.module {
                    problems.push(format!(
                        "`{}` module differs: code=`{}` database=`{}`",
                        def.code, def.module, module
                    ));
                }
                if max_principal != def.max_principal_type.as_str() {
                    problems.push(format!(
                        "`{}` max_principal_type differs: code=`{}` database=`{}` \
                         (this is the client security envelope — refusing to run)",
                        def.code,
                        def.max_principal_type.as_str(),
                        max_principal
                    ));
                }
                if *dangerous != def.is_dangerous {
                    problems.push(format!(
                        "`{}` is_dangerous differs: code={} database={}",
                        def.code, def.is_dangerous, dangerous
                    ));
                }
            }
        }
    }

    for (code, _, _, _) in db_rows {
        if !exists(code) {
            problems.push(format!(
                "`{code}` exists in the permissions table but not in the code catalogue \
                 (an ungoverned grant — refusing to run)"
            ));
        }
    }

    if problems.is_empty() {
        None
    } else {
        Some(problems.join("\n  - "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique() {
        let mut seen = HashSet::new();
        for p in PERMISSIONS {
            assert!(
                seen.insert(p.code),
                "duplicate permission code `{}`",
                p.code
            );
        }
    }

    #[test]
    fn codes_match_the_database_check_constraint() {
        // `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` — at least two dot-separated
        // segments, lowercase, starting with a letter. A code that fails this would
        // be rejected by PostgreSQL at seed time, so it is asserted here where the
        // failure is cheap to diagnose.
        for p in PERMISSIONS {
            let segments: Vec<&str> = p.code.split('.').collect();
            assert!(
                segments.len() >= 2,
                "`{}` needs at least two segments",
                p.code
            );
            for seg in segments {
                assert!(!seg.is_empty(), "`{}` has an empty segment", p.code);
                let mut chars = seg.chars();
                let first = chars.next().expect("non-empty");
                assert!(
                    first.is_ascii_lowercase(),
                    "`{}` segment must start with a-z",
                    p.code
                );
                assert!(
                    seg.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "`{}` contains an illegal character",
                    p.code
                );
            }
        }
    }

    #[test]
    fn the_table_is_sorted() {
        let codes: Vec<&str> = PERMISSIONS.iter().map(|p| p.code).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted, "keep PERMISSIONS sorted by code");
    }

    /// The single most important property of this file. If a non-`client.portal.*`
    /// permission ever becomes `Any`, a CLIENT principal could hold internal
    /// authority — the exact failure the envelope exists to prevent.
    #[test]
    fn only_client_portal_permissions_are_reachable_by_external_principals() {
        for p in PERMISSIONS {
            let client_reachable = p.max_principal_type.permits(PrincipalType::Client);
            let is_portal = p.code.starts_with("client.portal.");
            assert_eq!(
                client_reachable, is_portal,
                "`{}` reachability by CLIENT principals must match its namespace",
                p.code
            );
        }
    }

    #[test]
    fn client_reachable_permissions_are_read_only() {
        // An external principal must never hold a mutating capability. If this ever
        // needs to change, it needs an ADR, not a table edit.
        for p in PERMISSIONS
            .iter()
            .filter(|p| p.max_principal_type.permits(PrincipalType::Client))
        {
            assert!(
                p.code.ends_with(".read"),
                "`{}` is reachable by CLIENT principals but is not a read",
                p.code
            );
            assert!(
                !p.is_dangerous,
                "`{}` must not be both client-reachable and dangerous",
                p.code
            );
        }
    }

    #[test]
    fn the_dangerous_set_is_exactly_what_the_documentation_claims() {
        let mut dangerous: Vec<&str> = PERMISSIONS
            .iter()
            .filter(|p| p.is_dangerous)
            .map(|p| p.code)
            .collect();
        dangerous.sort_unstable();
        assert_eq!(
            dangerous,
            vec![
                "iam.permissions.delegate",
                "iam.roles.assign",
                "iam.sessions.revoke",
                "projects.clients.share",
                "settings.security.write",
            ],
            "the dangerous set changed; update docs/backend/04-authorization.md §3 too"
        );
    }

    #[test]
    fn unknown_codes_deny_rather_than_fall_through() {
        assert!(!exists("iam.users.delete"));
        assert!(!exists(""));
        assert!(!exists("*"));
        assert!(!exists("iam.*"));
        assert!(!envelope_permits(
            "not.a.permission",
            PrincipalType::Internal
        ));
        assert!(!envelope_permits("not.a.permission", PrincipalType::Client));
        assert!(!is_dangerous("not.a.permission"));
    }

    #[test]
    fn envelope_permits_matches_the_table() {
        assert!(envelope_permits(
            "client.portal.projects.read",
            PrincipalType::Client
        ));
        assert!(envelope_permits(
            "client.portal.projects.read",
            PrincipalType::Internal
        ));
        assert!(!envelope_permits("audit.read", PrincipalType::Client));
        assert!(envelope_permits("audit.read", PrincipalType::Internal));
    }

    #[test]
    fn diff_reports_both_directions_and_attribute_drift() {
        let mut rows: Vec<(String, String, String, bool)> = PERMISSIONS
            .iter()
            .map(|p| {
                (
                    p.code.to_string(),
                    p.module.to_string(),
                    p.max_principal_type.as_str().to_string(),
                    p.is_dangerous,
                )
            })
            .collect();
        assert!(
            diff_against(&rows).is_none(),
            "an identical set must not diff"
        );

        // Extra row in the database.
        rows.push((
            "ghost.permission".into(),
            "ghost".into(),
            "INTERNAL".into(),
            false,
        ));
        let d = diff_against(&rows).expect("should diff");
        assert!(d.contains("ghost.permission"));
        assert!(d.contains("ungoverned grant"));
        rows.pop();

        // Envelope drift — the most dangerous possible divergence.
        let idx = rows
            .iter()
            .position(|(c, _, _, _)| c == "audit.read")
            .unwrap();
        rows[idx].2 = "ANY".into();
        let d = diff_against(&rows).expect("should diff");
        assert!(d.contains("client security envelope"), "{d}");
        rows[idx].2 = "INTERNAL".into();

        // Missing row in the database.
        rows.retain(|(c, _, _, _)| c != "audit.read");
        let d = diff_against(&rows).expect("should diff");
        assert!(d.contains("not in the permissions table"));
    }
}
