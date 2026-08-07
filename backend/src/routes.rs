//! The canonical route table.
//!
//! Every route the application serves is composed here, and the `ROUTE_TABLE`
//! constant below is the machine-readable description of that composition. It has
//! two jobs:
//!
//!   1. it is the single place a reviewer can see the whole authenticated surface,
//!      including which routes are anonymous and which require step-up;
//!   2. it drives the OpenAPI drift test — `tests/openapi_contract.rs` asserts that
//!      `api/openapi.yaml` describes exactly these `(method, path)` pairs. Adding an
//!      endpoint without documenting it fails the build (ADR-001).

use axum::Router;

use crate::app::AppState;
use crate::platform::http::middleware;

/// How a route is protected. Kept as data so the OpenAPI test can assert that a
/// route documented as anonymous really is anonymous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reachable without authentication. Every entry here is a deliberate decision.
    Anonymous,
    /// Requires a valid session that has completed MFA.
    Authenticated,
    /// Reachable by a session that has authenticated with a password but not yet
    /// completed MFA. Only the MFA endpoints.
    MfaPending,
}

#[derive(Debug, Clone, Copy)]
pub struct RouteSpec {
    pub method: &'static str,
    /// The pattern, not a concrete path — `/api/v1/projects/{id}`.
    pub path: &'static str,
    pub access: Access,
    /// The permission the handler requires, if any.
    pub permission: Option<&'static str>,
    /// Whether the handler additionally requires a recent second factor.
    pub step_up: bool,
}

const fn r(
    method: &'static str,
    path: &'static str,
    access: Access,
    permission: Option<&'static str>,
    step_up: bool,
) -> RouteSpec {
    RouteSpec {
        method,
        path,
        access,
        permission,
        step_up,
    }
}

use Access::{Anonymous, Authenticated, MfaPending};

/// The complete surface.
pub const ROUTE_TABLE: &[RouteSpec] = &[
    // --- health and platform (anonymous by necessity) ------------------------
    r("GET", "/health/live", Anonymous, None, false),
    r("GET", "/health/ready", Anonymous, None, false),
    r("GET", "/metrics", Anonymous, None, false),
    // --- bootstrap ------------------------------------------------------------
    // Anonymous by necessity: before the owner exists there is nobody to
    // authenticate as. Both are rate limited, and `status` reveals only a boolean.
    r("GET", "/api/v1/bootstrap/status", Anonymous, None, false),
    r("POST", "/api/v1/bootstrap/root", Anonymous, None, false),
    // --- authentication -------------------------------------------------------
    r("POST", "/api/v1/auth/login", Anonymous, None, false),
    r("POST", "/api/v1/auth/refresh", Anonymous, None, false),
    r("POST", "/api/v1/auth/logout", Authenticated, None, false),
    r(
        "POST",
        "/api/v1/auth/logout-all",
        Authenticated,
        None,
        false,
    ),
    r("GET", "/api/v1/auth/me", MfaPending, None, false),
    r("GET", "/api/v1/auth/sessions", Authenticated, None, false),
    r(
        "DELETE",
        "/api/v1/auth/sessions/{id}",
        Authenticated,
        None,
        false,
    ),
    r(
        "POST",
        "/api/v1/auth/password/change",
        Authenticated,
        None,
        false,
    ),
    r(
        "POST",
        "/api/v1/auth/password-reset/request",
        Anonymous,
        None,
        false,
    ),
    r(
        "POST",
        "/api/v1/auth/password-reset/confirm",
        Anonymous,
        None,
        false,
    ),
    // MFA endpoints accept an MFA-pending session — that is the whole point of the
    // pending state, and the reason `Authenticated` refuses it everywhere else.
    r(
        "POST",
        "/api/v1/auth/mfa/totp/setup",
        MfaPending,
        None,
        false,
    ),
    r(
        "POST",
        "/api/v1/auth/mfa/totp/activate",
        MfaPending,
        None,
        false,
    ),
    r("POST", "/api/v1/auth/mfa/verify", MfaPending, None, false),
    r(
        "POST",
        "/api/v1/auth/mfa/recovery/verify",
        MfaPending,
        None,
        false,
    ),
    r(
        "POST",
        "/api/v1/auth/mfa/recovery/regenerate",
        Authenticated,
        None,
        true,
    ),
    r(
        "POST",
        "/api/v1/auth/mfa/disable",
        Authenticated,
        None,
        true,
    ),
    // --- registration ---------------------------------------------------------
    r("GET", "/api/v1/registration/config", Anonymous, None, false),
    r("POST", "/api/v1/registration", Anonymous, None, false),
    r("POST", "/api/v1/invitations/accept", Anonymous, None, false),
    // --- users ----------------------------------------------------------------
    r(
        "GET",
        "/api/v1/users",
        Authenticated,
        Some("iam.users.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/users/{id}",
        Authenticated,
        Some("iam.users.read"),
        false,
    ),
    r(
        "PATCH",
        "/api/v1/users/{id}",
        Authenticated,
        Some("iam.users.update"),
        false,
    ),
    r(
        "POST",
        "/api/v1/users/{id}/suspend",
        Authenticated,
        Some("iam.users.suspend"),
        false,
    ),
    r(
        "POST",
        "/api/v1/users/{id}/reactivate",
        Authenticated,
        Some("iam.users.suspend"),
        false,
    ),
    r(
        "POST",
        "/api/v1/users/{id}/archive",
        Authenticated,
        Some("iam.users.archive"),
        false,
    ),
    // --- invitations ----------------------------------------------------------
    r(
        "GET",
        "/api/v1/invitations",
        Authenticated,
        Some("iam.users.invite"),
        false,
    ),
    r(
        "POST",
        "/api/v1/invitations",
        Authenticated,
        Some("iam.users.invite"),
        false,
    ),
    r(
        "DELETE",
        "/api/v1/invitations/{id}",
        Authenticated,
        Some("iam.users.invite"),
        false,
    ),
    // --- roles and permissions ------------------------------------------------
    r(
        "GET",
        "/api/v1/permissions",
        Authenticated,
        Some("iam.permissions.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/roles",
        Authenticated,
        Some("iam.roles.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/roles",
        Authenticated,
        Some("iam.roles.create"),
        true,
    ),
    r(
        "GET",
        "/api/v1/roles/{id}",
        Authenticated,
        Some("iam.roles.read"),
        false,
    ),
    r(
        "PATCH",
        "/api/v1/roles/{id}",
        Authenticated,
        Some("iam.roles.update"),
        true,
    ),
    r(
        "DELETE",
        "/api/v1/roles/{id}",
        Authenticated,
        Some("iam.roles.delete"),
        true,
    ),
    r(
        "GET",
        "/api/v1/users/{id}/roles",
        Authenticated,
        Some("iam.roles.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/users/{id}/roles",
        Authenticated,
        Some("iam.roles.assign"),
        true,
    ),
    r(
        "DELETE",
        "/api/v1/users/{id}/roles/{role_id}",
        Authenticated,
        Some("iam.roles.assign"),
        true,
    ),
    r(
        "GET",
        "/api/v1/users/{id}/permissions",
        Authenticated,
        Some("iam.permissions.read"),
        false,
    ),
    // Reading a subject's overrides is `iam.permissions.read`, not `delegate`:
    // seeing which exceptions exist is an inspection, not a grant, and an auditor
    // needs it without being handed the ability to change them.
    //
    // This route was implemented before it was declared here, which meant the
    // OpenAPI drift test could not see it — the test compares this table against
    // the spec, so a route missing from *both* is invisible to it. Found during
    // the application-structure review and recorded in
    // `docs/product/01-application-structure.md` §11.
    r(
        "GET",
        "/api/v1/users/{id}/permission-overrides",
        Authenticated,
        Some("iam.permissions.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/users/{id}/permission-overrides",
        Authenticated,
        Some("iam.permissions.delegate"),
        true,
    ),
    r(
        "DELETE",
        "/api/v1/users/{id}/permission-overrides/{override_id}",
        Authenticated,
        Some("iam.permissions.delegate"),
        true,
    ),
    // --- departments ----------------------------------------------------------
    r(
        "GET",
        "/api/v1/departments",
        Authenticated,
        Some("departments.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/departments",
        Authenticated,
        Some("departments.create"),
        false,
    ),
    r(
        "GET",
        "/api/v1/departments/{id}",
        Authenticated,
        Some("departments.read"),
        false,
    ),
    r(
        "PATCH",
        "/api/v1/departments/{id}",
        Authenticated,
        Some("departments.update"),
        false,
    ),
    r(
        "POST",
        "/api/v1/departments/{id}/archive",
        Authenticated,
        Some("departments.archive"),
        false,
    ),
    r(
        "GET",
        "/api/v1/departments/{id}/members",
        Authenticated,
        Some("departments.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/departments/{id}/members",
        Authenticated,
        Some("departments.members.manage"),
        false,
    ),
    r(
        "DELETE",
        "/api/v1/departments/{id}/members/{user_id}",
        Authenticated,
        Some("departments.members.manage"),
        false,
    ),
    // --- client accounts ------------------------------------------------------
    r(
        "GET",
        "/api/v1/clients",
        Authenticated,
        Some("clients.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/clients",
        Authenticated,
        Some("clients.create"),
        false,
    ),
    r(
        "GET",
        "/api/v1/clients/{id}",
        Authenticated,
        Some("clients.read"),
        false,
    ),
    r(
        "PATCH",
        "/api/v1/clients/{id}",
        Authenticated,
        Some("clients.update"),
        false,
    ),
    r(
        "POST",
        "/api/v1/clients/{id}/archive",
        Authenticated,
        Some("clients.archive"),
        false,
    ),
    r(
        "GET",
        "/api/v1/clients/{id}/members",
        Authenticated,
        Some("clients.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/clients/{id}/members",
        Authenticated,
        Some("clients.members.manage"),
        false,
    ),
    r(
        "POST",
        "/api/v1/clients/{id}/members/{user_id}/activate",
        Authenticated,
        Some("clients.members.manage"),
        false,
    ),
    r(
        "DELETE",
        "/api/v1/clients/{id}/members/{user_id}",
        Authenticated,
        Some("clients.members.manage"),
        false,
    ),
    // --- projects -------------------------------------------------------------
    r(
        "GET",
        "/api/v1/projects",
        Authenticated,
        Some("projects.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/projects",
        Authenticated,
        Some("projects.create"),
        false,
    ),
    r(
        "GET",
        "/api/v1/projects/{id}",
        Authenticated,
        Some("projects.read"),
        false,
    ),
    r(
        "PATCH",
        "/api/v1/projects/{id}",
        Authenticated,
        Some("projects.update"),
        false,
    ),
    r(
        "POST",
        "/api/v1/projects/{id}/archive",
        Authenticated,
        Some("projects.archive"),
        false,
    ),
    r(
        "GET",
        "/api/v1/projects/{id}/members",
        Authenticated,
        Some("projects.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/projects/{id}/members",
        Authenticated,
        Some("projects.members.manage"),
        false,
    ),
    r(
        "DELETE",
        "/api/v1/projects/{id}/members/{user_id}",
        Authenticated,
        Some("projects.members.manage"),
        false,
    ),
    r(
        "GET",
        "/api/v1/projects/{id}/clients",
        Authenticated,
        Some("projects.read"),
        false,
    ),
    // Crossing the external trust boundary. Dangerous, therefore step-up.
    r(
        "POST",
        "/api/v1/projects/{id}/clients",
        Authenticated,
        Some("projects.clients.share"),
        true,
    ),
    r(
        "DELETE",
        "/api/v1/projects/{id}/clients/{client_account_id}",
        Authenticated,
        Some("projects.clients.share"),
        true,
    ),
    r(
        "GET",
        "/api/v1/projects/{project_id}/tasks",
        Authenticated,
        Some("tasks.read"),
        false,
    ),
    // --- tasks ----------------------------------------------------------------
    r(
        "GET",
        "/api/v1/tasks",
        Authenticated,
        Some("tasks.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/tasks",
        Authenticated,
        Some("tasks.create"),
        false,
    ),
    r(
        "GET",
        "/api/v1/tasks/{id}",
        Authenticated,
        Some("tasks.read"),
        false,
    ),
    r(
        "PATCH",
        "/api/v1/tasks/{id}",
        Authenticated,
        Some("tasks.update"),
        false,
    ),
    r(
        "DELETE",
        "/api/v1/tasks/{id}",
        Authenticated,
        Some("tasks.delete"),
        false,
    ),
    // Reading who is assigned is `tasks.read`, not `tasks.assign`: seeing the
    // assignee list is part of reading the task, and requiring the assignment
    // permission to view it would force every reader to hold a write capability.
    //
    // Found undeclared by `tests/router_registry.rs` — the handler was mounted and
    // reachable but appeared in neither this table nor the OpenAPI document, so it
    // had no declared permission and the drift test could not see it. That test
    // exists because the same class of gap was found by hand once already.
    r(
        "GET",
        "/api/v1/tasks/{id}/assignees",
        Authenticated,
        Some("tasks.read"),
        false,
    ),
    r(
        "POST",
        "/api/v1/tasks/{id}/assignees",
        Authenticated,
        Some("tasks.assign"),
        false,
    ),
    r(
        "DELETE",
        "/api/v1/tasks/{id}/assignees/{user_id}",
        Authenticated,
        Some("tasks.assign"),
        false,
    ),
    // --- client portal (the only surface an external principal may reach) -----
    r(
        "GET",
        "/api/v1/client-portal/projects",
        Authenticated,
        Some("client.portal.projects.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/client-portal/projects/{id}",
        Authenticated,
        Some("client.portal.projects.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/client-portal/projects/{id}/tasks",
        Authenticated,
        Some("client.portal.tasks.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/client-portal/tasks/{id}",
        Authenticated,
        Some("client.portal.tasks.read"),
        false,
    ),
    // --- settings and flags ---------------------------------------------------
    r(
        "GET",
        "/api/v1/settings",
        Authenticated,
        Some("settings.read"),
        false,
    ),
    r(
        "PUT",
        "/api/v1/settings/{key}",
        Authenticated,
        Some("settings.features.write"),
        false,
    ),
    r(
        "GET",
        "/api/v1/feature-flags",
        Authenticated,
        Some("settings.read"),
        false,
    ),
    r(
        "PUT",
        "/api/v1/feature-flags/{key}",
        Authenticated,
        Some("settings.features.write"),
        false,
    ),
    r("GET", "/api/v1/system/info", Authenticated, None, false),
    // --- audit (read only, deliberately) --------------------------------------
    r(
        "GET",
        "/api/v1/audit/events",
        Authenticated,
        Some("audit.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/audit/events/{id}",
        Authenticated,
        Some("audit.read"),
        false,
    ),
    r(
        "GET",
        "/api/v1/audit/verify",
        Authenticated,
        Some("audit.read"),
        true,
    ),
];

/// Compose the application router.
///
/// Module routers use two conventions and both are handled explicitly here rather
/// than being normalised, because normalising would mean rewriting paths at
/// composition time and the resulting URL would no longer be greppable from the
/// module that owns it:
///
/// * **Absolute** routers already declare their full path (`/api/v1/projects`, or
///   `/health/live` for the platform endpoints). They are merged at the root.
/// * **Relative** routers declare a path within `/api/v1` (`/roles`, `/settings`),
///   or within their own prefix (`authentication` declares `/login`). They are
///   nested.
///
/// `ROUTE_TABLE` above is the assertion that the result is what was intended; the
/// OpenAPI contract test compares the two.
pub fn build(state: AppState) -> Router {
    // Relative routers, nested under the version prefix.
    let v1 = Router::new()
        .nest("/auth", crate::modules::authentication::router())
        .merge(crate::modules::authorization::routes::router())
        .merge(crate::modules::settings::router())
        .merge(crate::modules::audit::routes::router());

    // Absolute routers, merged at the root.
    let router = Router::new()
        .merge(crate::modules::system::router())
        .merge(crate::modules::bootstrap::router())
        .merge(crate::modules::identity::router())
        .merge(crate::modules::departments::router())
        .merge(crate::modules::clients::router())
        .merge(crate::modules::projects::router())
        .merge(crate::modules::tasks::router())
        .nest("/api/v1", v1);

    middleware::apply(router, &state.config).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::catalog;
    use std::collections::HashSet;

    #[test]
    fn every_declared_permission_exists_in_the_catalogue() {
        for route in ROUTE_TABLE {
            if let Some(code) = route.permission {
                assert!(
                    catalog::exists(code),
                    "{} {} declares `{code}`, which is not in the permission catalogue",
                    route.method,
                    route.path
                );
            }
        }
    }

    /// A permission that no route exercises can be granted, audited and delegated
    /// while doing absolutely nothing. That is worse than a missing permission: it
    /// gives an administrator the impression they have conferred an ability, and it
    /// gives a reviewer a capability to reason about that does not exist.
    ///
    /// The three below are **deliberately reserved** and are named here so that a
    /// *fourth* one appearing is a test failure rather than a discovery months
    /// later. Found by the application-structure review, not by a test — which is
    /// why this test now exists.
    #[test]
    fn every_catalogued_permission_is_either_routed_or_knowingly_reserved() {
        // Enforced by a service *after* the target row is loaded, so it cannot be
        // declared statically on a route. This is the object-level authorisation
        // pattern working as intended, not an omission: whether writing a setting
        // needs `settings.features.write` or `settings.security.write` depends on
        // that row's `is_security_sensitive`, which is unknowable at routing time.
        const ENFORCED_DYNAMICALLY: &[&str] = &["settings.security.write"];

        const KNOWINGLY_RESERVED: &[&str] = &[
            // Users arrive only via bootstrap, invitation or self-registration.
            // Direct creation is deliberately not exposed: it would be a path to an
            // account with no invitation record and no accepted-terms trail.
            "iam.users.create",
            // Administering *other people's* sessions. `GET /auth/sessions` is
            // self-only by design. Exposing these needs its own review — session
            // revocation is an availability weapon as well as a security control.
            "iam.sessions.read",
            "iam.sessions.revoke",
        ];

        let routed: HashSet<&str> = ROUTE_TABLE.iter().filter_map(|r| r.permission).collect();
        let unrouted: Vec<&str> = catalog::PERMISSIONS
            .iter()
            .map(|p| p.code)
            .filter(|code| !routed.contains(code))
            .collect();

        let unexpected: Vec<&&str> = unrouted
            .iter()
            .filter(|code| {
                !KNOWINGLY_RESERVED.contains(code) && !ENFORCED_DYNAMICALLY.contains(code)
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "these permissions are in the catalogue but no route uses them: {unexpected:?}\n\
             Either route them, remove them from the catalogue and the 0008 seed, or add them \
             to KNOWINGLY_RESERVED (with a reason) or ENFORCED_DYNAMICALLY (if a service \
             decides them after loading the target row)."
        );

        let stale: Vec<&&str> = KNOWINGLY_RESERVED
            .iter()
            .chain(ENFORCED_DYNAMICALLY.iter())
            .filter(|code| routed.contains(**code))
            .collect();
        assert!(
            stale.is_empty(),
            "these are listed as reserved or dynamically enforced but are now declared on a \
             route — remove them from that list: {stale:?}"
        );
    }

    #[test]
    fn no_route_is_declared_twice() {
        let mut seen = HashSet::new();
        for route in ROUTE_TABLE {
            assert!(
                seen.insert((route.method, route.path)),
                "duplicate route {} {}",
                route.method,
                route.path
            );
        }
    }

    /// The anonymous surface is the part an unauthenticated attacker can reach, so
    /// it is pinned exactly. Adding to it must be a deliberate, reviewed change,
    /// not something that happens by merging a router.
    #[test]
    fn the_anonymous_surface_is_exactly_what_is_expected() {
        let mut anonymous: Vec<&str> = ROUTE_TABLE
            .iter()
            .filter(|r| r.access == Anonymous)
            .map(|r| r.path)
            .collect();
        anonymous.sort_unstable();
        anonymous.dedup();
        assert_eq!(
            anonymous,
            vec![
                "/api/v1/auth/login",
                "/api/v1/auth/password-reset/confirm",
                "/api/v1/auth/password-reset/request",
                "/api/v1/auth/refresh",
                "/api/v1/bootstrap/root",
                "/api/v1/bootstrap/status",
                "/api/v1/invitations/accept",
                "/api/v1/registration",
                "/api/v1/registration/config",
                "/health/live",
                "/health/ready",
                "/metrics",
            ],
            "the anonymous attack surface changed — review it deliberately"
        );
    }

    #[test]
    fn no_anonymous_route_declares_a_permission() {
        for route in ROUTE_TABLE.iter().filter(|r| r.access == Anonymous) {
            assert!(
                route.permission.is_none(),
                "{} {} is anonymous but declares a permission",
                route.method,
                route.path
            );
            assert!(
                !route.step_up,
                "{} {} is anonymous but requires step-up",
                route.method, route.path
            );
        }
    }

    /// The MFA-pending surface must stay minimal: it is what a password-only
    /// session of a privileged user can reach.
    #[test]
    fn the_mfa_pending_surface_is_minimal() {
        let pending: Vec<&str> = ROUTE_TABLE
            .iter()
            .filter(|r| r.access == MfaPending)
            .map(|r| r.path)
            .collect();
        for path in &pending {
            assert!(
                path.starts_with("/api/v1/auth/mfa/") || *path == "/api/v1/auth/me",
                "`{path}` is reachable by a pending-MFA session but is not an MFA endpoint"
            );
        }
        assert!(
            pending.len() <= 6,
            "the pending-MFA surface grew to {}",
            pending.len()
        );
    }

    /// Every dangerous permission must be behind step-up wherever it is exercised.
    #[test]
    fn dangerous_permissions_are_always_behind_step_up() {
        for route in ROUTE_TABLE {
            let Some(code) = route.permission else {
                continue;
            };
            if catalog::is_dangerous(code) {
                assert!(
                    route.step_up,
                    "{} {} exercises the dangerous permission `{code}` without step-up",
                    route.method, route.path
                );
            }
        }
    }

    /// A `GET` must never change state, so it must never be behind step-up or a
    /// write permission — with one deliberate exception, the audit verification
    /// endpoint, which is a `GET` that is expensive rather than mutating.
    #[test]
    fn get_routes_do_not_declare_write_permissions() {
        for route in ROUTE_TABLE.iter().filter(|r| r.method == "GET") {
            let Some(code) = route.permission else {
                continue;
            };
            let is_write = code.ends_with(".create")
                || code.ends_with(".update")
                || code.ends_with(".delete")
                || code.ends_with(".archive")
                || code.ends_with(".assign")
                || code.ends_with(".write")
                || code.ends_with(".manage")
                || code.ends_with(".share")
                || code.ends_with(".delegate")
                || code.ends_with(".revoke")
                || code.ends_with(".suspend");
            assert!(
                !is_write,
                "GET {} declares the write permission `{code}` — state-changing GET is forbidden",
                route.path
            );
        }
    }

    #[test]
    fn client_portal_routes_are_read_only_and_use_portal_permissions() {
        for route in ROUTE_TABLE
            .iter()
            .filter(|r| r.path.starts_with("/api/v1/client-portal"))
        {
            assert_eq!(route.method, "GET", "the client portal is read-only");
            let code = route
                .permission
                .expect("client portal routes must declare a permission");
            assert!(
                code.starts_with("client.portal."),
                "{} uses `{code}`, which is not a client-portal permission",
                route.path
            );
        }
    }

    /// A route pattern must use `{name}` placeholders, never a concrete id — the
    /// metrics layer labels by pattern, and a concrete path would make label
    /// cardinality unbounded.
    #[test]
    fn paths_are_patterns_not_concrete_values() {
        for route in ROUTE_TABLE {
            assert!(
                route.path.starts_with('/'),
                "`{}` must be absolute",
                route.path
            );
            assert!(
                !route.path.ends_with('/'),
                "`{}` must not have a trailing slash",
                route.path
            );
            assert!(
                !route.path.contains("//"),
                "`{}` contains an empty segment",
                route.path
            );
            for segment in route.path.split('/').filter(|s| !s.is_empty()) {
                if segment.contains('{') {
                    assert!(
                        segment.starts_with('{') && segment.ends_with('}'),
                        "`{}` has a malformed placeholder",
                        route.path
                    );
                }
            }
        }
    }
}
