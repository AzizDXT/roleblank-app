//! The central endpoint registry: every path this API serves, written down once.
//!
//! `ROUTE_TABLE` in `crate::routes` is the authority on *what is served* and how it
//! is protected. This module is the authority on *what the URL is*, so that no call
//! site — a test, a client generator, an operational script — has to spell a path out
//! by hand and drift from the router. The test at the bottom asserts that the two
//! describe exactly the same set of paths, in both directions, so adding a route
//! without registering it here fails the build, and registering a path that nothing
//! serves fails it too.
//!
//! `api/endpoints.json` is the same registry as data, for clients that are not Rust.
//! It is generated from the same source and carries the permission, the step-up flag
//! and the principal types alongside each path.

/// The API version segment, without slashes.
pub const API_VERSION: &str = "v1";

/// The prefix every versioned route sits under. Health and metrics deliberately do
/// not: probes and scrapers are not part of the versioned contract.
pub const API_PREFIX: &str = "/api/v1";

/// Sessions, tokens, passwords and MFA — every way a principal proves who it
/// is. The anonymous entry points live here too, which is why `REGISTRATION`
/// and `REGISTRATION_CONFIG` are grouped here despite not sitting under
/// `/api/v1/auth`: they are part of the same unauthenticated onboarding
/// surface, and a reader looking for "how does somebody get in" should find
/// them in one place.
pub mod auth {
    /// `POST /api/v1/auth/login`
    pub const LOGIN: &str = "/api/v1/auth/login";
    /// `POST /api/v1/auth/refresh`
    pub const REFRESH: &str = "/api/v1/auth/refresh";
    /// `POST /api/v1/auth/logout`
    pub const LOGOUT: &str = "/api/v1/auth/logout";
    /// `POST /api/v1/auth/logout-all`
    pub const LOGOUT_ALL: &str = "/api/v1/auth/logout-all";
    /// `GET /api/v1/auth/me`
    pub const ME: &str = "/api/v1/auth/me";
    /// `GET /api/v1/auth/sessions`
    pub const SESSIONS: &str = "/api/v1/auth/sessions";
    /// `DELETE /api/v1/auth/sessions/{id}`
    pub const SESSION_BY_ID: &str = "/api/v1/auth/sessions/{id}";
    /// `POST /api/v1/auth/password/change`
    pub const PASSWORD_CHANGE: &str = "/api/v1/auth/password/change";
    /// `POST /api/v1/auth/password-reset/request`
    pub const PASSWORD_RESET_REQUEST: &str = "/api/v1/auth/password-reset/request";
    /// `POST /api/v1/auth/password-reset/confirm`
    pub const PASSWORD_RESET_CONFIRM: &str = "/api/v1/auth/password-reset/confirm";
    /// `POST /api/v1/auth/mfa/totp/setup`
    pub const MFA_TOTP_SETUP: &str = "/api/v1/auth/mfa/totp/setup";
    /// `POST /api/v1/auth/mfa/totp/activate`
    pub const MFA_TOTP_ACTIVATE: &str = "/api/v1/auth/mfa/totp/activate";
    /// `POST /api/v1/auth/mfa/verify`
    pub const MFA_VERIFY: &str = "/api/v1/auth/mfa/verify";
    /// `POST /api/v1/auth/mfa/recovery/verify`
    pub const MFA_RECOVERY_VERIFY: &str = "/api/v1/auth/mfa/recovery/verify";
    /// `POST /api/v1/auth/mfa/recovery/regenerate`
    pub const MFA_RECOVERY_REGENERATE: &str = "/api/v1/auth/mfa/recovery/regenerate";
    /// `POST /api/v1/auth/mfa/disable`
    pub const MFA_DISABLE: &str = "/api/v1/auth/mfa/disable";
    /// `GET /api/v1/registration/config`
    pub const REGISTRATION_CONFIG: &str = "/api/v1/registration/config";
    /// `POST /api/v1/registration`
    pub const REGISTRATION: &str = "/api/v1/registration";
}

/// One-time creation of the system owner. Anonymous by necessity.
pub mod bootstrap {
    /// `GET /api/v1/bootstrap/status`
    pub const STATUS: &str = "/api/v1/bootstrap/status";
    /// `POST /api/v1/bootstrap/root`
    pub const ROOT: &str = "/api/v1/bootstrap/root";
}

/// User accounts. There is no create and no delete: an account comes into
/// existence through invitation, self-registration or bootstrap, and leaves
/// only by being archived.
pub mod users {
    /// `GET /api/v1/users`
    pub const ROOT: &str = "/api/v1/users";
    /// `GET | PATCH /api/v1/users/{id}`
    pub const BY_ID: &str = "/api/v1/users/{id}";
    /// `POST /api/v1/users/{id}/suspend`
    pub const SUSPEND: &str = "/api/v1/users/{id}/suspend";
    /// `POST /api/v1/users/{id}/reactivate`
    pub const REACTIVATE: &str = "/api/v1/users/{id}/reactivate";
    /// `POST /api/v1/users/{id}/archive`
    pub const ARCHIVE: &str = "/api/v1/users/{id}/archive";
}

/// Issuing, listing and revoking invitations, plus the anonymous endpoint
/// that redeems one.
pub mod invitations {
    /// `POST /api/v1/invitations/accept`
    pub const ACCEPT: &str = "/api/v1/invitations/accept";
    /// `GET | POST /api/v1/invitations`
    pub const ROOT: &str = "/api/v1/invitations";
    /// `DELETE /api/v1/invitations/{id}`
    pub const BY_ID: &str = "/api/v1/invitations/{id}";
}

/// Roles and role assignment. Everything that grants authority is behind
/// step-up.
pub mod roles {
    /// `GET | POST /api/v1/roles`
    pub const ROOT: &str = "/api/v1/roles";
    /// `DELETE | GET | PATCH /api/v1/roles/{id}`
    pub const BY_ID: &str = "/api/v1/roles/{id}";
    /// `GET | POST /api/v1/users/{id}/roles`
    pub const FOR_USER: &str = "/api/v1/users/{id}/roles";
    /// `DELETE /api/v1/users/{id}/roles/{role_id}`
    pub const FOR_USER_BY_ID: &str = "/api/v1/users/{id}/roles/{role_id}";
}

/// The compiled permission catalogue, effective permissions, and per-user
/// overrides.
pub mod permissions {
    /// `GET /api/v1/permissions`
    pub const ROOT: &str = "/api/v1/permissions";
    /// `GET /api/v1/users/{id}/permissions`
    pub const EFFECTIVE_FOR_USER: &str = "/api/v1/users/{id}/permissions";
    /// `GET | POST /api/v1/users/{id}/permission-overrides`
    pub const OVERRIDES_FOR_USER: &str = "/api/v1/users/{id}/permission-overrides";
    /// `DELETE /api/v1/users/{id}/permission-overrides/{override_id}`
    pub const OVERRIDE_BY_ID: &str = "/api/v1/users/{id}/permission-overrides/{override_id}";
}

/// Internal company structure. Flat by design.
pub mod departments {
    /// `GET | POST /api/v1/departments`
    pub const ROOT: &str = "/api/v1/departments";
    /// `GET | PATCH /api/v1/departments/{id}`
    pub const BY_ID: &str = "/api/v1/departments/{id}";
    /// `POST /api/v1/departments/{id}/archive`
    pub const ARCHIVE: &str = "/api/v1/departments/{id}/archive";
    /// `GET | POST /api/v1/departments/{id}/members`
    pub const MEMBERS: &str = "/api/v1/departments/{id}/members";
    /// `DELETE /api/v1/departments/{id}/members/{user_id}`
    pub const MEMBER_BY_ID: &str = "/api/v1/departments/{id}/members/{user_id}";
}

/// External client businesses and their memberships.
pub mod clients {
    /// `GET | POST /api/v1/clients`
    pub const ROOT: &str = "/api/v1/clients";
    /// `GET | PATCH /api/v1/clients/{id}`
    pub const BY_ID: &str = "/api/v1/clients/{id}";
    /// `POST /api/v1/clients/{id}/archive`
    pub const ARCHIVE: &str = "/api/v1/clients/{id}/archive";
    /// `GET | POST /api/v1/clients/{id}/members`
    pub const MEMBERS: &str = "/api/v1/clients/{id}/members";
    /// `POST /api/v1/clients/{id}/members/{user_id}/activate`
    pub const MEMBER_ACTIVATE: &str = "/api/v1/clients/{id}/members/{user_id}/activate";
    /// `DELETE /api/v1/clients/{id}/members/{user_id}`
    pub const MEMBER_BY_ID: &str = "/api/v1/clients/{id}/members/{user_id}";
}

/// Projects, their internal members, and the client shares that cross the
/// external trust boundary.
pub mod projects {
    /// `GET | POST /api/v1/projects`
    pub const ROOT: &str = "/api/v1/projects";
    /// `GET | PATCH /api/v1/projects/{id}`
    pub const BY_ID: &str = "/api/v1/projects/{id}";
    /// `POST /api/v1/projects/{id}/archive`
    pub const ARCHIVE: &str = "/api/v1/projects/{id}/archive";
    /// `GET | POST /api/v1/projects/{id}/members`
    pub const MEMBERS: &str = "/api/v1/projects/{id}/members";
    /// `DELETE /api/v1/projects/{id}/members/{user_id}`
    pub const MEMBER_BY_ID: &str = "/api/v1/projects/{id}/members/{user_id}";
    /// `GET | POST /api/v1/projects/{id}/clients`
    pub const CLIENTS: &str = "/api/v1/projects/{id}/clients";
    /// `DELETE /api/v1/projects/{id}/clients/{client_account_id}`
    pub const CLIENT_BY_ID: &str = "/api/v1/projects/{id}/clients/{client_account_id}";
    /// `GET /api/v1/projects/{project_id}/tasks`
    pub const TASKS: &str = "/api/v1/projects/{project_id}/tasks";
}

/// Tasks and their assignees.
pub mod tasks {
    /// `GET | POST /api/v1/tasks`
    pub const ROOT: &str = "/api/v1/tasks";
    /// `DELETE | GET | PATCH /api/v1/tasks/{id}`
    pub const BY_ID: &str = "/api/v1/tasks/{id}";
    /// `GET | POST /api/v1/tasks/{id}/assignees`
    pub const ASSIGNEES: &str = "/api/v1/tasks/{id}/assignees";
    /// `DELETE /api/v1/tasks/{id}/assignees/{user_id}`
    pub const ASSIGNEE_BY_ID: &str = "/api/v1/tasks/{id}/assignees/{user_id}";
}

/// The only business surface an external `CLIENT` principal may reach, and
/// read-only throughout.
pub mod client_portal {
    /// `GET /api/v1/client-portal/projects`
    pub const PROJECTS: &str = "/api/v1/client-portal/projects";
    /// `GET /api/v1/client-portal/projects/{id}`
    pub const PROJECT_BY_ID: &str = "/api/v1/client-portal/projects/{id}";
    /// `GET /api/v1/client-portal/projects/{id}/tasks`
    pub const PROJECT_TASKS: &str = "/api/v1/client-portal/projects/{id}/tasks";
    /// `GET /api/v1/client-portal/tasks/{id}`
    pub const TASK_BY_ID: &str = "/api/v1/client-portal/tasks/{id}";
}

/// System settings, feature flags and the authenticated environment
/// description.
pub mod settings {
    /// `GET /api/v1/settings`
    pub const ROOT: &str = "/api/v1/settings";
    /// `PUT /api/v1/settings/{key}`
    pub const BY_KEY: &str = "/api/v1/settings/{key}";
    /// `GET /api/v1/feature-flags`
    pub const FEATURE_FLAGS: &str = "/api/v1/feature-flags";
    /// `PUT /api/v1/feature-flags/{key}`
    pub const FEATURE_FLAG_BY_KEY: &str = "/api/v1/feature-flags/{key}";
    /// `GET /api/v1/system/info`
    pub const SYSTEM_INFO: &str = "/api/v1/system/info";
}

/// The append-only audit log. Read only: nothing here writes, edits or
/// deletes an event.
pub mod audit {
    /// `GET /api/v1/audit/events`
    pub const EVENTS: &str = "/api/v1/audit/events";
    /// `GET /api/v1/audit/events/{id}`
    pub const EVENT_BY_ID: &str = "/api/v1/audit/events/{id}";
    /// `GET /api/v1/audit/verify`
    pub const VERIFY: &str = "/api/v1/audit/verify";
}

/// Liveness, readiness and the Prometheus scrape. Anonymous by necessity.
pub mod health {
    /// `GET /health/live`
    pub const LIVE: &str = "/health/live";
    /// `GET /health/ready`
    pub const READY: &str = "/health/ready";
    /// `GET /metrics`
    pub const METRICS: &str = "/metrics";
}

/// Every registered pattern, in one slice.
///
/// The order is the order of `ROUTE_TABLE`, which groups by area rather than
/// alphabetically, so a reviewer reading the two side by side sees the same shape.
pub const ALL: &[&str] = &[
    health::LIVE,
    health::READY,
    health::METRICS,
    bootstrap::STATUS,
    bootstrap::ROOT,
    auth::LOGIN,
    auth::REFRESH,
    auth::LOGOUT,
    auth::LOGOUT_ALL,
    auth::ME,
    auth::SESSIONS,
    auth::SESSION_BY_ID,
    auth::PASSWORD_CHANGE,
    auth::PASSWORD_RESET_REQUEST,
    auth::PASSWORD_RESET_CONFIRM,
    auth::MFA_TOTP_SETUP,
    auth::MFA_TOTP_ACTIVATE,
    auth::MFA_VERIFY,
    auth::MFA_RECOVERY_VERIFY,
    auth::MFA_RECOVERY_REGENERATE,
    auth::MFA_DISABLE,
    auth::REGISTRATION_CONFIG,
    auth::REGISTRATION,
    invitations::ACCEPT,
    users::ROOT,
    users::BY_ID,
    users::SUSPEND,
    users::REACTIVATE,
    users::ARCHIVE,
    invitations::ROOT,
    invitations::BY_ID,
    permissions::ROOT,
    roles::ROOT,
    roles::BY_ID,
    roles::FOR_USER,
    roles::FOR_USER_BY_ID,
    permissions::EFFECTIVE_FOR_USER,
    permissions::OVERRIDES_FOR_USER,
    permissions::OVERRIDE_BY_ID,
    departments::ROOT,
    departments::BY_ID,
    departments::ARCHIVE,
    departments::MEMBERS,
    departments::MEMBER_BY_ID,
    clients::ROOT,
    clients::BY_ID,
    clients::ARCHIVE,
    clients::MEMBERS,
    clients::MEMBER_ACTIVATE,
    clients::MEMBER_BY_ID,
    projects::ROOT,
    projects::BY_ID,
    projects::ARCHIVE,
    projects::MEMBERS,
    projects::MEMBER_BY_ID,
    projects::CLIENTS,
    projects::CLIENT_BY_ID,
    projects::TASKS,
    tasks::ROOT,
    tasks::BY_ID,
    tasks::ASSIGNEES,
    tasks::ASSIGNEE_BY_ID,
    client_portal::PROJECTS,
    client_portal::PROJECT_BY_ID,
    client_portal::PROJECT_TASKS,
    client_portal::TASK_BY_ID,
    settings::ROOT,
    settings::BY_KEY,
    settings::FEATURE_FLAGS,
    settings::FEATURE_FLAG_BY_KEY,
    settings::SYSTEM_INFO,
    audit::EVENTS,
    audit::EVENT_BY_ID,
    audit::VERIFY,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn registry() -> BTreeSet<&'static str> {
        ALL.iter().copied().collect()
    }

    fn router() -> BTreeSet<&'static str> {
        crate::routes::ROUTE_TABLE.iter().map(|r| r.path).collect()
    }

    /// `ALL` must not repeat itself, or the set comparison below would hide a
    /// copy-paste mistake behind deduplication.
    #[test]
    fn the_registry_lists_every_pattern_once() {
        let mut seen = BTreeSet::new();
        for path in ALL {
            assert!(seen.insert(*path), "`{path}` is listed twice in ALL");
        }
        assert_eq!(seen.len(), ALL.len());
    }

    /// The whole point of the module. A readable diff in both directions, because
    /// the two failure modes have different fixes: a missing entry means somebody
    /// added a route without registering it, and an extra entry means somebody left
    /// a path here after deleting the route.
    #[test]
    fn the_registry_and_the_route_table_describe_the_same_paths() {
        let registry = registry();
        let router = router();

        let missing: Vec<_> = router.difference(&registry).collect();
        let extra: Vec<_> = registry.difference(&router).collect();

        assert!(
            missing.is_empty(),
            "ROUTE_TABLE serves paths the endpoint registry does not list: {missing:#?}\n\
             add them to the matching `pub mod` in platform::http::endpoints and to ALL"
        );
        assert!(
            extra.is_empty(),
            "the endpoint registry lists paths ROUTE_TABLE does not serve: {extra:#?}\n\
             remove them, or add the route to crate::routes::ROUTE_TABLE"
        );
        assert_eq!(registry, router);
    }

    /// Every versioned pattern must actually start with the prefix this module
    /// publishes, so that `API_PREFIX` stays a fact rather than a comment.
    #[test]
    fn every_versioned_pattern_starts_with_the_prefix() {
        for path in ALL {
            let unversioned = path.starts_with("/health/") || *path == "/metrics";
            assert!(
                unversioned || path.starts_with(API_PREFIX),
                "`{path}` is neither a probe nor under `{API_PREFIX}`"
            );
        }
        assert!(API_PREFIX.ends_with(API_VERSION));
    }
}
