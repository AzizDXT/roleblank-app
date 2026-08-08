//! Request and response types for the authorization HTTP surface.
//!
//! Request and response types are never the same struct (MODULE_GUIDE §3.3). Every
//! request DTO here is closed with `deny_unknown_fields`, and none of them carries
//! `id`, `is_system`, `granted_by`, `created_by`, `security_version` or
//! `principal_type` for the *actor* — those are either server-assigned or loaded
//! from the database. `version` appears exactly once, on the role update request,
//! where it is the optimistic-concurrency token rather than a writable field.
//!
//! Timestamps cross the wire as RFC 3339 strings rather than as `OffsetDateTime`.
//! `time`'s default `serde` impl is not RFC 3339 (the `serde-well-known` feature is
//! not enabled in this crate), and an API that emits `2026-08-07 9:31:00.0 +00:00:00`
//! because nobody checked the feature flags is a contract accident waiting to happen.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ===========================================================================
// Requests
// ===========================================================================

/// One `(permission, scope)` pair inside a role.
///
/// There is deliberately no `resource_type`/`resource_id` here: a role is a
/// reusable template and cannot name a specific object, so the fields a
/// `RESOURCE` scope would need are *physically absent* rather than validated away
/// (`docs/backend/04-authorization.md` §4).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePermissionInput {
    pub permission_code: String,
    /// `GLOBAL` | `DEPARTMENT` | `ASSIGNED` | `SELF`.
    pub scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRoleRequest {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// `INTERNAL` | `CLIENT`. Fixed at creation: changing it later would move an
    /// existing permission set across the client envelope.
    pub allowed_principal_type: String,
    #[serde(default)]
    pub permissions: Vec<RolePermissionInput>,
}

/// `code` and `allowed_principal_type` are absent on purpose.
///
/// A role code is referenced by operators and by seed data, and the principal type
/// is the envelope the role's permission set was authorised against. Both are
/// immutable through this endpoint; a different envelope means a different role.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRoleRequest {
    /// Optimistic concurrency token (MODULE_GUIDE §3.4).
    pub version: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Absent means "leave the permission set alone"; present means "replace it
    /// with exactly this". An empty array is a legitimate request to strip a role.
    #[serde(default)]
    pub permissions: Option<Vec<RolePermissionInput>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignRoleRequest {
    pub role_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOverrideRequest {
    pub permission_code: String,
    /// `ALLOW` | `DENY`.
    pub effect: String,
    /// `GLOBAL` | `DEPARTMENT` | `ASSIGNED` | `SELF` | `RESOURCE`.
    pub scope: String,
    /// Required with, and only with, `RESOURCE` scope.
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub resource_id: Option<Uuid>,
    /// RFC 3339. Must be in the future when present.
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

// ===========================================================================
// Responses
// ===========================================================================

#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    pub code: &'static str,
    pub module: &'static str,
    /// `INTERNAL` = internal principals only; `ANY` = a CLIENT may hold it.
    pub max_principal_type: &'static str,
    /// Granting *or* exercising it requires a recent step-up.
    pub is_dangerous: bool,
}

#[derive(Debug, Serialize)]
pub struct PermissionCatalogueResponse {
    pub items: Vec<PermissionResponse>,
}

#[derive(Debug, Serialize)]
pub struct RoleGrantResponse {
    pub permission_code: String,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct RoleSummaryResponse {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub allowed_principal_type: String,
    pub version: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct RoleDetailResponse {
    #[serde(flatten)]
    pub role: RoleSummaryResponse,
    pub permissions: Vec<RoleGrantResponse>,
}

#[derive(Debug, Serialize)]
pub struct UserRoleResponse {
    pub role_id: Uuid,
    pub code: String,
    pub name: String,
    pub is_system: bool,
    pub allowed_principal_type: String,
    pub granted_by: Option<Uuid>,
    pub granted_at: String,
}

#[derive(Debug, Serialize)]
pub struct UserRolesResponse {
    pub user_id: Uuid,
    pub items: Vec<UserRoleResponse>,
}

#[derive(Debug, Serialize)]
pub struct CapabilityResponse {
    pub permission_code: &'static str,
    /// Every scope the subject effectively holds for this permission.
    pub scopes: Vec<&'static str>,
}

/// The subject's effective permissions.
///
/// A *hint* for user interfaces, exactly like `/auth/me`: the backend re-derives
/// every decision per request regardless of what a client believes
/// (`docs/backend/04-authorization.md` §11).
#[derive(Debug, Serialize)]
pub struct EffectivePermissionsResponse {
    pub user_id: Uuid,
    pub principal_type: String,
    pub is_root: bool,
    pub items: Vec<CapabilityResponse>,
}

#[derive(Debug, Serialize)]
pub struct OverrideResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub permission_code: String,
    pub effect: String,
    pub scope: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub expires_at: Option<String>,
    pub reason: String,
    pub granted_by: Uuid,
    pub granted_at: String,
}

#[derive(Debug, Serialize)]
pub struct OverrideListResponse {
    pub user_id: Uuid,
    pub items: Vec<OverrideResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TH-12 — mass assignment. Every one of these fields exists on the underlying
    /// row and none of them may be steered from a request body. `deny_unknown_fields`
    /// turns each into a rejection rather than a silently ignored field.
    #[test]
    fn privileged_fields_are_refused_on_role_creation() {
        for attack in [
            r#"{"code":"x","name":"X","allowed_principal_type":"INTERNAL","permissions":[],"is_system":true}"#,
            r#"{"code":"x","name":"X","allowed_principal_type":"INTERNAL","permissions":[],"id":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"x","name":"X","allowed_principal_type":"INTERNAL","permissions":[],"version":9}"#,
            r#"{"code":"x","name":"X","allowed_principal_type":"INTERNAL","permissions":[],"created_by":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"x","name":"X","allowed_principal_type":"INTERNAL","permissions":[],"granted_by":"00000000-0000-0000-0000-000000000001"}"#,
            r#"{"code":"x","name":"X","allowed_principal_type":"INTERNAL","permissions":[],"created_at":"2026-01-01T00:00:00Z"}"#,
        ] {
            assert!(
                serde_json::from_str::<CreateRoleRequest>(attack).is_err(),
                "accepted a privileged field: {attack}"
            );
        }

        // The legitimate shape still parses.
        let ok: CreateRoleRequest = serde_json::from_str(
            r#"{"code":"field_manager","name":"Field Manager","description":"d",
                "allowed_principal_type":"INTERNAL",
                "permissions":[{"permission_code":"projects.read","scope":"DEPARTMENT"}]}"#,
        )
        .expect("the documented shape must parse");
        assert_eq!(ok.permissions.len(), 1);
    }

    #[test]
    fn a_role_permission_cannot_smuggle_a_resource_object() {
        // RESOURCE scope needs these two fields; refusing them at the type level is
        // what makes "roles never name an object" structural rather than a check
        // someone can forget.
        assert!(serde_json::from_str::<RolePermissionInput>(
            r#"{"permission_code":"projects.read","scope":"RESOURCE",
                "resource_type":"PROJECT","resource_id":"00000000-0000-0000-0000-000000000001"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<RolePermissionInput>(
            r#"{"permission_code":"projects.read","scope":"GLOBAL"}"#
        )
        .is_ok());
    }

    #[test]
    fn role_update_accepts_version_and_nothing_else_privileged() {
        let ok: UpdateRoleRequest =
            serde_json::from_str(r#"{"version":3,"name":"New name"}"#).expect("valid");
        assert_eq!(ok.version, 3);
        assert!(
            ok.permissions.is_none(),
            "absent permissions must stay absent, not become empty"
        );

        // An explicit empty list is a real instruction and must be distinguishable.
        let stripped: UpdateRoleRequest =
            serde_json::from_str(r#"{"version":3,"permissions":[]}"#).expect("valid");
        assert_eq!(stripped.permissions.map(|p| p.len()), Some(0));

        for attack in [
            r#"{"version":1,"is_system":false}"#,
            r#"{"version":1,"code":"renamed"}"#,
            r#"{"version":1,"allowed_principal_type":"CLIENT"}"#,
            r#"{"version":1,"id":"00000000-0000-0000-0000-000000000001"}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateRoleRequest>(attack).is_err(),
                "accepted {attack}"
            );
        }
        // `version` is mandatory: a missing token must not mean "overwrite".
        assert!(serde_json::from_str::<UpdateRoleRequest>(r#"{"name":"x"}"#).is_err());
    }

    #[test]
    fn assignment_and_override_requests_are_closed() {
        assert!(serde_json::from_str::<AssignRoleRequest>(
            r#"{"role_id":"00000000-0000-0000-0000-000000000001","granted_by":"00000000-0000-0000-0000-000000000002"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateOverrideRequest>(
            r#"{"permission_code":"projects.read","effect":"ALLOW","scope":"GLOBAL",
                "granted_by":"00000000-0000-0000-0000-000000000002"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateOverrideRequest>(
            r#"{"permission_code":"projects.read","effect":"ALLOW","scope":"GLOBAL","user_id":"00000000-0000-0000-0000-000000000002"}"#
        )
        .is_err(), "the subject comes from the path, never from the body");

        assert!(serde_json::from_str::<CreateOverrideRequest>(
            r#"{"permission_code":"projects.read","effect":"DENY","scope":"RESOURCE",
                "resource_type":"PROJECT","resource_id":"00000000-0000-0000-0000-000000000001",
                "expires_at":"2027-01-01T00:00:00Z","reason":"incident 42"}"#
        )
        .is_ok());
    }
}
