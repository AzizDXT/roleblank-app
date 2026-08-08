//! The delegation guard — the sharpest privilege-escalation boundary in the system.
//!
//! An administrator granting authority is the operation most worth attacking: it
//! turns a bounded account into an unbounded one, quietly, through a legitimate
//! API. Everything here exists to make "grant yourself more" and "grant someone
//! else more than you have" impossible rather than merely discouraged.
//!
//! Rules implemented (each has a test named after it):
//!   1. an actor cannot grant a permission it does not effectively hold
//!   2. an actor cannot grant a scope it cannot derive from one it holds
//!   3. an actor cannot modify its **own** privileges at all
//!   4. an actor cannot target the system owner
//!   5. an actor cannot touch a system role
//!   6. a role may only be assigned to a matching principal type
//!   7. a DENY on the actor blocks delegation as well as access
//!   8. dangerous permissions additionally require a recent step-up

use uuid::Uuid;

use super::catalog;
use super::domain::{ActorContext, PrincipalType, Scope, ScopeType};
use super::evaluator;
use crate::platform::errors::AppError;

/// Can an actor holding `held` legitimately hand out `requested`?
///
/// The order here is **partial, not total**. `DEPARTMENT` and `ASSIGNED` are
/// incomparable: an actor whose authority stops at their department must not be
/// able to mint `ASSIGNED` authority, because the grantee could then be assigned
/// to a project in a different department — a silent lateral escalation. Treating
/// scopes as a single integer ladder is exactly how that bug ships.
pub fn derivable(held: Scope, requested: Scope) -> bool {
    if !held.is_coherent() || !requested.is_coherent() {
        return false;
    }
    match (held.scope_type, requested.scope_type) {
        // Global authority can hand out anything narrower, including a specific object.
        (ScopeType::Global, _) => true,

        // Department authority can reproduce itself or narrow to SELF. It may NOT
        // produce ASSIGNED (see the module comment) and may not name an arbitrary
        // resource, because it cannot verify that resource is in its department.
        (ScopeType::Department, ScopeType::Department) => true,
        (ScopeType::Department, ScopeType::Own) => true,

        (ScopeType::Assigned, ScopeType::Assigned) => true,
        (ScopeType::Assigned, ScopeType::Own) => true,

        (ScopeType::Own, ScopeType::Own) => true,

        // A resource-scoped holder may pass on exactly that object and nothing else.
        (ScopeType::Resource, ScopeType::Resource) => {
            held.resource_type == requested.resource_type
                && held.resource_id == requested.resource_id
        }

        _ => false,
    }
}

/// Context for a delegation attempt.
pub struct DelegationRequest<'a> {
    pub actor: &'a ActorContext,
    /// The user whose authority is being changed.
    pub subject_id: Uuid,
    pub subject_principal_type: PrincipalType,
    /// Whether the subject is the system owner.
    pub subject_is_root: bool,
    /// Whether the actor's session satisfies the step-up window right now.
    pub has_recent_step_up: bool,
}

/// Check a single `(permission, scope)` the actor wants to grant.
pub fn check_permission_grant(
    req: &DelegationRequest<'_>,
    permission_code: &str,
    requested_scope: Scope,
) -> Result<(), AppError> {
    // Rule 4 — the system owner is never a target of an authorisation operation.
    // Checked first so the error is unmistakable rather than being masked by a
    // generic delegation refusal.
    if req.subject_is_root {
        return Err(AppError::RootProtected);
    }

    // Rule 3 — no self-modification of privilege, ever.
    //
    // This is a refusal, not an analysis. Deciding whether a particular
    // self-change is an escalation is subtle, and subtlety is where the bugs live.
    // ROOT changes privileges for others; nobody changes their own.
    if req.actor.user_id == req.subject_id {
        return Err(AppError::delegation(
            "You cannot modify your own permissions or roles.",
        ));
    }

    let Some(def) = catalog::get(permission_code) else {
        return Err(AppError::UnknownPermission);
    };

    // The subject's own envelope. Redundant with a database trigger, deliberately.
    if !def.max_principal_type.permits(req.subject_principal_type) {
        return Err(AppError::delegation(format!(
            "`{permission_code}` cannot be held by a {} principal.",
            req.subject_principal_type
        )));
    }

    if !requested_scope.is_coherent() {
        return Err(AppError::field(
            "scope",
            "INVALID",
            "The requested scope is malformed.",
        ));
    }

    // The owner may delegate anything — but still only after the checks above,
    // so ROOT cannot accidentally grant an internal permission to a client.
    if req.actor.is_root {
        return Ok(());
    }

    // Rule 8 — dangerous permissions need a fresh second factor.
    if def.is_dangerous && !req.has_recent_step_up {
        return Err(AppError::StepUpRequired { window_seconds: 0 });
    }

    // Rules 1, 2 and 7 — the actor's own effective authority, denials included.
    let held = evaluator::effective_scopes(req.actor, permission_code);
    if held.is_empty() {
        return Err(AppError::delegation(format!(
            "You do not hold `{permission_code}` and therefore cannot grant it."
        )));
    }
    if !held.iter().any(|h| derivable(*h, requested_scope)) {
        return Err(AppError::delegation(format!(
            "You hold `{permission_code}` at {} and cannot grant it at {}.",
            held.iter()
                .map(|h| h.scope_type.as_str())
                .collect::<Vec<_>>()
                .join("/"),
            requested_scope.scope_type
        )));
    }

    Ok(())
}

/// A role's contents, as needed for delegation checks.
pub struct RoleSummary {
    pub id: Uuid,
    pub code: String,
    pub is_system: bool,
    pub allowed_principal_type: PrincipalType,
    /// Every `(permission_code, scope)` the role carries.
    pub permissions: Vec<(String, Scope)>,
}

/// Check that the actor may assign this role to this subject.
///
/// Validated **permission by permission**, not role by role. Checking only "may I
/// assign roles?" is the classic hole: an administrator with `iam.roles.assign` but
/// without `settings.security.write` could otherwise assign a role that contains
/// `settings.security.write` and escalate through composition.
pub fn check_role_assignment(
    req: &DelegationRequest<'_>,
    role: &RoleSummary,
) -> Result<(), AppError> {
    if req.subject_is_root {
        return Err(AppError::RootProtected);
    }
    if req.actor.user_id == req.subject_id {
        return Err(AppError::delegation("You cannot assign roles to yourself."));
    }

    // Rule 6 — principal-type match. Also enforced by a database trigger.
    if role.allowed_principal_type != req.subject_principal_type {
        return Err(AppError::delegation(format!(
            "Role `{}` is restricted to {} principals.",
            role.code, role.allowed_principal_type
        )));
    }

    if req.actor.is_root {
        return Ok(());
    }

    for (code, scope) in &role.permissions {
        check_permission_grant(req, code, *scope).map_err(|e| match e {
            AppError::DelegationDenied { detail } => AppError::delegation(format!(
                "Role `{}` contains `{code}`, which you cannot delegate: {detail}",
                role.code
            )),
            other => other,
        })?;
    }
    Ok(())
}

/// Check that the actor may create or modify a role with this permission set.
///
/// Same principle: an actor cannot author a role more powerful than itself, which
/// would otherwise be escalation with an extra step.
pub fn check_role_authoring(
    actor: &ActorContext,
    has_recent_step_up: bool,
    is_system_role: bool,
    allowed_principal_type: PrincipalType,
    permissions: &[(String, Scope)],
) -> Result<(), AppError> {
    // Rule 5 — system roles are immutable through the API, for everyone including
    // the owner. Changing `employee` for one person changes it for every employee;
    // that is what custom roles are for.
    if is_system_role {
        return Err(AppError::delegation(
            "Built-in system roles cannot be modified or deleted.",
        ));
    }

    for (code, scope) in permissions {
        let Some(def) = catalog::get(code) else {
            return Err(AppError::UnknownPermission);
        };
        if !def.max_principal_type.permits(allowed_principal_type) {
            return Err(AppError::delegation(format!(
                "`{code}` cannot be part of a {allowed_principal_type} role."
            )));
        }
        if !scope.scope_type.valid_on_role() {
            return Err(AppError::field(
                "permissions",
                "INVALID_SCOPE",
                "RESOURCE scope can only be used on a per-user override, not on a role.",
            ));
        }
        if actor.is_root {
            continue;
        }
        if def.is_dangerous && !has_recent_step_up {
            return Err(AppError::StepUpRequired { window_seconds: 0 });
        }
        let held = evaluator::effective_scopes(actor, code);
        if held.is_empty() {
            return Err(AppError::delegation(format!(
                "You cannot put `{code}` in a role because you do not hold it."
            )));
        }
        if !held.iter().any(|h| derivable(*h, *scope)) {
            return Err(AppError::delegation(format!(
                "You cannot put `{code}` at scope {} in a role.",
                scope.scope_type
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::domain::{Grant, ResourceType};

    const READ: &str = "projects.read";
    const SHARE: &str = "projects.clients.share"; // dangerous
    const SECURITY: &str = "settings.security.write"; // dangerous

    fn actor_with(grants: &[(&str, Scope)]) -> ActorContext {
        let mut a = ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal);
        for (code, scope) in grants {
            a.allows.push(Grant {
                permission_code: (*code).into(),
                scope: *scope,
            });
        }
        a
    }

    fn req<'a>(actor: &'a ActorContext, step_up: bool) -> DelegationRequest<'a> {
        DelegationRequest {
            actor,
            subject_id: Uuid::now_v7(),
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: false,
            has_recent_step_up: step_up,
        }
    }

    // ---- the lattice --------------------------------------------------------

    #[test]
    fn global_can_derive_everything() {
        let g = Scope::global();
        for s in [
            Scope::global(),
            Scope::simple(ScopeType::Department),
            Scope::simple(ScopeType::Assigned),
            Scope::simple(ScopeType::Own),
            Scope::resource(ResourceType::Project, Uuid::now_v7()),
        ] {
            assert!(derivable(g, s), "GLOBAL should derive {}", s.scope_type);
        }
    }

    /// The escalation this lattice exists to prevent.
    #[test]
    fn department_cannot_derive_assigned() {
        let dept = Scope::simple(ScopeType::Department);
        assert!(
            !derivable(dept, Scope::simple(ScopeType::Assigned)),
            "DEPARTMENT -> ASSIGNED is a lateral escalation and must be refused"
        );
        assert!(!derivable(dept, Scope::global()));
        assert!(!derivable(
            dept,
            Scope::resource(ResourceType::Project, Uuid::now_v7())
        ));
        assert!(derivable(dept, dept));
        assert!(derivable(dept, Scope::simple(ScopeType::Own)));
    }

    #[test]
    fn assigned_cannot_derive_department_or_global() {
        let a = Scope::simple(ScopeType::Assigned);
        assert!(!derivable(a, Scope::simple(ScopeType::Department)));
        assert!(!derivable(a, Scope::global()));
        assert!(derivable(a, a));
        assert!(derivable(a, Scope::simple(ScopeType::Own)));
    }

    #[test]
    fn self_derives_only_self() {
        let s = Scope::simple(ScopeType::Own);
        assert!(derivable(s, s));
        for other in [
            Scope::global(),
            Scope::simple(ScopeType::Department),
            Scope::simple(ScopeType::Assigned),
        ] {
            assert!(!derivable(s, other));
        }
    }

    #[test]
    fn resource_derives_only_that_exact_object() {
        let id = Uuid::now_v7();
        let held = Scope::resource(ResourceType::Project, id);
        assert!(derivable(held, Scope::resource(ResourceType::Project, id)));
        assert!(!derivable(
            held,
            Scope::resource(ResourceType::Project, Uuid::now_v7())
        ));
        assert!(!derivable(held, Scope::resource(ResourceType::Task, id)));
        assert!(!derivable(held, Scope::simple(ScopeType::Assigned)));
        assert!(!derivable(held, Scope::global()));
    }

    // ---- rule 1: cannot grant what you do not hold --------------------------

    #[test]
    fn rule_1_cannot_grant_a_permission_not_held() {
        let a = actor_with(&[(READ, Scope::global())]);
        let r = req(&a, true);
        assert!(check_permission_grant(&r, READ, Scope::global()).is_ok());
        let err = check_permission_grant(&r, "tasks.create", Scope::global()).unwrap_err();
        assert!(matches!(err, AppError::DelegationDenied { .. }));
        assert!(format!("{err}").contains("do not hold"), "{err}");
    }

    // ---- rule 2: cannot widen scope -----------------------------------------

    #[test]
    fn rule_2_cannot_grant_a_broader_scope_than_held() {
        let a = actor_with(&[(READ, Scope::simple(ScopeType::Department))]);
        let r = req(&a, true);
        assert!(check_permission_grant(&r, READ, Scope::simple(ScopeType::Department)).is_ok());
        assert!(check_permission_grant(&r, READ, Scope::simple(ScopeType::Own)).is_ok());
        assert!(check_permission_grant(&r, READ, Scope::global()).is_err());
        assert!(check_permission_grant(&r, READ, Scope::simple(ScopeType::Assigned)).is_err());
    }

    // ---- rule 3: no self-modification ---------------------------------------

    #[test]
    fn rule_3_an_actor_cannot_change_its_own_privileges() {
        let a = actor_with(&[(READ, Scope::global())]);
        let r = DelegationRequest {
            actor: &a,
            subject_id: a.user_id, // itself
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: false,
            has_recent_step_up: true,
        };
        let err = check_permission_grant(&r, READ, Scope::global()).unwrap_err();
        assert!(format!("{err}").contains("your own"));
    }

    #[test]
    fn rule_3_applies_to_root_as_well() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        let r = DelegationRequest {
            actor: &a,
            subject_id: a.user_id,
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: true,
            has_recent_step_up: true,
        };
        // Targeting root is refused before the self-check, which is the stronger
        // and more legible error.
        assert!(matches!(
            check_permission_grant(&r, READ, Scope::global()),
            Err(AppError::RootProtected)
        ));
    }

    // ---- rule 4: root is untouchable ----------------------------------------

    #[test]
    fn rule_4_no_authorisation_operation_may_target_root() {
        let mut a = actor_with(&[(READ, Scope::global())]);
        a.is_root = true; // even the owner acting on the owner
        let r = DelegationRequest {
            actor: &a,
            subject_id: Uuid::now_v7(),
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: true,
            has_recent_step_up: true,
        };
        assert!(matches!(
            check_permission_grant(&r, READ, Scope::global()),
            Err(AppError::RootProtected)
        ));
    }

    // ---- rule 5: system roles ------------------------------------------------

    #[test]
    fn rule_5_system_roles_cannot_be_authored_even_by_root() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        let err = check_role_authoring(&a, true, true, PrincipalType::Internal, &[]).unwrap_err();
        assert!(format!("{err}").contains("system roles"));
    }

    // ---- rule 6: principal-type match ---------------------------------------

    #[test]
    fn rule_6_a_client_cannot_receive_an_internal_role() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        let role = RoleSummary {
            id: Uuid::now_v7(),
            code: "system_administrator".into(),
            is_system: true,
            allowed_principal_type: PrincipalType::Internal,
            permissions: vec![],
        };
        let r = DelegationRequest {
            actor: &a,
            subject_id: Uuid::now_v7(),
            subject_principal_type: PrincipalType::Client,
            subject_is_root: false,
            has_recent_step_up: true,
        };
        let err = check_role_assignment(&r, &role).unwrap_err();
        assert!(format!("{err}").contains("restricted to INTERNAL"));
    }

    #[test]
    fn rule_6_a_client_cannot_receive_an_internal_permission_even_from_root() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        let r = DelegationRequest {
            actor: &a,
            subject_id: Uuid::now_v7(),
            subject_principal_type: PrincipalType::Client,
            subject_is_root: false,
            has_recent_step_up: true,
        };
        assert!(check_permission_grant(&r, "audit.read", Scope::global()).is_err());
        assert!(check_permission_grant(
            &r,
            "client.portal.projects.read",
            Scope::simple(ScopeType::Assigned)
        )
        .is_ok());
    }

    // ---- rule 7: a DENY blocks delegation -----------------------------------

    #[test]
    fn rule_7_a_deny_on_the_actor_blocks_delegation_not_just_access() {
        let mut a = actor_with(&[(READ, Scope::global())]);
        a.denies.push(Grant {
            permission_code: READ.into(),
            scope: Scope::global(),
        });
        let r = req(&a, true);
        let err = check_permission_grant(&r, READ, Scope::global()).unwrap_err();
        assert!(format!("{err}").contains("do not hold"));
    }

    // ---- rule 8: step-up ----------------------------------------------------

    #[test]
    fn rule_8_dangerous_permissions_require_a_recent_step_up() {
        let a = actor_with(&[(SHARE, Scope::global()), (SECURITY, Scope::global())]);
        let without = req(&a, false);
        assert!(matches!(
            check_permission_grant(&without, SHARE, Scope::global()),
            Err(AppError::StepUpRequired { .. })
        ));
        let with = req(&a, true);
        assert!(check_permission_grant(&with, SHARE, Scope::global()).is_ok());
    }

    #[test]
    fn rule_8_does_not_apply_to_ordinary_permissions() {
        let a = actor_with(&[(READ, Scope::global())]);
        assert!(check_permission_grant(&req(&a, false), READ, Scope::global()).is_ok());
    }

    // ---- escalation through composition -------------------------------------

    /// The classic hole: an actor with `iam.roles.assign` but not
    /// `settings.security.write` assigns a role that *contains*
    /// `settings.security.write`.
    #[test]
    fn a_role_cannot_be_used_to_smuggle_a_permission_the_actor_lacks() {
        let a = actor_with(&[
            ("iam.roles.assign", Scope::global()),
            (READ, Scope::global()),
        ]);
        let powerful_role = RoleSummary {
            id: Uuid::now_v7(),
            code: "sneaky".into(),
            is_system: false,
            allowed_principal_type: PrincipalType::Internal,
            permissions: vec![
                (READ.to_string(), Scope::global()),
                (SECURITY.to_string(), Scope::global()), // the actor does NOT hold this
            ],
        };
        let err = check_role_assignment(&req(&a, true), &powerful_role).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("settings.security.write"), "{msg}");
        assert!(msg.contains("cannot delegate"), "{msg}");
    }

    #[test]
    fn an_actor_cannot_author_a_role_more_powerful_than_itself() {
        let a = actor_with(&[(READ, Scope::simple(ScopeType::Department))]);
        // Widening its own scope inside a new role.
        let err = check_role_authoring(
            &a,
            true,
            false,
            PrincipalType::Internal,
            &[(READ.to_string(), Scope::global())],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("at scope GLOBAL"));

        // Reproducing what it holds is fine.
        assert!(check_role_authoring(
            &a,
            true,
            false,
            PrincipalType::Internal,
            &[(READ.to_string(), Scope::simple(ScopeType::Department))]
        )
        .is_ok());
    }

    #[test]
    fn a_role_cannot_carry_resource_scope() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        let err = check_role_authoring(
            &a,
            true,
            false,
            PrincipalType::Internal,
            &[(
                READ.to_string(),
                Scope::resource(ResourceType::Project, Uuid::now_v7()),
            )],
        )
        .unwrap_err();
        // Assert on the machine-readable field code, which is the actual contract;
        // the human message is free to be reworded.
        let AppError::Validation { errors } = &err else {
            panic!("expected a validation error, got {err}");
        };
        assert_eq!(errors[0].field, "permissions");
        assert_eq!(errors[0].code, "INVALID_SCOPE");
    }

    #[test]
    fn an_unknown_permission_in_a_role_is_rejected() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        assert!(matches!(
            check_role_authoring(
                &a,
                true,
                false,
                PrincipalType::Internal,
                &[("not.a.real.permission".to_string(), Scope::global())]
            ),
            Err(AppError::UnknownPermission)
        ));
    }

    #[test]
    fn root_may_delegate_anything_within_the_envelope() {
        let mut a = actor_with(&[]);
        a.is_root = true;
        let r = req(&a, true);
        for def in catalog::PERMISSIONS {
            assert!(
                check_permission_grant(&r, def.code, Scope::global()).is_ok(),
                "root should be able to grant `{}`",
                def.code
            );
        }
    }
}
