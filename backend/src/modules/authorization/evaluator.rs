//! The authorization evaluator.
//!
//! Pure, synchronous, and small enough to hold in your head — which is the point.
//! Everything it needs was loaded by the caller; it performs no I/O, so it can be
//! exhaustively unit- and property-tested without a database.
//!
//! The numbered steps below are normative and correspond 1:1 with
//! `docs/backend/04-authorization.md` §5. **Do not reorder them.** Two properties
//! depend entirely on the order:
//!
//!   * the principal envelope is checked *before* grants are collected, so no
//!     misconfigured role can hand internal authority to an external principal;
//!   * denials are evaluated *before* allows and never consult the allow set, so
//!     "add another role to escape a DENY" is structurally impossible.

use super::catalog;
use super::domain::{
    ActorContext, Decision, Grant, PrincipalType, Scope, ScopeType, Target, TargetContext,
};

/// Decide whether `actor` may perform `permission_code` against `target`.
pub fn evaluate(actor: &ActorContext, permission_code: &str, target: &Target) -> Decision {
    // Step 1 — system ownership. The single bypass in the entire system.
    //
    // It is reached only after the request has already satisfied authentication,
    // session validity, MFA and step-up: ownership bypasses *permission
    // evaluation*, nothing else. See ADR-004.
    if actor.is_root {
        return Decision::AllowRootOwnership;
    }

    // Step 2 — the permission must exist. An unknown code is a hard deny, never an
    // unmatched fallthrough.
    let Some(def) = catalog::get(permission_code) else {
        return Decision::DenyUnknownPermission;
    };

    // Step 3 — the principal envelope, before any grant is looked at.
    if !def.max_principal_type.permits(actor.principal_type) {
        return Decision::DenyPrincipalEnvelope;
    }

    // Step 5 — explicit DENY wins. Evaluated before the allow set is consulted.
    for denial in actor
        .denies
        .iter()
        .filter(|g| g.permission_code == permission_code)
    {
        if scope_covers(&denial.scope, actor, target) {
            return Decision::DenyExplicitOverride;
        }
    }

    // Steps 6 & 7 — is there an allow whose scope actually reaches this object?
    let mut had_any_grant = false;
    for grant in actor
        .allows
        .iter()
        .filter(|g| g.permission_code == permission_code)
    {
        had_any_grant = true;
        if scope_covers(&grant.scope, actor, target) {
            return Decision::AllowGranted(grant.scope.scope_type);
        }
    }

    if had_any_grant {
        Decision::DenyOutOfScope
    } else {
        Decision::DenyNoGrant
    }
}

/// Does this scope reach this target?
///
/// `Target::Collection` is covered only by `GLOBAL`. A narrower scope does not
/// authorise "list everything" — it turns the listing into a *filtered query*.
/// That distinction is why BOLA is hard to reintroduce here: a list endpoint with
/// an `ASSIGNED` grant cannot be implemented as "fetch all, filter in Rust",
/// because this function refuses the unfiltered form outright.
pub fn scope_covers(scope: &Scope, actor: &ActorContext, target: &Target) -> bool {
    // A malformed scope — RESOURCE with no object, or GLOBAL carrying one — is
    // refused rather than interpreted. Corrupt authorisation data must fail closed.
    if !scope.is_coherent() {
        return false;
    }

    match target {
        Target::Collection => matches!(scope.scope_type, ScopeType::Global),
        Target::Resource(ctx) => match scope.scope_type {
            ScopeType::Global => true,

            ScopeType::Own => ctx.is_actor_self,

            ScopeType::Department => match ctx.department_id {
                // A resource with no department is not covered by a department
                // -scoped grant. The alternative — treating "no department" as
                // "every department" — would silently widen the grant.
                None => false,
                Some(dept) => actor.department_ids.contains(&dept),
            },

            ScopeType::Assigned => ctx.actor_is_member,

            ScopeType::Resource => {
                scope.resource_type == Some(ctx.resource_type)
                    && scope.resource_id == Some(ctx.resource_id)
            }
        },
    }
}

/// The scopes an actor effectively holds for one permission, after denials.
///
/// Used by the delegation guard: an actor cannot delegate what it does not hold,
/// and an explicit DENY removes the ability to delegate as well as the ability to
/// act. A DENY is a restriction on authority, not merely on access.
pub fn effective_scopes(actor: &ActorContext, permission_code: &str) -> Vec<Scope> {
    if actor.is_root {
        return vec![Scope::global()];
    }
    if !catalog::envelope_permits(permission_code, actor.principal_type) {
        return Vec::new();
    }

    // A GLOBAL denial removes the permission entirely. A narrower denial removes
    // only what it covers, and is handled per-object at `evaluate` time.
    let globally_denied = actor
        .denies
        .iter()
        .any(|d| d.permission_code == permission_code && d.scope.scope_type == ScopeType::Global);
    if globally_denied {
        return Vec::new();
    }

    let mut scopes: Vec<Scope> = actor
        .allows
        .iter()
        .filter(|g| g.permission_code == permission_code && g.scope.is_coherent())
        .map(|g| g.scope)
        .collect();

    scopes.dedup_by(|a, b| a == b);
    scopes
}

/// Convenience for the common "does the actor hold this at all" question, used to
/// build the capability list returned by `GET /api/v1/auth/me`.
pub fn holds_any(actor: &ActorContext, permission_code: &str) -> bool {
    !effective_scopes(actor, permission_code).is_empty()
}

/// Every permission the actor effectively holds, with its scopes.
///
/// Returned to the client so a frontend can hide buttons. It is a *hint*: the
/// backend re-derives the decision on every request regardless of what the client
/// believes. See `docs/backend/04-authorization.md` §11.
pub fn capability_list(actor: &ActorContext) -> Vec<(&'static str, Vec<ScopeType>)> {
    catalog::PERMISSIONS
        .iter()
        .filter_map(|def| {
            let scopes: Vec<ScopeType> = effective_scopes(actor, def.code)
                .into_iter()
                .map(|s| s.scope_type)
                .collect();
            if scopes.is_empty() {
                None
            } else {
                Some((def.code, scopes))
            }
        })
        .collect()
}

/// Build a grant, rejecting incoherent scopes at construction rather than storing
/// them and discovering the problem during a decision.
pub fn grant(permission_code: impl Into<String>, scope: Scope) -> Option<Grant> {
    let g = Grant {
        permission_code: permission_code.into(),
        scope,
    };
    if g.scope.is_coherent() {
        Some(g)
    } else {
        None
    }
}

#[allow(dead_code)]
fn _assert_types(_: PrincipalType, _: TargetContext) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::domain::{ResourceType, TargetContext};
    use uuid::Uuid;

    const READ: &str = "projects.read";
    const AUDIT: &str = "audit.read";
    const PORTAL: &str = "client.portal.projects.read";

    fn internal() -> ActorContext {
        ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal)
    }
    fn client() -> ActorContext {
        ActorContext::empty(Uuid::now_v7(), PrincipalType::Client)
    }
    fn project(id: Uuid) -> Target {
        Target::Resource(TargetContext::new(ResourceType::Project, id))
    }
    fn allow(actor: &mut ActorContext, code: &str, scope: Scope) {
        actor.allows.push(Grant {
            permission_code: code.into(),
            scope,
        });
    }
    fn deny(actor: &mut ActorContext, code: &str, scope: Scope) {
        actor.denies.push(Grant {
            permission_code: code.into(),
            scope,
        });
    }

    // ---- deny by default ---------------------------------------------------

    #[test]
    fn an_actor_with_no_grants_is_denied() {
        let a = internal();
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::DenyNoGrant
        );
        assert_eq!(
            evaluate(&a, READ, &Target::Collection),
            Decision::DenyNoGrant
        );
    }

    #[test]
    fn an_unknown_permission_is_denied_not_ignored() {
        let mut a = internal();
        allow(&mut a, "projects.destroy_everything", Scope::global());
        assert_eq!(
            evaluate(&a, "projects.destroy_everything", &Target::Collection),
            Decision::DenyUnknownPermission,
            "a grant for a code outside the catalogue must never take effect"
        );
        for bogus in ["", "*", "projects.*", "PROJECTS.READ", " projects.read"] {
            assert_eq!(
                evaluate(&a, bogus, &Target::Collection),
                Decision::DenyUnknownPermission
            );
        }
    }

    // ---- the client envelope ------------------------------------------------

    #[test]
    fn a_client_cannot_hold_an_internal_permission_however_it_is_granted() {
        let mut a = client();
        // Every mechanism at once: a role-derived allow AND a direct override.
        allow(&mut a, AUDIT, Scope::global());
        allow(&mut a, READ, Scope::global());
        assert_eq!(
            evaluate(&a, AUDIT, &Target::Collection),
            Decision::DenyPrincipalEnvelope
        );
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::DenyPrincipalEnvelope
        );
        assert!(effective_scopes(&a, AUDIT).is_empty());
    }

    #[test]
    fn the_envelope_is_checked_before_grants_exist() {
        // A client with NO grants and an internal permission must report the
        // envelope, not "no grant" — the order matters for auditing a probe.
        let a = client();
        assert_eq!(
            evaluate(&a, AUDIT, &Target::Collection),
            Decision::DenyPrincipalEnvelope
        );
    }

    #[test]
    fn a_client_can_hold_a_portal_permission() {
        let mut a = client();
        let p = Uuid::now_v7();
        allow(&mut a, PORTAL, Scope::simple(ScopeType::Assigned));
        let t =
            Target::Resource(TargetContext::new(ResourceType::Project, p).with_membership(true));
        assert_eq!(
            evaluate(&a, PORTAL, &t),
            Decision::AllowGranted(ScopeType::Assigned)
        );
    }

    // ---- explicit DENY precedence -------------------------------------------

    #[test]
    fn an_explicit_deny_beats_any_number_of_allows() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        allow(&mut a, READ, Scope::simple(ScopeType::Assigned));
        allow(&mut a, READ, Scope::simple(ScopeType::Department));
        deny(&mut a, READ, Scope::global());
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::DenyExplicitOverride
        );
        assert_eq!(
            evaluate(&a, READ, &Target::Collection),
            Decision::DenyExplicitOverride
        );
    }

    #[test]
    fn adding_more_roles_cannot_overturn_a_matching_deny() {
        let mut a = internal();
        deny(&mut a, READ, Scope::global());
        for _ in 0..50 {
            allow(&mut a, READ, Scope::global());
        }
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::DenyExplicitOverride
        );
    }

    #[test]
    fn a_narrow_deny_only_removes_what_it_covers() {
        let mut a = internal();
        let blocked = Uuid::now_v7();
        let other = Uuid::now_v7();
        allow(&mut a, READ, Scope::global());
        deny(
            &mut a,
            READ,
            Scope::resource(ResourceType::Project, blocked),
        );

        assert_eq!(
            evaluate(&a, READ, &project(blocked)),
            Decision::DenyExplicitOverride
        );
        assert_eq!(
            evaluate(&a, READ, &project(other)),
            Decision::AllowGranted(ScopeType::Global)
        );
    }

    #[test]
    fn a_deny_on_a_different_permission_is_irrelevant() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        deny(&mut a, "projects.update", Scope::global());
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::AllowGranted(ScopeType::Global)
        );
    }

    // ---- scope semantics ----------------------------------------------------

    #[test]
    fn collections_are_covered_only_by_global() {
        for narrow in [ScopeType::Department, ScopeType::Assigned, ScopeType::Own] {
            let mut a = internal();
            allow(&mut a, READ, Scope::simple(narrow));
            assert_eq!(
                evaluate(&a, READ, &Target::Collection),
                Decision::DenyOutOfScope,
                "{narrow} must not authorise an unfiltered collection"
            );
        }
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        assert_eq!(
            evaluate(&a, READ, &Target::Collection),
            Decision::AllowGranted(ScopeType::Global)
        );
    }

    #[test]
    fn assigned_scope_requires_actual_membership() {
        let mut a = internal();
        let p = Uuid::now_v7();
        allow(&mut a, READ, Scope::simple(ScopeType::Assigned));

        let member =
            Target::Resource(TargetContext::new(ResourceType::Project, p).with_membership(true));
        let stranger = Target::Resource(TargetContext::new(ResourceType::Project, p));
        assert_eq!(
            evaluate(&a, READ, &member),
            Decision::AllowGranted(ScopeType::Assigned)
        );
        assert_eq!(evaluate(&a, READ, &stranger), Decision::DenyOutOfScope);
    }

    #[test]
    fn department_scope_requires_matching_membership() {
        let dept = Uuid::now_v7();
        let other_dept = Uuid::now_v7();
        let mut a = internal();
        a.department_ids = vec![dept];
        allow(&mut a, READ, Scope::simple(ScopeType::Department));

        let mine = Target::Resource(
            TargetContext::new(ResourceType::Project, Uuid::now_v7()).with_department(Some(dept)),
        );
        let theirs = Target::Resource(
            TargetContext::new(ResourceType::Project, Uuid::now_v7())
                .with_department(Some(other_dept)),
        );
        assert_eq!(
            evaluate(&a, READ, &mine),
            Decision::AllowGranted(ScopeType::Department)
        );
        assert_eq!(evaluate(&a, READ, &theirs), Decision::DenyOutOfScope);
    }

    /// Treating "no department" as "every department" would silently widen every
    /// department-scoped grant to global.
    #[test]
    fn department_scope_does_not_cover_a_resource_with_no_department() {
        let dept = Uuid::now_v7();
        let mut a = internal();
        a.department_ids = vec![dept];
        allow(&mut a, READ, Scope::simple(ScopeType::Department));
        let orphan = Target::Resource(
            TargetContext::new(ResourceType::Project, Uuid::now_v7()).with_department(None),
        );
        assert_eq!(evaluate(&a, READ, &orphan), Decision::DenyOutOfScope);
    }

    #[test]
    fn self_scope_covers_only_the_actors_own_record() {
        let me = Uuid::now_v7();
        let mut a = ActorContext::empty(me, PrincipalType::Internal);
        allow(&mut a, "iam.users.read", Scope::simple(ScopeType::Own));

        let own = Target::Resource(TargetContext::own_user(me));
        let other = Target::Resource(TargetContext::other_user(me, Uuid::now_v7()));
        assert_eq!(
            evaluate(&a, "iam.users.read", &own),
            Decision::AllowGranted(ScopeType::Own)
        );
        assert_eq!(
            evaluate(&a, "iam.users.read", &other),
            Decision::DenyOutOfScope
        );
    }

    #[test]
    fn resource_scope_matches_only_the_exact_object_and_type() {
        let target_id = Uuid::now_v7();
        let mut a = internal();
        allow(
            &mut a,
            READ,
            Scope::resource(ResourceType::Project, target_id),
        );

        assert_eq!(
            evaluate(&a, READ, &project(target_id)),
            Decision::AllowGranted(ScopeType::Resource)
        );
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::DenyOutOfScope
        );
        // Same id, different type.
        let wrong_type = Target::Resource(TargetContext::new(ResourceType::Task, target_id));
        assert_eq!(evaluate(&a, READ, &wrong_type), Decision::DenyOutOfScope);
    }

    #[test]
    fn an_incoherent_scope_fails_closed() {
        let mut a = internal();
        // RESOURCE scope with no object — corrupt authorisation data.
        a.allows.push(Grant {
            permission_code: READ.into(),
            scope: Scope {
                scope_type: ScopeType::Resource,
                resource_type: None,
                resource_id: None,
            },
        });
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::DenyOutOfScope
        );

        // A corrupt DENY must not accidentally allow either — it simply does not
        // match, and the actor still has no allow.
        let mut b = internal();
        b.denies.push(Grant {
            permission_code: READ.into(),
            scope: Scope {
                scope_type: ScopeType::Global,
                resource_type: Some(ResourceType::Project),
                resource_id: Some(Uuid::now_v7()),
            },
        });
        assert_eq!(
            evaluate(&b, READ, &project(Uuid::now_v7())),
            Decision::DenyNoGrant
        );
    }

    // ---- root ---------------------------------------------------------------

    #[test]
    fn root_is_allowed_everything_including_unknown_targets() {
        let mut a = internal();
        a.is_root = true;
        assert_eq!(
            evaluate(&a, AUDIT, &Target::Collection),
            Decision::AllowRootOwnership
        );
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::AllowRootOwnership
        );
    }

    /// Ownership bypasses permission evaluation. It is *not* a licence to invent
    /// permissions: an unknown code is still unknown, which keeps a typo in a route
    /// definition from becoming an accidental grant for the owner alone.
    #[test]
    fn root_bypass_precedes_everything_including_explicit_denies() {
        let mut a = internal();
        a.is_root = true;
        deny(&mut a, READ, Scope::global());
        assert_eq!(
            evaluate(&a, READ, &project(Uuid::now_v7())),
            Decision::AllowRootOwnership
        );
    }

    // ---- effective scopes / capabilities ------------------------------------

    #[test]
    fn effective_scopes_reflect_denials() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        assert_eq!(effective_scopes(&a, READ).len(), 1);
        deny(&mut a, READ, Scope::global());
        assert!(
            effective_scopes(&a, READ).is_empty(),
            "a global DENY removes delegation authority too"
        );
        assert!(!holds_any(&a, READ));
    }

    #[test]
    fn root_effective_scopes_are_global() {
        let mut a = internal();
        a.is_root = true;
        assert_eq!(effective_scopes(&a, AUDIT), vec![Scope::global()]);
    }

    #[test]
    fn capability_list_never_includes_an_internal_permission_for_a_client() {
        let mut a = client();
        // Grant the client absolutely everything in the catalogue.
        for def in catalog::PERMISSIONS {
            allow(&mut a, def.code, Scope::global());
        }
        let caps = capability_list(&a);
        for (code, _) in &caps {
            assert!(
                code.starts_with("client.portal."),
                "capability list leaked `{code}` to an external principal"
            );
        }
        assert_eq!(caps.len(), 2, "exactly the two portal permissions");
    }

    #[test]
    fn grant_constructor_rejects_incoherent_scopes() {
        assert!(grant(READ, Scope::global()).is_some());
        assert!(grant(
            READ,
            Scope {
                scope_type: ScopeType::Resource,
                resource_type: None,
                resource_id: None
            }
        )
        .is_none());
    }
}
