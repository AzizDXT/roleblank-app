//! Property-based verification of the authorization invariants.
//!
//! Example-based tests prove that the cases someone thought of behave correctly.
//! These prove that *no* combination of roles, overrides, scopes and targets — of
//! the many thousands `proptest` generates per run — can break the four properties
//! the whole security model rests on.
//!
//! Each property here corresponds to a threat in `docs/backend/02-threat-model.md`.

#![cfg(test)]

use proptest::prelude::*;
use uuid::Uuid;

use super::catalog;
use super::delegation::{self, DelegationRequest};
use super::domain::{
    ActorContext, Decision, Grant, PrincipalType, ResourceType, Scope, ScopeType, Target,
    TargetContext,
};
use super::evaluator;

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

fn any_permission_code() -> impl Strategy<Value = String> {
    // The real catalogue, plus codes that are NOT in it — the evaluator must
    // handle both, and an unknown code must always deny.
    prop_oneof![
        7 => prop::sample::select(
                catalog::PERMISSIONS.iter().map(|p| p.code.to_string()).collect::<Vec<_>>()
            ),
        3 => prop_oneof![
                Just("iam.users.delete".to_string()),
                Just("*".to_string()),
                Just("".to_string()),
                Just("projects.*".to_string()),
                Just("PROJECTS.READ".to_string()),
                Just("audit.read ".to_string()),
                "[a-z]{1,8}\\.[a-z]{1,8}",
            ],
    ]
}

fn any_scope_type() -> impl Strategy<Value = ScopeType> {
    prop_oneof![
        Just(ScopeType::Global),
        Just(ScopeType::Department),
        Just(ScopeType::Assigned),
        Just(ScopeType::Own),
        Just(ScopeType::Resource),
    ]
}

fn any_resource_type() -> impl Strategy<Value = ResourceType> {
    prop_oneof![
        Just(ResourceType::Project),
        Just(ResourceType::Task),
        Just(ResourceType::Department),
        Just(ResourceType::ClientAccount),
        Just(ResourceType::User),
    ]
}

/// A pool of fixed UUIDs so that generated grants and targets actually collide
/// sometimes. Fully random UUIDs would almost never match, and the properties
/// would pass vacuously.
fn id_pool() -> Vec<Uuid> {
    (1u128..=6)
        .map(|n| Uuid::from_u128(0x0192_0000_7000_8000_0000_0000_0000_0000 + n))
        .collect()
}

fn any_id() -> impl Strategy<Value = Uuid> {
    prop::sample::select(id_pool())
}

fn any_scope() -> impl Strategy<Value = Scope> {
    (any_scope_type(), any_resource_type(), any_id()).prop_map(|(st, rt, id)| match st {
        ScopeType::Resource => Scope::resource(rt, id),
        other => Scope::simple(other),
    })
}

fn any_grant() -> impl Strategy<Value = Grant> {
    (any_permission_code(), any_scope()).prop_map(|(permission_code, scope)| Grant {
        permission_code,
        scope,
    })
}

fn any_actor(principal_type: PrincipalType) -> impl Strategy<Value = ActorContext> {
    (
        any_id(),
        prop::collection::vec(any_grant(), 0..8),
        prop::collection::vec(any_grant(), 0..4),
        prop::collection::vec(any_id(), 0..3),
        prop::collection::vec(any_id(), 0..3),
    )
        .prop_map(
            move |(user_id, allows, denies, departments, clients)| ActorContext {
                user_id,
                principal_type,
                is_root: false,
                department_ids: departments,
                client_account_ids: clients,
                allows,
                denies,
            },
        )
}

fn any_target() -> impl Strategy<Value = Target> {
    prop_oneof![
        1 => Just(Target::Collection),
        4 => (any_resource_type(), any_id(), prop::option::of(any_id()), any::<bool>(), any::<bool>())
            .prop_map(|(rt, id, dept, member, is_self)| {
                Target::Resource(TargetContext {
                    resource_type: rt,
                    resource_id: id,
                    department_id: dept,
                    actor_is_member: member,
                    is_actor_self: is_self,
                })
            }),
    ]
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// **TH-09 — the client envelope holds unconditionally.**
    ///
    /// For any external principal, with any random pile of roles, overrides,
    /// scopes and targets, an INTERNAL-only permission is never allowed.
    #[test]
    fn client_principals_never_obtain_an_internal_permission(
        actor in any_actor(PrincipalType::Client),
        target in any_target(),
    ) {
        for def in catalog::PERMISSIONS.iter().filter(|d| !d.max_principal_type.permits(PrincipalType::Client)) {
            let decision = evaluator::evaluate(&actor, def.code, &target);
            prop_assert!(
                !decision.is_allowed(),
                "CLIENT principal was allowed `{}` (decision {:?})",
                def.code,
                decision
            );
            prop_assert_eq!(decision, Decision::DenyPrincipalEnvelope);
        }
    }

    /// **TH-09 (capability surface).** Whatever the grants, the capability list
    /// returned to an external principal contains only client-portal permissions.
    #[test]
    fn client_capability_lists_never_leak_internal_permissions(
        actor in any_actor(PrincipalType::Client),
    ) {
        for (code, _) in evaluator::capability_list(&actor) {
            prop_assert!(
                code.starts_with("client.portal."),
                "capability list contained `{}`", code
            );
        }
    }

    /// **TH-16 — an explicit DENY can never be overturned by adding allows.**
    ///
    /// Take any actor and any decision that came out ALLOW; add a matching global
    /// DENY; the decision must become a denial regardless of how many allows exist.
    #[test]
    fn a_global_deny_always_wins_over_any_allow_set(
        mut actor in any_actor(PrincipalType::Internal),
        target in any_target(),
        code in any_permission_code(),
    ) {
        actor.denies.push(Grant { permission_code: code.clone(), scope: Scope::global() });
        let decision = evaluator::evaluate(&actor, &code, &target);
        prop_assert!(
            !decision.is_allowed(),
            "a global DENY on `{}` was overturned (decision {:?})", code, decision
        );
    }

    /// Adding allows to an actor that is already denied changes nothing.
    #[test]
    fn piling_on_roles_cannot_escape_a_deny(
        mut actor in any_actor(PrincipalType::Internal),
        target in any_target(),
        code in prop::sample::select(
            catalog::PERMISSIONS.iter().map(|p| p.code.to_string()).collect::<Vec<_>>()
        ),
        extra_scopes in prop::collection::vec(any_scope(), 1..10),
    ) {
        actor.denies.push(Grant { permission_code: code.clone(), scope: Scope::global() });
        for scope in extra_scopes {
            actor.allows.push(Grant { permission_code: code.clone(), scope });
        }
        prop_assert_eq!(
            evaluator::evaluate(&actor, &code, &target),
            Decision::DenyExplicitOverride
        );
    }

    /// **A permission outside the catalogue never authorises anything**, even when
    /// the actor has been granted it explicitly at global scope.
    #[test]
    fn unknown_permissions_always_deny(
        mut actor in any_actor(PrincipalType::Internal),
        target in any_target(),
        code in "[a-z]{1,10}\\.[a-z]{1,10}\\.[a-z]{1,10}",
    ) {
        prop_assume!(!catalog::exists(&code));
        actor.allows.push(Grant { permission_code: code.clone(), scope: Scope::global() });
        prop_assert_eq!(
            evaluator::evaluate(&actor, &code, &target),
            Decision::DenyUnknownPermission
        );
    }

    /// **A grant is never wider than its scope.** For every non-GLOBAL grant, an
    /// unfiltered collection request is refused — this is what stops "authorise,
    /// then fetch everything" from being written.
    #[test]
    fn narrow_scopes_never_authorise_an_unfiltered_collection(
        user_id in any_id(),
        code in prop::sample::select(
            catalog::PERMISSIONS
                .iter()
                .filter(|p| p.max_principal_type.permits(PrincipalType::Internal))
                .map(|p| p.code.to_string())
                .collect::<Vec<_>>()
        ),
        scope_type in prop_oneof![
            Just(ScopeType::Department),
            Just(ScopeType::Assigned),
            Just(ScopeType::Own),
        ],
    ) {
        let mut actor = ActorContext::empty(user_id, PrincipalType::Internal);
        actor.allows.push(Grant { permission_code: code.clone(), scope: Scope::simple(scope_type) });
        prop_assert!(
            !evaluator::evaluate(&actor, &code, &Target::Collection).is_allowed(),
            "{} authorised an unfiltered collection", scope_type
        );
    }

    /// **TH-13 / TH-14 — no actor can delegate beyond its own authority.**
    ///
    /// For any non-root actor and any requested grant, if the delegation guard
    /// permits it then the actor genuinely holds a scope from which the requested
    /// one is derivable. Restated: the guard never says yes without a basis.
    #[test]
    fn delegation_never_exceeds_the_actors_own_authority(
        actor in any_actor(PrincipalType::Internal),
        code in any_permission_code(),
        requested in any_scope(),
        subject in any_id(),
    ) {
        prop_assume!(actor.user_id != subject);
        let req = DelegationRequest {
            actor: &actor,
            subject_id: subject,
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: false,
            // Grant step-up so the property tests the authority logic itself
            // rather than short-circuiting on the step-up gate.
            has_recent_step_up: true,
        };
        if delegation::check_permission_grant(&req, &code, requested).is_ok() {
            let held = evaluator::effective_scopes(&actor, &code);
            prop_assert!(!held.is_empty(), "granted `{}` while holding nothing", code);
            prop_assert!(
                held.iter().any(|h| delegation::derivable(*h, requested)),
                "granted `{}` at {} without a derivable held scope {:?}",
                code, requested.scope_type, held
            );
        }
    }

    /// **TH-13 — self-escalation is impossible by construction.**
    #[test]
    fn an_actor_can_never_grant_anything_to_itself(
        actor in any_actor(PrincipalType::Internal),
        code in any_permission_code(),
        requested in any_scope(),
    ) {
        let req = DelegationRequest {
            actor: &actor,
            subject_id: actor.user_id,
            subject_principal_type: actor.principal_type,
            subject_is_root: false,
            has_recent_step_up: true,
        };
        prop_assert!(delegation::check_permission_grant(&req, &code, requested).is_err());
    }

    /// **TH-04 / ADR-004 — the system owner is never a valid delegation target**,
    /// for any actor including the owner itself.
    #[test]
    fn root_is_never_a_valid_target_of_an_authorisation_operation(
        mut actor in any_actor(PrincipalType::Internal),
        is_root_actor in any::<bool>(),
        code in any_permission_code(),
        requested in any_scope(),
        subject in any_id(),
    ) {
        actor.is_root = is_root_actor;
        let req = DelegationRequest {
            actor: &actor,
            subject_id: subject,
            subject_principal_type: PrincipalType::Internal,
            subject_is_root: true,
            has_recent_step_up: true,
        };
        prop_assert!(delegation::check_permission_grant(&req, &code, requested).is_err());
    }

    /// **The derivation relation is reflexive and never widens.** A holder can
    /// always reproduce exactly what it holds, and can never produce GLOBAL unless
    /// it already holds GLOBAL.
    #[test]
    fn derivation_is_reflexive_and_never_widens_to_global(held in any_scope()) {
        prop_assert!(delegation::derivable(held, held), "{:?} should derive itself", held);
        if held.scope_type != ScopeType::Global {
            prop_assert!(
                !delegation::derivable(held, Scope::global()),
                "{:?} must not derive GLOBAL", held.scope_type
            );
        }
    }

    /// **Derivation is transitive.** If A can hand out B and B can hand out C, then
    /// A can hand out C directly. Without this, a chain of two legitimate
    /// delegations would reach a scope that a single delegation refuses — an
    /// escalation with an extra hop.
    #[test]
    fn derivation_is_transitive(a in any_scope(), b in any_scope(), c in any_scope()) {
        if delegation::derivable(a, b) && delegation::derivable(b, c) {
            prop_assert!(
                delegation::derivable(a, c),
                "{:?} -> {:?} -> {:?} but not {:?} -> {:?} directly",
                a.scope_type, b.scope_type, c.scope_type, a.scope_type, c.scope_type
            );
        }
    }

    /// **An incoherent scope is always refused**, never interpreted. Corrupt
    /// authorization data must fail closed.
    #[test]
    fn malformed_scopes_never_authorise(
        user_id in any_id(),
        target in any_target(),
        code in prop::sample::select(
            catalog::PERMISSIONS.iter().map(|p| p.code.to_string()).collect::<Vec<_>>()
        ),
        rt in any_resource_type(),
        rid in any_id(),
    ) {
        let mut actor = ActorContext::empty(user_id, PrincipalType::Internal);
        // RESOURCE without an object.
        actor.allows.push(Grant {
            permission_code: code.clone(),
            scope: Scope { scope_type: ScopeType::Resource, resource_type: None, resource_id: None },
        });
        // GLOBAL carrying an object.
        actor.allows.push(Grant {
            permission_code: code.clone(),
            scope: Scope { scope_type: ScopeType::Global, resource_type: Some(rt), resource_id: Some(rid) },
        });
        prop_assert!(!evaluator::evaluate(&actor, &code, &target).is_allowed());
    }

    /// **The evaluator is a pure function.** Evaluating twice yields the same
    /// decision — no hidden state, no interior mutability, no ordering dependence.
    #[test]
    fn evaluation_is_deterministic(
        actor in any_actor(PrincipalType::Internal),
        code in any_permission_code(),
        target in any_target(),
    ) {
        let first = evaluator::evaluate(&actor, &code, &target);
        let second = evaluator::evaluate(&actor, &code, &target);
        prop_assert_eq!(first, second);
    }

    /// **Root ownership allows everything in the catalogue**, but is still not a
    /// licence to invent permissions — an unknown code stays unknown, so a typo in
    /// a route definition cannot become an accidental grant for the owner.
    #[test]
    fn root_is_allowed_every_catalogued_permission(
        mut actor in any_actor(PrincipalType::Internal),
        target in any_target(),
    ) {
        actor.is_root = true;
        for def in catalog::PERMISSIONS {
            prop_assert!(evaluator::evaluate(&actor, def.code, &target).is_allowed());
        }
    }
}
