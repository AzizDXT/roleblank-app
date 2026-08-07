//! Layer 4: visibility as a SQL predicate.
//!
//! `docs/backend/04-authorization.md` describes four layers. Layers 1–3 (the
//! principal envelope, the policy evaluation and the object-level decision) are
//! Rust. **This file is layer 4, and it is deliberately redundant with all three
//! of them.**
//!
//! The redundancy is the point. Every query that can serve an external principal
//! carries the client-visibility predicate *in its `WHERE` clause*, so a row
//! belonging to another client is never selected, never decoded into a struct and
//! never present in this process's memory — even if the evaluator were wrong, even
//! if a handler forgot to authorise, even if a future refactor moved a `require`
//! call to the wrong side of a branch. A bug in the policy layer becomes a bug that
//! returns *fewer* rows, not a bug that returns another company's project
//! (TH-10, TH-11).
//!
//! The same idea is applied to internal listings: a narrower scope is translated
//! into a `WHERE` clause here rather than into a filter over rows that were already
//! fetched. "Fetch everything and filter in Rust" is refused by the evaluator
//! itself — `Target::Collection` is covered only by `GLOBAL` — and this module is
//! what makes the filtered alternative available.
//!
//! Everything below is a `&'static str`. No part of a predicate is ever built from
//! a value that came from a request.

use uuid::Uuid;

use crate::modules::authorization::domain::{ActorContext, ResourceType, ScopeType};
use crate::modules::authorization::{catalog, evaluator};

// ===========================================================================
// Client visibility
// ===========================================================================

/// The bind position the client-visibility fragments read the actor's user id
/// from.
///
/// **Bind order contract:** every query that embeds `PROJECT_VISIBLE_TO_CLIENT` or
/// `TASK_VISIBLE_TO_CLIENT` MUST bind the authenticated CLIENT principal's
/// `user_id` as `$1`, before any other parameter. Fixing the position rather than
/// renumbering the fragment per call site means a call site cannot get the
/// numbering subtly wrong and silently bind, say, a project id into the identity
/// check. Every other parameter of such a query starts at `$2`.
pub const CLIENT_UID_BIND: usize = 1;

/// A project is visible to an external principal **only** through a live
/// `project_client_links` row, joined to an `ACTIVE` membership in an `ACTIVE`
/// client account.
///
/// Requires the `projects` table to be aliased `p`.
///
/// Note what is *not* here: no `OR`, no fallback, nothing about the project's own
/// columns. Possession of the project's UUID contributes nothing. Revoking a link
/// (`revoked_at`) removes visibility on the very next query, with no cache to
/// invalidate.
pub const PROJECT_VISIBLE_TO_CLIENT: &str = "EXISTS (
        SELECT 1
          FROM project_client_links pcl
          JOIN client_memberships   cm ON cm.client_account_id = pcl.client_account_id
          JOIN client_accounts      ca ON ca.id = pcl.client_account_id
         WHERE pcl.project_id  = p.id
           AND pcl.revoked_at IS NULL
           AND cm.user_id      = $1
           AND cm.status       = 'ACTIVE'
           AND ca.status       = 'ACTIVE'
    )";

/// A task is visible to an external principal **only** when it is individually
/// flagged `client_visible` **and** its project is shared with that principal.
///
/// Requires the `tasks` table to be aliased `t`.
///
/// Sharing a project does not share its tasks. `tasks.client_visible` defaults to
/// `false` and is only ever set by an internal principal through an audited edit,
/// so the default state of every task in a newly shared project is invisible.
pub const TASK_VISIBLE_TO_CLIENT: &str = "(
        t.client_visible
        AND EXISTS (
            SELECT 1
              FROM project_client_links pcl
              JOIN client_memberships   cm ON cm.client_account_id = pcl.client_account_id
              JOIN client_accounts      ca ON ca.id = pcl.client_account_id
             WHERE pcl.project_id  = t.project_id
               AND pcl.revoked_at IS NULL
               AND cm.user_id      = $1
               AND cm.status       = 'ACTIVE'
               AND ca.status       = 'ACTIVE'
        )
    )";

// ===========================================================================
// Scope -> SQL for internal listings
// ===========================================================================

/// The scope-derived `WHERE` clause for a project listing.
///
/// **Bind order (identical for `TASK_SCOPE_PREDICATE`):**
///
/// | # | value | from |
/// | --- | --- | --- |
/// | `$1` | actor user id | `principal.user_id()` |
/// | `$2` | holds `GLOBAL` | `ScopeFilter::global` |
/// | `$3` | departments the grant reaches | `ScopeFilter::department_ids` |
/// | `$4` | holds `ASSIGNED` | `ScopeFilter::assigned` |
/// | `$5` | `RESOURCE`-scoped ids granted | `ScopeFilter::resource_ids` |
/// | `$6` | a `DEPARTMENT`-scoped DENY exists | `ScopeFilter::deny_department` |
/// | `$7` | the actor's own departments | `ScopeFilter::actor_department_ids` |
/// | `$8` | an `ASSIGNED`-scoped DENY exists | `ScopeFilter::deny_assigned` |
/// | `$9` | `RESOURCE`-scoped ids denied | `ScopeFilter::denied_resource_ids` |
///
/// The shape mirrors `evaluator::scope_covers` clause for clause, and the DENY
/// half mirrors the fact that a denial is evaluated before any allow. Every
/// department comparison is wrapped in `coalesce(..., false)`: a project with no
/// department yields `NULL`, and `NOT NULL` is `NULL`, which would silently drop
/// rows from the *allowed* set rather than from the denied one.
pub const PROJECT_SCOPE_PREDICATE: &str = "(
        (
            $2::boolean
            OR coalesce(p.department_id = ANY($3::uuid[]), false)
            OR ($4::boolean AND EXISTS (
                    SELECT 1 FROM project_memberships pm
                     WHERE pm.project_id = p.id
                       AND pm.user_id    = $1
                       AND pm.removed_at IS NULL))
            OR p.id = ANY($5::uuid[])
        )
        AND NOT ($6::boolean AND coalesce(p.department_id = ANY($7::uuid[]), false))
        AND NOT ($8::boolean AND EXISTS (
                    SELECT 1 FROM project_memberships pm
                     WHERE pm.project_id = p.id
                       AND pm.user_id    = $1
                       AND pm.removed_at IS NULL))
        AND NOT (p.id = ANY($9::uuid[]))
    )";

/// The same translation for tasks.
///
/// Requires `tasks` aliased `t` and its project joined as `pr`: a task has no
/// department of its own, so `DEPARTMENT` scope resolves through the project that
/// owns it. `ASSIGNED` resolves through `task_assignees` — being a member of the
/// project is not by itself an assignment, and treating it as one would widen
/// every `tasks.*@ASSIGNED` grant to the whole project.
pub const TASK_SCOPE_PREDICATE: &str = "(
        (
            $2::boolean
            OR coalesce(pr.department_id = ANY($3::uuid[]), false)
            OR ($4::boolean AND EXISTS (
                    SELECT 1 FROM task_assignees ta
                     WHERE ta.task_id    = t.id
                       AND ta.user_id    = $1
                       AND ta.removed_at IS NULL))
            OR t.id = ANY($5::uuid[])
        )
        AND NOT ($6::boolean AND coalesce(pr.department_id = ANY($7::uuid[]), false))
        AND NOT ($8::boolean AND EXISTS (
                    SELECT 1 FROM task_assignees ta
                     WHERE ta.task_id    = t.id
                       AND ta.user_id    = $1
                       AND ta.removed_at IS NULL))
        AND NOT (t.id = ANY($9::uuid[]))
    )";

/// The bound parameters `PROJECT_SCOPE_PREDICATE` and `TASK_SCOPE_PREDICATE`
/// expect, derived from what the actor actually holds.
///
/// Constructing one is the only supported way to list a collection with anything
/// narrower than `GLOBAL`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeFilter {
    pub global: bool,
    pub department_ids: Vec<Uuid>,
    pub assigned: bool,
    pub resource_ids: Vec<Uuid>,
    pub deny_department: bool,
    pub deny_assigned: bool,
    pub denied_resource_ids: Vec<Uuid>,
    pub actor_department_ids: Vec<Uuid>,
}

impl ScopeFilter {
    /// Translate the actor's effective grants for `permission` into bind values.
    ///
    /// `None` means "this actor holds no allow for this permission at all", which
    /// the caller turns into the ordinary authorisation failure. A returned filter
    /// that happens to match nothing — a `DEPARTMENT` grant held by someone in no
    /// department — is deliberately *not* `None`: the actor does hold the
    /// permission, so the honest answer is an empty page, and a `403` there would
    /// leak the actor's own department membership state back at them.
    pub fn build(
        actor: &ActorContext,
        permission: &str,
        resource_type: ResourceType,
    ) -> Option<Self> {
        // Root is the one bypass, and it is the same bypass the evaluator applies.
        if actor.is_root {
            return Some(Self {
                global: true,
                ..Self::default()
            });
        }
        // The principal envelope, before any grant is looked at — the same order as
        // `evaluator::evaluate` steps 2 and 3. An external principal reaching an
        // internal listing is stopped here, not by a filter that returns nothing.
        if !catalog::envelope_permits(permission, actor.principal_type) {
            return None;
        }

        let mut filter = Self {
            actor_department_ids: actor.department_ids.clone(),
            ..Self::default()
        };

        // DENY first, and a GLOBAL deny ends it — exactly as `effective_scopes` does.
        for denial in actor
            .denies
            .iter()
            .filter(|g| g.permission_code == permission)
        {
            if !denial.scope.is_coherent() {
                continue; // corrupt authorisation data fails closed, never open
            }
            match denial.scope.scope_type {
                ScopeType::Global => return None,
                ScopeType::Department => filter.deny_department = true,
                ScopeType::Assigned => filter.deny_assigned = true,
                ScopeType::Resource => {
                    if denial.scope.resource_type == Some(resource_type) {
                        if let Some(id) = denial.scope.resource_id {
                            filter.denied_resource_ids.push(id);
                        }
                    }
                }
                // SELF only ever covers a User target; it denies nothing here.
                ScopeType::Own => {}
            }
        }

        let mut had_any_allow = false;
        for scope in evaluator::effective_scopes(actor, permission) {
            had_any_allow = true;
            match scope.scope_type {
                ScopeType::Global => filter.global = true,
                ScopeType::Department => {
                    filter.department_ids = actor.department_ids.clone();
                }
                ScopeType::Assigned => filter.assigned = true,
                ScopeType::Resource => {
                    if scope.resource_type == Some(resource_type) {
                        if let Some(id) = scope.resource_id {
                            filter.resource_ids.push(id);
                        }
                    }
                }
                // A SELF grant authorises the actor's own user record and nothing
                // in this module. It contributes no rows rather than all of them.
                ScopeType::Own => {}
            }
        }

        if had_any_allow {
            Some(filter)
        } else {
            None
        }
    }

    /// Whether this filter can match any row at all. Used only to skip a query
    /// that provably returns nothing — never to widen one.
    pub fn matches_nothing(&self) -> bool {
        !self.global
            && self.department_ids.is_empty()
            && !self.assigned
            && self.resource_ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::domain::{Grant, PrincipalType, Scope};

    const READ: &str = "projects.read";
    const PORTAL: &str = "client.portal.projects.read";

    fn internal() -> ActorContext {
        ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal)
    }
    fn client() -> ActorContext {
        ActorContext::empty(Uuid::now_v7(), PrincipalType::Client)
    }
    fn allow(a: &mut ActorContext, code: &str, scope: Scope) {
        a.allows.push(Grant {
            permission_code: code.into(),
            scope,
        });
    }
    fn deny(a: &mut ActorContext, code: &str, scope: Scope) {
        a.denies.push(Grant {
            permission_code: code.into(),
            scope,
        });
    }
    fn build(a: &ActorContext) -> Option<ScopeFilter> {
        ScopeFilter::build(a, READ, ResourceType::Project)
    }

    // ---- the client-visibility fragments ------------------------------------

    /// These strings are the last line of defence. If any clause is dropped, the
    /// predicate silently widens and the failure is a cross-client data leak, so
    /// each clause is asserted individually rather than by comparing the whole
    /// string (which nobody would ever read closely in a diff).
    #[test]
    fn the_project_predicate_contains_every_clause_that_makes_it_safe() {
        let p = PROJECT_VISIBLE_TO_CLIENT;
        for clause in [
            "project_client_links",
            "client_memberships",
            "client_accounts",
            "pcl.revoked_at IS NULL",
            "cm.user_id      = $1",
            "cm.status       = 'ACTIVE'",
            "ca.status       = 'ACTIVE'",
            "pcl.project_id  = p.id",
        ] {
            assert!(
                p.contains(clause),
                "the project visibility predicate lost `{clause}`"
            );
        }
        assert!(
            p.starts_with("EXISTS ("),
            "the predicate must be a bare EXISTS"
        );
        assert!(
            !p.contains(" OR "),
            "an OR in the visibility predicate is a bypass; there must be no alternative path"
        );
    }

    #[test]
    fn the_task_predicate_requires_the_per_task_flag_as_well_as_the_project_link() {
        let t = TASK_VISIBLE_TO_CLIENT;
        assert!(
            t.contains("t.client_visible"),
            "sharing a project would expose every task in it"
        );
        assert!(t.contains("pcl.project_id  = t.project_id"));
        for clause in [
            "pcl.revoked_at IS NULL",
            "cm.user_id      = $1",
            "cm.status       = 'ACTIVE'",
            "ca.status       = 'ACTIVE'",
        ] {
            assert!(
                t.contains(clause),
                "the task visibility predicate lost `{clause}`"
            );
        }
        assert!(
            !t.contains(" OR "),
            "the two conditions are AND-ed, never OR-ed"
        );
    }

    #[test]
    fn the_visibility_fragments_bind_the_user_id_at_the_documented_position() {
        assert_eq!(CLIENT_UID_BIND, 1);
        let placeholder = format!("${CLIENT_UID_BIND}");
        assert!(PROJECT_VISIBLE_TO_CLIENT.contains(&placeholder));
        assert!(TASK_VISIBLE_TO_CLIENT.contains(&placeholder));
        // Nothing else in either fragment may be parameterised, or the contract
        // "bind the user id first and start everything else at $2" is broken.
        for fragment in [PROJECT_VISIBLE_TO_CLIENT, TASK_VISIBLE_TO_CLIENT] {
            for n in 2..=9 {
                assert!(
                    !fragment.contains(&format!("${n}")),
                    "the fragment uses ${n}; it may only ever use $1"
                );
            }
        }
    }

    #[test]
    fn no_predicate_in_this_file_is_ever_interpolated() {
        // A crude but effective guard: a format placeholder in one of these
        // constants would mean somebody intended to build it from a request value.
        for s in [
            PROJECT_VISIBLE_TO_CLIENT,
            TASK_VISIBLE_TO_CLIENT,
            PROJECT_SCOPE_PREDICATE,
            TASK_SCOPE_PREDICATE,
        ] {
            assert!(
                !s.contains('{'),
                "a predicate contains an interpolation placeholder"
            );
            assert!(
                !s.contains(';'),
                "a predicate contains a statement separator"
            );
            assert!(!s.contains("--"), "a predicate contains a SQL comment");
        }
        // The only string literals anywhere in these predicates are the two fixed
        // status values the visibility rule is defined in terms of.
        for s in [PROJECT_SCOPE_PREDICATE, TASK_SCOPE_PREDICATE] {
            assert!(
                !s.contains('\''),
                "the scope predicates compare only bound values"
            );
        }
        for s in [PROJECT_VISIBLE_TO_CLIENT, TASK_VISIBLE_TO_CLIENT] {
            assert_eq!(
                s.matches('\'').count(),
                4,
                "exactly two quoted 'ACTIVE' literals"
            );
        }
    }

    // ---- scope -> filter ----------------------------------------------------

    #[test]
    fn no_grant_produces_no_filter() {
        assert_eq!(build(&internal()), None);
    }

    #[test]
    fn global_scope_produces_an_unrestricted_filter() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        let f = build(&a).expect("a filter");
        assert!(f.global);
        assert!(!f.matches_nothing());
    }

    #[test]
    fn department_scope_filters_on_the_actors_own_departments() {
        let mine = Uuid::now_v7();
        let also_mine = Uuid::now_v7();
        let mut a = internal();
        a.department_ids = vec![mine, also_mine];
        allow(&mut a, READ, Scope::simple(ScopeType::Department));
        let f = build(&a).expect("a filter");
        assert!(!f.global, "DEPARTMENT must never widen to GLOBAL");
        assert_eq!(f.department_ids, vec![mine, also_mine]);
        assert!(!f.assigned);
        assert!(f.resource_ids.is_empty());
    }

    #[test]
    fn assigned_scope_filters_on_membership_only() {
        let mut a = internal();
        allow(&mut a, READ, Scope::simple(ScopeType::Assigned));
        let f = build(&a).expect("a filter");
        assert!(f.assigned);
        assert!(!f.global);
        assert!(f.department_ids.is_empty());
    }

    #[test]
    fn resource_scope_filters_on_exactly_the_named_objects_of_the_right_type() {
        let wanted = Uuid::now_v7();
        let other_type = Uuid::now_v7();
        let mut a = internal();
        allow(&mut a, READ, Scope::resource(ResourceType::Project, wanted));
        allow(
            &mut a,
            READ,
            Scope::resource(ResourceType::Task, other_type),
        );
        let f = build(&a).expect("a filter");
        assert_eq!(
            f.resource_ids,
            vec![wanted],
            "a TASK-scoped grant must not select a project"
        );
        assert!(!f.global);
    }

    #[test]
    fn self_scope_selects_nothing_rather_than_everything() {
        let mut a = internal();
        allow(&mut a, READ, Scope::simple(ScopeType::Own));
        let f = build(&a).expect("the actor does hold the permission");
        assert!(
            f.matches_nothing(),
            "SELF must contribute no rows, not all rows"
        );
        assert!(!f.global);
    }

    #[test]
    fn a_department_grant_held_by_someone_in_no_department_yields_an_empty_page_not_a_denial() {
        let mut a = internal();
        a.department_ids = vec![];
        allow(&mut a, READ, Scope::simple(ScopeType::Department));
        let f = build(&a).expect("holding the permission is not the same as matching rows");
        assert!(f.matches_nothing());
    }

    #[test]
    fn several_scopes_union_rather_than_override() {
        let dept = Uuid::now_v7();
        let named = Uuid::now_v7();
        let mut a = internal();
        a.department_ids = vec![dept];
        allow(&mut a, READ, Scope::simple(ScopeType::Department));
        allow(&mut a, READ, Scope::simple(ScopeType::Assigned));
        allow(&mut a, READ, Scope::resource(ResourceType::Project, named));
        let f = build(&a).expect("a filter");
        assert_eq!(f.department_ids, vec![dept]);
        assert!(f.assigned);
        assert_eq!(f.resource_ids, vec![named]);
    }

    // ---- DENY --------------------------------------------------------------

    #[test]
    fn a_global_deny_removes_the_listing_entirely() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        deny(&mut a, READ, Scope::global());
        assert_eq!(
            build(&a),
            None,
            "adding allows can never overturn a global DENY"
        );
    }

    #[test]
    fn a_resource_deny_excludes_exactly_that_row() {
        let blocked = Uuid::now_v7();
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        deny(
            &mut a,
            READ,
            Scope::resource(ResourceType::Project, blocked),
        );
        let f = build(&a).expect("a filter");
        assert!(f.global);
        assert_eq!(f.denied_resource_ids, vec![blocked]);
    }

    #[test]
    fn narrow_denies_are_carried_into_the_query_not_dropped() {
        let dept = Uuid::now_v7();
        let mut a = internal();
        a.department_ids = vec![dept];
        allow(&mut a, READ, Scope::global());
        deny(&mut a, READ, Scope::simple(ScopeType::Department));
        deny(&mut a, READ, Scope::simple(ScopeType::Assigned));
        let f = build(&a).expect("a filter");
        assert!(f.deny_department);
        assert!(f.deny_assigned);
        assert_eq!(f.actor_department_ids, vec![dept]);
    }

    #[test]
    fn a_deny_on_another_permission_is_irrelevant() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        deny(&mut a, "projects.update", Scope::global());
        assert!(build(&a).expect("a filter").global);
    }

    #[test]
    fn an_incoherent_deny_is_ignored_rather_than_interpreted() {
        let mut a = internal();
        allow(&mut a, READ, Scope::global());
        a.denies.push(Grant {
            permission_code: READ.into(),
            scope: Scope {
                scope_type: ScopeType::Resource,
                resource_type: None,
                resource_id: None,
            },
        });
        let f = build(&a).expect("a filter");
        assert!(f.denied_resource_ids.is_empty());
    }

    // ---- the envelope ------------------------------------------------------

    /// The property this whole module exists to protect: an external principal
    /// cannot obtain an internal listing, however its grants were assembled.
    #[test]
    fn an_external_principal_can_never_build_an_internal_filter() {
        let mut a = client();
        allow(&mut a, READ, Scope::global());
        allow(&mut a, "tasks.read", Scope::global());
        allow(&mut a, "projects.update", Scope::global());
        assert_eq!(ScopeFilter::build(&a, READ, ResourceType::Project), None);
        assert_eq!(
            ScopeFilter::build(&a, "tasks.read", ResourceType::Task),
            None
        );
    }

    #[test]
    fn an_external_principal_can_build_a_portal_filter() {
        let mut a = client();
        allow(&mut a, PORTAL, Scope::simple(ScopeType::Assigned));
        let f = ScopeFilter::build(&a, PORTAL, ResourceType::Project)
            .expect("the portal permission is within the envelope");
        assert!(f.assigned);
        assert!(!f.global);
    }

    #[test]
    fn an_unknown_permission_produces_no_filter() {
        let mut a = internal();
        allow(&mut a, "projects.read_everything", Scope::global());
        assert_eq!(
            ScopeFilter::build(&a, "projects.read_everything", ResourceType::Project),
            None
        );
    }

    #[test]
    fn root_is_global_without_holding_a_grant() {
        let mut a = internal();
        a.is_root = true;
        let f = build(&a).expect("root");
        assert!(f.global);
    }
}
