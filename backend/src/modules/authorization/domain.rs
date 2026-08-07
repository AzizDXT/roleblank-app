//! Authorization domain types.
//!
//! These are closed enums on purpose. Adding a scope type or a principal type is a
//! compile error at every match site until it is handled — which is the migration
//! mechanism for this model, and the reason a policy DSL was rejected (ADR-003).

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// The security envelope a human principal lives inside.
///
/// This is not a role and cannot be changed by role assignment. It is fixed when
/// the account is created and determines the maximum authority the account can
/// *ever* hold, before any grant is consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrincipalType {
    Internal,
    Client,
}

impl PrincipalType {
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalType::Internal => "INTERNAL",
            PrincipalType::Client => "CLIENT",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "INTERNAL" => Some(PrincipalType::Internal),
            "CLIENT" => Some(PrincipalType::Client),
            _ => None,
        }
    }
    /// External principals get `404` where an internal principal gets `403`, and
    /// their queries carry the client-visibility predicate.
    pub fn is_external(self) -> bool {
        matches!(self, PrincipalType::Client)
    }
}

impl fmt::Display for PrincipalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ceiling a permission places on who may hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxPrincipalType {
    /// Only INTERNAL principals. The default and the overwhelming majority.
    Internal,
    /// A CLIENT may hold it. Only the `client.portal.*` codes are like this.
    Any,
}

impl MaxPrincipalType {
    pub fn as_str(self) -> &'static str {
        match self {
            MaxPrincipalType::Internal => "INTERNAL",
            MaxPrincipalType::Any => "ANY",
        }
    }
    /// The envelope test. Evaluated before any grant lookup.
    pub fn permits(self, principal: PrincipalType) -> bool {
        match self {
            MaxPrincipalType::Any => true,
            MaxPrincipalType::Internal => matches!(principal, PrincipalType::Internal),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ResourceType {
    Project,
    Task,
    Department,
    ClientAccount,
    User,
}

impl ResourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceType::Project => "PROJECT",
            ResourceType::Task => "TASK",
            ResourceType::Department => "DEPARTMENT",
            ResourceType::ClientAccount => "CLIENT_ACCOUNT",
            ResourceType::User => "USER",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "PROJECT" => Some(ResourceType::Project),
            "TASK" => Some(ResourceType::Task),
            "DEPARTMENT" => Some(ResourceType::Department),
            "CLIENT_ACCOUNT" => Some(ResourceType::ClientAccount),
            "USER" => Some(ResourceType::User),
            _ => None,
        }
    }
}

/// How wide a grant reaches.
///
/// Five variants, no more. See `docs/backend/04-authorization.md` §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScopeType {
    Global,
    Department,
    Assigned,
    #[serde(rename = "SELF")]
    Own,
    Resource,
}

impl ScopeType {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeType::Global => "GLOBAL",
            ScopeType::Department => "DEPARTMENT",
            ScopeType::Assigned => "ASSIGNED",
            ScopeType::Own => "SELF",
            ScopeType::Resource => "RESOURCE",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "GLOBAL" => Some(ScopeType::Global),
            "DEPARTMENT" => Some(ScopeType::Department),
            "ASSIGNED" => Some(ScopeType::Assigned),
            "SELF" => Some(ScopeType::Own),
            "RESOURCE" => Some(ScopeType::Resource),
            _ => None,
        }
    }
    /// Roles may not carry `RESOURCE`: a role is a reusable template and cannot
    /// name a specific object.
    pub fn valid_on_role(self) -> bool {
        !matches!(self, ScopeType::Resource)
    }
}

impl fmt::Display for ScopeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A scope together with the object it names, when it names one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    pub scope_type: ScopeType,
    pub resource_type: Option<ResourceType>,
    pub resource_id: Option<Uuid>,
}

impl Scope {
    pub fn global() -> Self {
        Self {
            scope_type: ScopeType::Global,
            resource_type: None,
            resource_id: None,
        }
    }
    pub fn simple(scope_type: ScopeType) -> Self {
        Self {
            scope_type,
            resource_type: None,
            resource_id: None,
        }
    }
    pub fn resource(resource_type: ResourceType, resource_id: Uuid) -> Self {
        Self {
            scope_type: ScopeType::Resource,
            resource_type: Some(resource_type),
            resource_id: Some(resource_id),
        }
    }
    /// A `RESOURCE` scope without an object, or a non-resource scope carrying one,
    /// is incoherent and must never be constructed from the database or from input.
    pub fn is_coherent(&self) -> bool {
        match self.scope_type {
            ScopeType::Resource => self.resource_type.is_some() && self.resource_id.is_some(),
            _ => self.resource_type.is_none() && self.resource_id.is_none(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "ALLOW",
            Effect::Deny => "DENY",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ALLOW" => Some(Effect::Allow),
            "DENY" => Some(Effect::Deny),
            _ => None,
        }
    }
}

/// One `(permission, scope)` pair the actor holds, from a role or an override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub permission_code: String,
    pub scope: Scope,
}

/// Everything the evaluator needs about the actor, loaded once per request.
#[derive(Debug, Clone)]
pub struct ActorContext {
    pub user_id: Uuid,
    pub principal_type: PrincipalType,
    /// True only for the single `system_ownership.root_user_id`.
    pub is_root: bool,
    /// Departments the actor is an active member of — resolves `DEPARTMENT` scope.
    pub department_ids: Vec<Uuid>,
    /// Client accounts with an ACTIVE membership — the external visibility root.
    pub client_account_ids: Vec<Uuid>,
    pub allows: Vec<Grant>,
    pub denies: Vec<Grant>,
}

impl ActorContext {
    /// A principal with no grants at all. Used for anonymous evaluation paths and
    /// as the safe starting point in tests.
    pub fn empty(user_id: Uuid, principal_type: PrincipalType) -> Self {
        Self {
            user_id,
            principal_type,
            is_root: false,
            department_ids: Vec::new(),
            client_account_ids: Vec::new(),
            allows: Vec::new(),
            denies: Vec::new(),
        }
    }
}

/// What the decision is being made *about*.
///
/// `Collection` is deliberately distinct from a resource: a narrow scope does not
/// authorise "list everything", it turns the listing into a filtered query. Only
/// `GLOBAL` covers `Collection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Collection,
    Resource(TargetContext),
}

/// The facts about a loaded resource that scope evaluation needs.
///
/// Filled in by the service *after* the row is read, which is what makes the
/// object-level decision real rather than route-level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetContext {
    pub resource_type: ResourceType,
    pub resource_id: Uuid,
    /// The department the resource belongs to, if any.
    pub department_id: Option<Uuid>,
    /// Whether the actor is an active member/assignee of this resource.
    pub actor_is_member: bool,
    /// For `User` targets: whether this is the actor's own record.
    pub is_actor_self: bool,
}

impl TargetContext {
    pub fn new(resource_type: ResourceType, resource_id: Uuid) -> Self {
        Self {
            resource_type,
            resource_id,
            department_id: None,
            actor_is_member: false,
            is_actor_self: false,
        }
    }
    pub fn with_department(mut self, department_id: Option<Uuid>) -> Self {
        self.department_id = department_id;
        self
    }
    pub fn with_membership(mut self, actor_is_member: bool) -> Self {
        self.actor_is_member = actor_is_member;
        self
    }
    pub fn own_user(actor_id: Uuid) -> Self {
        Self {
            resource_type: ResourceType::User,
            resource_id: actor_id,
            department_id: None,
            actor_is_member: true,
            is_actor_self: true,
        }
    }
    pub fn other_user(actor_id: Uuid, subject_id: Uuid) -> Self {
        Self {
            resource_type: ResourceType::User,
            resource_id: subject_id,
            department_id: None,
            actor_is_member: false,
            is_actor_self: actor_id == subject_id,
        }
    }
}

/// Why a decision came out the way it did.
///
/// Carried into audit metadata so a denial can be explained without re-deriving it,
/// and so an operator can tell "no grant" from "explicitly denied" from "wrong
/// envelope" — three very different operational problems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    AllowRootOwnership,
    AllowGranted(ScopeType),
    DenyUnknownPermission,
    DenyPrincipalEnvelope,
    DenyExplicitOverride,
    DenyNoGrant,
    DenyOutOfScope,
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        matches!(
            self,
            Decision::AllowRootOwnership | Decision::AllowGranted(_)
        )
    }
    pub fn reason(self) -> &'static str {
        match self {
            Decision::AllowRootOwnership => "root_ownership",
            Decision::AllowGranted(_) => "granted",
            Decision::DenyUnknownPermission => "unknown_permission",
            Decision::DenyPrincipalEnvelope => "principal_envelope",
            Decision::DenyExplicitOverride => "explicit_deny",
            Decision::DenyNoGrant => "no_grant",
            Decision::DenyOutOfScope => "out_of_scope",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_and_scope_strings_round_trip() {
        for p in [PrincipalType::Internal, PrincipalType::Client] {
            assert_eq!(PrincipalType::parse(p.as_str()), Some(p));
        }
        for s in [
            ScopeType::Global,
            ScopeType::Department,
            ScopeType::Assigned,
            ScopeType::Own,
            ScopeType::Resource,
        ] {
            assert_eq!(ScopeType::parse(s.as_str()), Some(s));
        }
        for r in [
            ResourceType::Project,
            ResourceType::Task,
            ResourceType::Department,
            ResourceType::ClientAccount,
            ResourceType::User,
        ] {
            assert_eq!(ResourceType::parse(r.as_str()), Some(r));
        }
    }

    #[test]
    fn unknown_strings_do_not_parse() {
        assert_eq!(PrincipalType::parse("ADMIN"), None);
        assert_eq!(
            PrincipalType::parse("internal"),
            None,
            "parsing is exact-case"
        );
        assert_eq!(ScopeType::parse("EVERYTHING"), None);
        assert_eq!(ScopeType::parse(""), None);
        assert_eq!(Effect::parse("MAYBE"), None);
    }

    #[test]
    fn the_envelope_only_admits_clients_to_any_permissions() {
        assert!(MaxPrincipalType::Internal.permits(PrincipalType::Internal));
        assert!(!MaxPrincipalType::Internal.permits(PrincipalType::Client));
        assert!(MaxPrincipalType::Any.permits(PrincipalType::Internal));
        assert!(MaxPrincipalType::Any.permits(PrincipalType::Client));
    }

    #[test]
    fn scope_coherence_rejects_malformed_combinations() {
        assert!(Scope::global().is_coherent());
        assert!(Scope::simple(ScopeType::Assigned).is_coherent());
        assert!(Scope::resource(ResourceType::Project, Uuid::now_v7()).is_coherent());

        // RESOURCE without an object.
        assert!(!Scope {
            scope_type: ScopeType::Resource,
            resource_type: None,
            resource_id: None
        }
        .is_coherent());
        // GLOBAL carrying an object.
        assert!(!Scope {
            scope_type: ScopeType::Global,
            resource_type: Some(ResourceType::Project),
            resource_id: Some(Uuid::now_v7())
        }
        .is_coherent());
    }

    #[test]
    fn roles_cannot_carry_resource_scope() {
        assert!(!ScopeType::Resource.valid_on_role());
        for s in [
            ScopeType::Global,
            ScopeType::Department,
            ScopeType::Assigned,
            ScopeType::Own,
        ] {
            assert!(s.valid_on_role());
        }
    }

    #[test]
    fn self_scope_serialises_as_self_not_own() {
        // The wire name is SELF; `Own` is only the Rust identifier, because `Self`
        // is a keyword. A mismatch here would silently break every stored grant.
        assert_eq!(ScopeType::Own.as_str(), "SELF");
        assert_eq!(serde_json::to_string(&ScopeType::Own).unwrap(), "\"SELF\"");
        assert_eq!(
            serde_json::from_str::<ScopeType>("\"SELF\"").unwrap(),
            ScopeType::Own
        );
    }
}
