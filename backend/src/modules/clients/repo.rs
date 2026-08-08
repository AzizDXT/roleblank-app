//! Client-accounts persistence: explicit SQL, explicit columns, parameterised binds.
//!
//! Every SQL fragment assembled here is a compile-time literal selected by a
//! `match` on a closed enum, or a `&'static str` returned by
//! `PageRequest::resolve` from an allowlist. Nothing a caller sends is ever
//! concatenated into a statement — user data reaches PostgreSQL only as a bind.
//! That is the audit `sqlx::AssertSqlSafe` asks for at each call site below.

use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::modules::authorization::domain::{ActorContext, ResourceType, Scope, ScopeType};
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{PageRequest, SortDirection};

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct ClientAccountRow {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub account_manager_user_id: Option<Uuid>,
    pub version: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct MembershipRow {
    pub id: Uuid,
    pub status: String,
    pub invited_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct MemberListRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: String,
    pub invited_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
    pub display_name: String,
    pub email: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserBriefRow {
    pub id: Uuid,
    pub principal_type: String,
    pub status: String,
    pub display_name: String,
    pub email: String,
}

const COLUMNS_ALIASED: &str = "c.id, c.code, c.name, c.description, c.status, \
                               c.account_manager_user_id, c.version, c.created_by, \
                               c.created_at, c.updated_at, c.archived_at";
const COLUMNS_PLAIN: &str = "id, code, name, description, status, \
                             account_manager_user_id, version, created_by, \
                             created_at, updated_at, archived_at";

const MEMBER_COLUMNS: &str = "id, status, invited_by, created_at, activated_at";

/// Only an immutable timestamp column is sortable: the cursor is `(timestamp, id)`
/// and a keyset over a column that changes moves the page boundary under the
/// reader, silently skipping or repeating rows.
pub const SORTS: &[(&str, &str)] = &[("created_at", "c.created_at")];
pub const DEFAULT_SORT: &str = "c.created_at";

pub const MEMBER_SORTS: &[(&str, &str)] = &[("created_at", "cm.created_at")];
pub const MEMBER_DEFAULT_SORT: &str = "cm.created_at";

// ---------------------------------------------------------------------------
// Scope -> SQL predicate
// ---------------------------------------------------------------------------

/// What one scope *kind* contributes to a client-account listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeContribution {
    /// `GLOBAL` — every account.
    Everything,
    /// `RESOURCE(CLIENT_ACCOUNT, id)` — exactly the accounts named by overrides.
    NamedIds,
    /// `ASSIGNED` — the accounts this actor manages.
    ///
    /// "Assigned" for a client account means *account manager*: a client account's
    /// membership table holds external users only, so an internal actor's
    /// relationship to one is the manager column and nothing else. The single
    /// -resource decision uses the same fact (`TargetContext::actor_is_member` is
    /// filled from `account_manager_user_id`), so the list and the detail endpoint
    /// cannot disagree.
    ManagedByActor,
    /// `DEPARTMENT` — a client account belongs to no department, and `SELF` names a
    /// user record. Treating either as wider would silently promote a narrow grant.
    Nothing,
}

/// The mapping, as a pure total function. Pinned by tests.
pub const fn contribution_for(scope_type: ScopeType) -> ScopeContribution {
    match scope_type {
        ScopeType::Global => ScopeContribution::Everything,
        ScopeType::Resource => ScopeContribution::NamedIds,
        ScopeType::Assigned => ScopeContribution::ManagedByActor,
        ScopeType::Department | ScopeType::Own => ScopeContribution::Nothing,
    }
}

/// The composed filter. Each variant states its own parameter contract, and the
/// `match` in [`list`] that binds them is the same `match` that chose the SQL —
/// so a new variant cannot be added with its predicate and its binds out of step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    /// No parameters.
    Everything,
    /// `$4` = `uuid[]`.
    Ids(Vec<Uuid>),
    /// `$4` = the actor's user id.
    ManagedByActor(Uuid),
    /// `$4` = `uuid[]`, `$5` = the actor's user id.
    IdsOrManagedByActor(Vec<Uuid>, Uuid),
    /// No parameters, and the caller must treat it as a denial rather than as an
    /// empty result.
    Nothing,
}

impl Visibility {
    /// `$4` is **always** the explicit denial set, whatever the variant.
    ///
    /// Binding it at a fixed position, unconditionally, is deliberate: an exclusion
    /// that is only appended "when there is something to exclude" is an exclusion
    /// somebody eventually forgets to append. An empty array makes
    /// `c.id <> ALL('{}')` simply true, so the uniform shape costs nothing. The
    /// variant's own parameters therefore start at `$5`.
    pub fn sql(&self) -> &'static str {
        match self {
            Visibility::Everything => "c.id <> ALL($4::uuid[])",
            Visibility::Ids(_) => "c.id = ANY($5::uuid[]) AND c.id <> ALL($4::uuid[])",
            Visibility::ManagedByActor(_) => {
                "c.account_manager_user_id = $5 AND c.id <> ALL($4::uuid[])"
            }
            Visibility::IdsOrManagedByActor(_, _) => {
                "(c.id = ANY($5::uuid[]) OR c.account_manager_user_id = $6)                  AND c.id <> ALL($4::uuid[])"
            }
            Visibility::Nothing => "FALSE",
        }
    }
}

/// The permission whose scopes decide what a client listing may return.
pub const READ_PERMISSION: &str = "clients.read";

/// Client-account ids this actor is explicitly denied, for `READ_PERMISSION`.
///
/// `effective_scopes` strips only GLOBAL denials and documents the rest as
/// "handled per-object at `evaluate` time" — which a listing does not do. Without
/// this the collection route returns rows that `GET /clients/{id}` refuses
/// (audit finding M-B / TH-49).
pub fn denied_ids(actor: &ActorContext) -> Vec<Uuid> {
    let mut denied = Vec::new();
    for denial in actor
        .denies
        .iter()
        .filter(|d| d.permission_code == READ_PERMISSION)
    {
        if !denial.scope.is_coherent() {
            continue; // corrupt authorisation data fails closed, never open
        }
        // A client account belongs to no department, so only a RESOURCE denial
        // naming a client account can reach one. GLOBAL is already total.
        if denial.scope.scope_type == ScopeType::Resource
            && denial.scope.resource_type == Some(ResourceType::ClientAccount)
        {
            if let Some(id) = denial.scope.resource_id {
                denied.push(id);
            }
        }
    }
    denied.sort_unstable();
    denied.dedup();
    denied
}

/// Turn the scopes an actor effectively holds into a filter.
pub fn visibility_for(scopes: &[Scope], actor: &ActorContext) -> Visibility {
    let mut ids: Vec<Uuid> = Vec::new();
    let mut manages = false;

    for scope in scopes.iter().filter(|s| s.is_coherent()) {
        match contribution_for(scope.scope_type) {
            // A GLOBAL grant subsumes everything narrower; nothing later widens it.
            ScopeContribution::Everything => return Visibility::Everything,
            ScopeContribution::NamedIds => {
                // A RESOURCE grant naming a project or a user names no client
                // account and must not leak into this filter.
                if scope.resource_type == Some(ResourceType::ClientAccount) {
                    if let Some(id) = scope.resource_id {
                        ids.push(id);
                    }
                }
            }
            ScopeContribution::ManagedByActor => manages = true,
            ScopeContribution::Nothing => {}
        }
    }

    ids.sort_unstable();
    ids.dedup();
    match (ids.is_empty(), manages) {
        (true, false) => Visibility::Nothing,
        (true, true) => Visibility::ManagedByActor(actor.user_id),
        (false, false) => Visibility::Ids(ids),
        (false, true) => Visibility::IdsOrManagedByActor(ids, actor.user_id),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn cursor_micros(at: OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos() / 1_000).unwrap_or(i64::MAX)
}

fn cursor_bounds(request: &PageRequest) -> AppResult<(Option<OffsetDateTime>, Option<Uuid>)> {
    match &request.cursor {
        None => Ok((None, None)),
        Some(cursor) => {
            let at = OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(cursor.timestamp_micros) * 1_000,
            )
            .map_err(|_| AppError::field("cursor", "INVALID", "Malformed pagination cursor."))?;
            Ok((Some(at), Some(cursor.id)))
        }
    }
}

const fn keyset_comparator(direction: SortDirection) -> &'static str {
    match direction {
        SortDirection::Desc => "<",
        SortDirection::Asc => ">",
    }
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// `$1` cursor timestamp, `$2` cursor id, `$3` limit, then the visibility
/// parameters the chosen predicate declares.
pub async fn list(
    pool: &PgPool,
    visibility: &Visibility,
    denied: &[Uuid],
    request: &PageRequest,
) -> AppResult<Vec<ClientAccountRow>> {
    let (cursor_at, cursor_id) = cursor_bounds(request)?;
    let column = request.sort_column;
    let direction = request.direction.sql();
    let comparator = keyset_comparator(request.direction);
    let predicate = visibility.sql();

    let sql = format!(
        "SELECT {COLUMNS_ALIASED} \
           FROM client_accounts c \
          WHERE ($1::timestamptz IS NULL OR ({column}, c.id) {comparator} ($1::timestamptz, $2::uuid)) \
            AND {predicate} \
          ORDER BY {column} {direction}, c.id {direction} \
          LIMIT $3"
    );

    let mut query = sqlx::query_as::<_, ClientAccountRow>(sqlx::AssertSqlSafe(sql))
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        // $4 — always, see `Visibility::sql`.
        .bind(denied.to_vec());
    query = match visibility {
        Visibility::Everything | Visibility::Nothing => query,
        Visibility::Ids(ids) => query.bind(ids.clone()),
        Visibility::ManagedByActor(actor) => query.bind(*actor),
        Visibility::IdsOrManagedByActor(ids, actor) => query.bind(ids.clone()).bind(*actor),
    };

    query.fetch_all(pool).await.map_err(AppError::from)
}

pub async fn find(pool: &PgPool, id: Uuid) -> AppResult<Option<ClientAccountRow>> {
    sqlx::query_as::<_, ClientAccountRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS_ALIASED} FROM client_accounts c WHERE c.id = $1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

pub async fn find_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<ClientAccountRow>> {
    sqlx::query_as::<_, ClientAccountRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS_ALIASED} FROM client_accounts c WHERE c.id = $1 FOR UPDATE"
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn find_user<'e, E>(executor: E, user_id: Uuid) -> AppResult<Option<UserBriefRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, UserBriefRow>(
        "SELECT id, principal_type, status, display_name, email FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

/// `REMOVED` memberships are excluded: they are history, and a list an operator
/// scans to decide who can see what should show only what currently exists.
pub async fn list_members(
    pool: &PgPool,
    client_account_id: Uuid,
    request: &PageRequest,
) -> AppResult<Vec<MemberListRow>> {
    let (cursor_at, cursor_id) = cursor_bounds(request)?;
    let column = request.sort_column;
    let direction = request.direction.sql();
    let comparator = keyset_comparator(request.direction);

    let sql = format!(
        "SELECT cm.id, cm.user_id, cm.status, cm.invited_by, cm.created_at, cm.activated_at, \
                u.display_name, u.email \
           FROM client_memberships cm \
           JOIN users u ON u.id = cm.user_id \
          WHERE cm.client_account_id = $1 \
            AND cm.status <> 'REMOVED' \
            AND ($2::timestamptz IS NULL OR ({column}, cm.id) {comparator} ($2::timestamptz, $3::uuid)) \
          ORDER BY {column} {direction}, cm.id {direction} \
          LIMIT $4"
    );

    sqlx::query_as::<_, MemberListRow>(sqlx::AssertSqlSafe(sql))
        .bind(client_account_id)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

/// The unique index on `(client_account_id, user_id)` is total — unlike department
/// membership there is no partial index — so a previously removed member is found
/// here and revived rather than inserted again.
pub async fn find_membership_for_update(
    tx: &mut Transaction<'_, Postgres>,
    client_account_id: Uuid,
    user_id: Uuid,
) -> AppResult<Option<MembershipRow>> {
    sqlx::query_as::<_, MembershipRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {MEMBER_COLUMNS} FROM client_memberships \
          WHERE client_account_id = $1 AND user_id = $2 FOR UPDATE"
    )))
    .bind(client_account_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

pub async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    code: &str,
    name: &str,
    description: &str,
    account_manager_user_id: Option<Uuid>,
    created_by: Uuid,
) -> AppResult<ClientAccountRow> {
    sqlx::query_as::<_, ClientAccountRow>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO client_accounts \
             (id, code, name, description, status, account_manager_user_id, version, created_by) \
         VALUES ($1, $2, $3, $4, 'ACTIVE', $5, 1, $6) \
         RETURNING {COLUMNS_PLAIN}"
    )))
    .bind(id)
    .bind(code)
    .bind(name)
    .bind(description)
    .bind(account_manager_user_id)
    .bind(created_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    version: i32,
    name: Option<&str>,
    description: Option<&str>,
    set_manager: bool,
    account_manager_user_id: Option<Uuid>,
) -> AppResult<Option<ClientAccountRow>> {
    sqlx::query_as::<_, ClientAccountRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE client_accounts \
            SET name                    = COALESCE($3, name), \
                description             = COALESCE($4, description), \
                account_manager_user_id = CASE WHEN $5 THEN $6 ELSE account_manager_user_id END, \
                version                 = version + 1 \
          WHERE id = $1 AND version = $2 \
          RETURNING {COLUMNS_PLAIN}"
    )))
    .bind(id)
    .bind(version)
    .bind(name)
    .bind(description)
    .bind(set_manager)
    .bind(account_manager_user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// `status <> 'ARCHIVED'` in the predicate makes a concurrent double-archive a
/// no-op instead of a second `archived_at` overwrite.
pub async fn archive(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    version: i32,
) -> AppResult<Option<ClientAccountRow>> {
    sqlx::query_as::<_, ClientAccountRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE client_accounts \
            SET status = 'ARCHIVED', archived_at = now(), version = version + 1 \
          WHERE id = $1 AND version = $2 AND status <> 'ARCHIVED' \
          RETURNING {COLUMNS_PLAIN}"
    )))
    .bind(id)
    .bind(version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// A new membership is always `PENDING`. There is no parameter for the status.
pub async fn insert_pending_membership(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    client_account_id: Uuid,
    user_id: Uuid,
    invited_by: Uuid,
) -> AppResult<MembershipRow> {
    sqlx::query_as::<_, MembershipRow>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO client_memberships \
             (id, client_account_id, user_id, status, invited_by) \
         VALUES ($1, $2, $3, 'PENDING', $4) \
         RETURNING {MEMBER_COLUMNS}"
    )))
    .bind(id)
    .bind(client_account_id)
    .bind(user_id)
    .bind(invited_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Re-adding someone who was removed returns them to `PENDING`, never to `ACTIVE`.
/// `activated_at` is cleared so the column always means "when the *current* grant
/// of visibility began".
pub async fn revive_membership_as_pending(
    tx: &mut Transaction<'_, Postgres>,
    membership_id: Uuid,
    invited_by: Uuid,
) -> AppResult<Option<MembershipRow>> {
    sqlx::query_as::<_, MembershipRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE client_memberships \
            SET status = 'PENDING', invited_by = $2, activated_at = NULL, removed_at = NULL \
          WHERE id = $1 AND status = 'REMOVED' \
          RETURNING {MEMBER_COLUMNS}"
    )))
    .bind(membership_id)
    .bind(invited_by)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// The status predicate is the second half of the transition rule: the service
/// refuses an impossible transition with a legible error, and the statement
/// refuses it again so a concurrent activation cannot double-apply.
pub async fn activate_membership(
    tx: &mut Transaction<'_, Postgres>,
    membership_id: Uuid,
) -> AppResult<Option<MembershipRow>> {
    sqlx::query_as::<_, MembershipRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE client_memberships \
            SET status = 'ACTIVE', activated_at = now() \
          WHERE id = $1 AND status IN ('PENDING', 'SUSPENDED') \
          RETURNING {MEMBER_COLUMNS}"
    )))
    .bind(membership_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Removal is a status change plus `removed_at`, never a `DELETE`: who could see
/// what, and between which dates, is exactly what an access review needs.
pub async fn remove_membership(
    tx: &mut Transaction<'_, Postgres>,
    membership_id: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE client_memberships SET status = 'REMOVED', removed_at = now(), activated_at = NULL \
          WHERE id = $1 AND status <> 'REMOVED'",
    )
    .bind(membership_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::domain::PrincipalType;

    fn actor() -> ActorContext {
        ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal)
    }

    /// The scope -> predicate mapping, pinned exactly. Changing one of these
    /// strings changes who can see which customers.
    #[test]
    fn every_scope_kind_maps_to_its_contribution() {
        assert_eq!(
            contribution_for(ScopeType::Global),
            ScopeContribution::Everything
        );
        assert_eq!(
            contribution_for(ScopeType::Resource),
            ScopeContribution::NamedIds
        );
        assert_eq!(
            contribution_for(ScopeType::Assigned),
            ScopeContribution::ManagedByActor
        );
        assert_eq!(
            contribution_for(ScopeType::Department),
            ScopeContribution::Nothing
        );
        assert_eq!(contribution_for(ScopeType::Own), ScopeContribution::Nothing);
    }

    /// Every variant carries the denial exclusion at `$4`, unconditionally.
    ///
    /// The uniform shape is the point: an exclusion appended only "when there is
    /// something to exclude" is one somebody eventually forgets. `Nothing` is the
    /// single exception, and only because it already returns no rows at all.
    #[test]
    fn every_filter_variant_has_its_predicate() {
        let id = Uuid::now_v7();
        assert_eq!(Visibility::Everything.sql(), "c.id <> ALL($4::uuid[])");
        assert_eq!(
            Visibility::Ids(vec![id]).sql(),
            "c.id = ANY($5::uuid[]) AND c.id <> ALL($4::uuid[])"
        );
        assert_eq!(
            Visibility::ManagedByActor(id).sql(),
            "c.account_manager_user_id = $5 AND c.id <> ALL($4::uuid[])"
        );
        assert_eq!(
            Visibility::IdsOrManagedByActor(vec![id], id).sql(),
            "(c.id = ANY($5::uuid[]) OR c.account_manager_user_id = $6)                  AND c.id <> ALL($4::uuid[])"
        );
        assert_eq!(Visibility::Nothing.sql(), "FALSE");

        // Not one of them mentions a denial set it does not also bind.
        for sql in [
            Visibility::Everything.sql(),
            Visibility::Ids(vec![id]).sql(),
            Visibility::ManagedByActor(id).sql(),
            Visibility::IdsOrManagedByActor(vec![id], id).sql(),
        ] {
            assert!(
                sql.contains("$4::uuid[]"),
                "a variant lost its denial exclusion: {sql}"
            );
        }
    }

    /// The predicate text is a function of the *scope kinds* only. Nothing a caller
    /// sends, and no amount of data, changes a character of it.
    #[test]
    fn the_predicate_text_never_varies_with_the_data() {
        let many: Vec<Uuid> = (0..1_000).map(|_| Uuid::now_v7()).collect();
        assert_eq!(Visibility::Ids(many).sql(), Visibility::Ids(vec![]).sql());
    }

    #[test]
    fn a_global_scope_sees_every_account() {
        assert_eq!(
            visibility_for(&[Scope::global()], &actor()),
            Visibility::Everything
        );
        assert_eq!(
            visibility_for(
                &[Scope::simple(ScopeType::Assigned), Scope::global()],
                &actor()
            ),
            Visibility::Everything
        );
    }

    #[test]
    fn assigned_scope_narrows_to_the_accounts_the_actor_manages() {
        let a = actor();
        assert_eq!(
            visibility_for(&[Scope::simple(ScopeType::Assigned)], &a),
            Visibility::ManagedByActor(a.user_id)
        );
    }

    #[test]
    fn department_and_self_scopes_reach_no_client_account() {
        let a = actor();
        for scope in [ScopeType::Department, ScopeType::Own] {
            assert_eq!(
                visibility_for(&[Scope::simple(scope)], &a),
                Visibility::Nothing
            );
        }
        assert_eq!(visibility_for(&[], &a), Visibility::Nothing);
    }

    #[test]
    fn a_resource_scope_naming_another_resource_type_leaks_nothing() {
        let a = actor();
        assert_eq!(
            visibility_for(
                &[Scope::resource(ResourceType::Project, Uuid::now_v7())],
                &a
            ),
            Visibility::Nothing
        );
        let account = Uuid::now_v7();
        assert_eq!(
            visibility_for(&[Scope::resource(ResourceType::ClientAccount, account)], &a),
            Visibility::Ids(vec![account])
        );
    }

    #[test]
    fn combined_scopes_produce_the_union_predicate() {
        let a = actor();
        let account = Uuid::now_v7();
        assert_eq!(
            visibility_for(
                &[
                    Scope::resource(ResourceType::ClientAccount, account),
                    Scope::resource(ResourceType::ClientAccount, account),
                    Scope::simple(ScopeType::Assigned),
                ],
                &a
            ),
            Visibility::IdsOrManagedByActor(vec![account], a.user_id),
            "duplicate ids must collapse and the manager clause must survive"
        );
    }

    #[test]
    fn incoherent_scopes_fail_closed() {
        let malformed = Scope {
            scope_type: ScopeType::Resource,
            resource_type: None,
            resource_id: None,
        };
        assert_eq!(visibility_for(&[malformed], &actor()), Visibility::Nothing);
    }

    #[test]
    fn the_keyset_comparator_follows_the_direction() {
        assert_eq!(keyset_comparator(SortDirection::Desc), "<");
        assert_eq!(keyset_comparator(SortDirection::Asc), ">");
    }
}
