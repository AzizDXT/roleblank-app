//! Departments persistence: explicit SQL, explicit columns, parameterised binds.
//!
//! The interesting part of this file is [`visibility_for`]: the translation from
//! the scopes an actor holds into a `WHERE` clause. `Target::Collection` is covered
//! only by `GLOBAL`, so any narrower scope must turn the listing into a *filtered
//! query*. Doing that filtering in PostgreSQL rather than in Rust is what makes
//! "fetch everything, then hide some of it" impossible to reintroduce by accident.
//!
//! Every predicate below is a compile-time `&'static str` selected by a `match` on
//! a closed enum. No part of any SQL string is derived from request input.

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
pub struct DepartmentRow {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub lead_user_id: Option<Uuid>,
    pub version: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct MemberListRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_in_department: String,
    pub joined_at: OffsetDateTime,
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

/// Never `SELECT *`. An explicit list is how a column added later — a token hash,
/// an encrypted blob — does not silently start being loaded into memory.
const COLUMNS_ALIASED: &str = "d.id, d.code, d.name, d.description, d.status, d.lead_user_id, \
                               d.version, d.created_by, d.created_at, d.updated_at, d.archived_at";
const COLUMNS_PLAIN: &str = "id, code, name, description, status, lead_user_id, \
                             version, created_by, created_at, updated_at, archived_at";

/// Only immutable timestamp columns are sortable.
///
/// The pagination cursor is `(timestamp, id)`; a text sort key cannot be encoded
/// in it, and a mutable timestamp (`updated_at`) makes a keyset page boundary move
/// under the reader, silently skipping or repeating rows. Offering `name` here
/// would require widening `Cursor`, which is out of this module's scope.
pub const SORTS: &[(&str, &str)] = &[("created_at", "d.created_at")];
pub const DEFAULT_SORT: &str = "d.created_at";

pub const MEMBER_SORTS: &[(&str, &str)] = &[("joined_at", "dm.joined_at")];
pub const MEMBER_DEFAULT_SORT: &str = "dm.joined_at";

// ---------------------------------------------------------------------------
// Scope -> SQL predicate
// ---------------------------------------------------------------------------

/// What one scope *kind* contributes to a department listing.
///
/// A small closed enum rather than a string builder: adding a `ScopeType` is a
/// compile error here until someone decides what it means for this listing, which
/// is the migration mechanism the authorisation model relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopePredicate {
    /// `GLOBAL` — every department.
    Everything,
    /// `DEPARTMENT`, `ASSIGNED` and `RESOURCE` all resolve to a set of ids that is
    /// computed in Rust and then *bound*, never interpolated.
    IdSet,
    /// Every department **except** a bound set: the actor holds the permission
    /// broadly but has explicit denials that must be subtracted.
    ExcludedIdSet,
    /// `SELF` names the actor's own user record. A department is not a user, so a
    /// `SELF` grant reaches no department at all. Treating it as anything wider
    /// would silently promote a self-service grant into an organisation-wide one.
    Nothing,
}

impl ScopePredicate {
    pub const fn sql(self) -> &'static str {
        match self {
            ScopePredicate::Everything => "TRUE",
            ScopePredicate::IdSet => "d.id = ANY($4::uuid[])",
            ScopePredicate::ExcludedIdSet => "d.id <> ALL($4::uuid[])",
            ScopePredicate::Nothing => "FALSE",
        }
    }
}

/// The permission whose scopes decide what a department listing may return.
///
/// Lives here rather than in the service because `visibility_for` has to consult
/// the actor's *denials* for it, and the rule that a denial narrows the SQL
/// predicate belongs with the code that builds the predicate.
pub const READ_PERMISSION: &str = "departments.read";

/// Department ids this actor is explicitly denied, for `READ_PERMISSION`.
///
/// A `GLOBAL` denial is handled earlier — `effective_scopes` removes the permission
/// outright — so it is deliberately not repeated here. What this covers is the
/// narrow denials that `effective_scopes` documents as "handled per-object at
/// `evaluate` time": true for an object route, and untrue for a listing, which has
/// no per-object step. Without this the object decision and the collection
/// decision disagree, and the row an administrator explicitly denied is returned by
/// the listing (audit finding M-B / TH-49).
fn denied_ids(actor: &ActorContext) -> Vec<Uuid> {
    let mut denied = Vec::new();
    for denial in actor
        .denies
        .iter()
        .filter(|d| d.permission_code == READ_PERMISSION)
    {
        if !denial.scope.is_coherent() {
            continue; // corrupt authorisation data fails closed, never open
        }
        match denial.scope.scope_type {
            // DEPARTMENT and ASSIGNED both resolve to "the departments the actor
            // belongs to" for this listing — `predicate_for` maps them to the same
            // `IdSet`, built from `actor.department_ids`. They must therefore deny
            // the same set; handling only DEPARTMENT left an ASSIGNED-scoped DENY
            // silently ignored by the collection route while the object route
            // honoured it.
            ScopeType::Department | ScopeType::Assigned => {
                denied.extend(actor.department_ids.iter().copied())
            }
            ScopeType::Resource => {
                if denial.scope.resource_type == Some(ResourceType::Department) {
                    if let Some(id) = denial.scope.resource_id {
                        denied.push(id);
                    }
                }
            }
            // GLOBAL is already total; SELF names no department.
            ScopeType::Global | ScopeType::Own => {}
        }
    }
    denied.sort_unstable();
    denied.dedup();
    denied
}

/// "Every department, except the ones explicitly denied."
///
/// Used when the caller holds the permission at `Target::Collection`; the denials
/// still have to be subtracted, which is exactly the step that was missing.
pub fn everything_minus_denials(actor: &ActorContext) -> Visibility {
    let denied = denied_ids(actor);
    if denied.is_empty() {
        Visibility::Everything
    } else {
        Visibility::AllExcept(denied)
    }
}

/// The mapping, as a pure total function. Pinned by tests.
pub const fn predicate_for(scope_type: ScopeType) -> ScopePredicate {
    match scope_type {
        ScopeType::Global => ScopePredicate::Everything,
        ScopeType::Department | ScopeType::Assigned | ScopeType::Resource => ScopePredicate::IdSet,
        ScopeType::Own => ScopePredicate::Nothing,
    }
}

/// The composed decision for one actor and one permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    Everything,
    Only(Vec<Uuid>),
    /// Everything the caller could otherwise see, minus an explicit denial set.
    AllExcept(Vec<Uuid>),
    /// Nothing at all — the caller must not run a query, and must not be handed an
    /// empty page silently either; it is a denial.
    Nothing,
}

impl Visibility {
    pub fn predicate(&self) -> ScopePredicate {
        match self {
            Visibility::Everything => ScopePredicate::Everything,
            Visibility::Only(_) => ScopePredicate::IdSet,
            Visibility::AllExcept(_) => ScopePredicate::ExcludedIdSet,
            Visibility::Nothing => ScopePredicate::Nothing,
        }
    }
}

/// Turn the scopes an actor effectively holds into a filter.
///
/// `DEPARTMENT` and `ASSIGNED` both resolve against `actor.department_ids`, which
/// is the *same* fact `evaluator::scope_covers` consults for the single-resource
/// decision. Deriving the list filter from anything else — a fresh join, say —
/// would let `GET /departments` and `GET /departments/{id}` disagree about which
/// departments exist for this actor.
pub fn visibility_for(scopes: &[Scope], actor: &ActorContext) -> Visibility {
    let mut ids: Vec<Uuid> = Vec::new();
    let mut had_usable_scope = false;

    for scope in scopes.iter().filter(|s| s.is_coherent()) {
        match predicate_for(scope.scope_type) {
            // One GLOBAL grant subsumes every narrower one; nothing later can widen it.
            ScopePredicate::Everything => return Visibility::Everything,
            ScopePredicate::IdSet => {
                had_usable_scope = true;
                if scope.scope_type == ScopeType::Resource {
                    // A RESOURCE grant naming a project or a user does not name a
                    // department, and must not leak into this filter.
                    if scope.resource_type == Some(ResourceType::Department) {
                        if let Some(id) = scope.resource_id {
                            ids.push(id);
                        }
                    }
                } else {
                    ids.extend(actor.department_ids.iter().copied());
                }
            }
            ScopePredicate::Nothing => {}
            // Unreachable by construction: `predicate_for` maps a *scope type*, and
            // an exclusion never comes from a scope type — it comes from the actor's
            // denials, which are applied below. Matched explicitly rather than with a
            // wildcard so that adding a `ScopeType` stays a compile error here.
            ScopePredicate::ExcludedIdSet => {}
        }
    }

    ids.sort_unstable();
    ids.dedup();

    // An explicit denial removes an id the grants would otherwise have allowed.
    // Subtracted here rather than in SQL so that "everything I could see is denied"
    // becomes a refusal, not an empty page that looks like an empty organisation.
    let denied = denied_ids(actor);
    ids.retain(|id| !denied.contains(id));

    if !had_usable_scope || ids.is_empty() {
        Visibility::Nothing
    } else {
        Visibility::Only(ids)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The cursor half of a keyset page. Saturating rather than panicking on an
/// out-of-range instant: a corrupt timestamp must not take the process down.
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

/// `DESC` walks downwards from the cursor, `ASC` upwards. Both are `&'static str`.
const fn keyset_comparator(direction: SortDirection) -> &'static str {
    match direction {
        SortDirection::Desc => "<",
        SortDirection::Asc => ">",
    }
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Parameter layout, identical for every visibility variant:
/// `$1` cursor timestamp, `$2` cursor id, `$3` limit, `$4` the id set (bound only
/// when the predicate actually references it).
pub async fn list(
    pool: &PgPool,
    visibility: &Visibility,
    request: &PageRequest,
) -> AppResult<Vec<DepartmentRow>> {
    let (cursor_at, cursor_id) = cursor_bounds(request)?;
    let column = request.sort_column;
    let direction = request.direction.sql();
    let comparator = keyset_comparator(request.direction);
    let predicate = visibility.predicate().sql();

    let sql = format!(
        "SELECT {COLUMNS_ALIASED} \
           FROM departments d \
          WHERE ($1::timestamptz IS NULL OR ({column}, d.id) {comparator} ($1::timestamptz, $2::uuid)) \
            AND {predicate} \
          ORDER BY {column} {direction}, d.id {direction} \
          LIMIT $3"
    );

    let mut query = sqlx::query_as::<_, DepartmentRow>(sqlx::AssertSqlSafe(sql))
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit());
    if let Visibility::Only(ids) | Visibility::AllExcept(ids) = visibility {
        query = query.bind(ids.clone());
    }

    query.fetch_all(pool).await.map_err(AppError::from)
}

pub async fn find(pool: &PgPool, id: Uuid) -> AppResult<Option<DepartmentRow>> {
    sqlx::query_as::<_, DepartmentRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS_ALIASED} FROM departments d WHERE d.id = $1"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

/// Locks the row for the duration of the transaction, so the authorisation
/// decision is made against a row nobody can change underneath it (TH-43).
pub async fn find_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<DepartmentRow>> {
    sqlx::query_as::<_, DepartmentRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS_ALIASED} FROM departments d WHERE d.id = $1 FOR UPDATE"
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn is_active_member<'e, E>(
    executor: E,
    department_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM department_memberships \
          WHERE department_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(department_id)
    .bind(user_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)?;
    Ok(found.is_some())
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

/// Archiving a department must not orphan work. Counting live projects is the
/// check that turns "silently detach five projects" into a 409.
pub async fn count_live_projects(
    tx: &mut Transaction<'_, Postgres>,
    department_id: Uuid,
) -> AppResult<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM projects WHERE department_id = $1 AND status <> 'ARCHIVED'",
    )
    .bind(department_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(count)
}

pub async fn list_members(
    pool: &PgPool,
    department_id: Uuid,
    request: &PageRequest,
) -> AppResult<Vec<MemberListRow>> {
    let (cursor_at, cursor_id) = cursor_bounds(request)?;
    let column = request.sort_column;
    let direction = request.direction.sql();
    let comparator = keyset_comparator(request.direction);

    let sql = format!(
        "SELECT dm.id, dm.user_id, dm.role_in_department, dm.joined_at, \
                u.display_name, u.email \
           FROM department_memberships dm \
           JOIN users u ON u.id = dm.user_id \
          WHERE dm.department_id = $1 \
            AND dm.removed_at IS NULL \
            AND ($2::timestamptz IS NULL OR ({column}, dm.id) {comparator} ($2::timestamptz, $3::uuid)) \
          ORDER BY {column} {direction}, dm.id {direction} \
          LIMIT $4"
    );

    sqlx::query_as::<_, MemberListRow>(sqlx::AssertSqlSafe(sql))
        .bind(department_id)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
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
    lead_user_id: Option<Uuid>,
    created_by: Uuid,
) -> AppResult<DepartmentRow> {
    sqlx::query_as::<_, DepartmentRow>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO departments (id, code, name, description, status, lead_user_id, version, created_by) \
         VALUES ($1, $2, $3, $4, 'ACTIVE', $5, 1, $6) \
         RETURNING {COLUMNS_PLAIN}"
    )))
    .bind(id)
    .bind(code)
    .bind(name)
    .bind(description)
    .bind(lead_user_id)
    .bind(created_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// `WHERE id = $1 AND version = $2` with `SET version = version + 1`.
///
/// `None` means the version moved between the read and the write. The caller
/// re-reads and reports the actual version rather than overwriting.
pub async fn update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    version: i32,
    name: Option<&str>,
    description: Option<&str>,
    set_lead: bool,
    lead_user_id: Option<Uuid>,
) -> AppResult<Option<DepartmentRow>> {
    sqlx::query_as::<_, DepartmentRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE departments \
            SET name         = COALESCE($3, name), \
                description  = COALESCE($4, description), \
                lead_user_id = CASE WHEN $5 THEN $6 ELSE lead_user_id END, \
                version      = version + 1 \
          WHERE id = $1 AND version = $2 \
          RETURNING {COLUMNS_PLAIN}"
    )))
    .bind(id)
    .bind(version)
    .bind(name)
    .bind(description)
    .bind(set_lead)
    .bind(lead_user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// `status = 'ACTIVE'` in the predicate makes a concurrent double-archive a
/// no-op rather than a second `archived_at` overwrite.
pub async fn archive(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    version: i32,
) -> AppResult<Option<DepartmentRow>> {
    sqlx::query_as::<_, DepartmentRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE departments \
            SET status = 'ARCHIVED', archived_at = now(), version = version + 1 \
          WHERE id = $1 AND version = $2 AND status = 'ACTIVE' \
          RETURNING {COLUMNS_PLAIN}"
    )))
    .bind(id)
    .bind(version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// Returns the `joined_at` the database assigned, so the response reports the
/// stored instant rather than one the application guessed.
pub async fn insert_membership(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    department_id: Uuid,
    user_id: Uuid,
    role_in_department: &str,
    added_by: Uuid,
) -> AppResult<OffsetDateTime> {
    let (joined_at,): (OffsetDateTime,) = sqlx::query_as(
        "INSERT INTO department_memberships \
             (id, department_id, user_id, role_in_department, added_by) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING joined_at",
    )
    .bind(id)
    .bind(department_id)
    .bind(user_id)
    .bind(role_in_department)
    .bind(added_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(joined_at)
}

/// Removal is `removed_at = now()`, never a `DELETE`.
///
/// The row is the evidence that someone was in this department between two dates,
/// which is exactly what an access review later depends on. The partial unique
/// index is on `removed_at IS NULL`, so the same person can be added again
/// afterwards and both facts survive.
pub async fn remove_membership(
    tx: &mut Transaction<'_, Postgres>,
    department_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE department_memberships SET removed_at = now() \
          WHERE department_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(department_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authorization::domain::PrincipalType;

    fn actor_in(departments: Vec<Uuid>) -> ActorContext {
        let mut actor = ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal);
        actor.department_ids = departments;
        actor
    }

    /// The scope -> predicate mapping, pinned exactly. If a reviewer changes one of
    /// these strings they have changed who can see what.
    #[test]
    fn every_scope_kind_maps_to_its_predicate() {
        assert_eq!(predicate_for(ScopeType::Global), ScopePredicate::Everything);
        assert_eq!(predicate_for(ScopeType::Department), ScopePredicate::IdSet);
        assert_eq!(predicate_for(ScopeType::Assigned), ScopePredicate::IdSet);
        assert_eq!(predicate_for(ScopeType::Resource), ScopePredicate::IdSet);
        assert_eq!(predicate_for(ScopeType::Own), ScopePredicate::Nothing);

        assert_eq!(ScopePredicate::Everything.sql(), "TRUE");
        assert_eq!(ScopePredicate::IdSet.sql(), "d.id = ANY($4::uuid[])");
        assert_eq!(ScopePredicate::Nothing.sql(), "FALSE");
    }

    /// The ids reach PostgreSQL as a bound array. Nothing about the predicate text
    /// depends on how many there are, or on anything a caller sent.
    #[test]
    fn the_predicate_text_never_varies_with_the_data() {
        let many: Vec<Uuid> = (0..500).map(|_| Uuid::now_v7()).collect();
        assert_eq!(
            Visibility::Only(many).predicate().sql(),
            ScopePredicate::IdSet.sql()
        );
        assert_eq!(
            Visibility::Only(vec![]).predicate().sql(),
            ScopePredicate::IdSet.sql()
        );
    }

    #[test]
    fn a_global_scope_sees_everything() {
        let actor = actor_in(vec![]);
        assert_eq!(
            visibility_for(&[Scope::global()], &actor),
            Visibility::Everything
        );
        // GLOBAL wins however it is ordered among narrower grants.
        assert_eq!(
            visibility_for(
                &[Scope::simple(ScopeType::Department), Scope::global()],
                &actor_in(vec![Uuid::now_v7()])
            ),
            Visibility::Everything
        );
    }

    #[test]
    fn department_scope_is_limited_to_the_actors_own_departments() {
        let mine = Uuid::now_v7();
        let actor = actor_in(vec![mine]);
        assert_eq!(
            visibility_for(&[Scope::simple(ScopeType::Department)], &actor),
            Visibility::Only(vec![mine])
        );
    }

    /// A department-scoped actor who is in no department must see nothing at all —
    /// never "no filter", which is how a narrow grant becomes a global one.
    #[test]
    fn a_narrow_scope_with_no_memberships_sees_nothing() {
        let actor = actor_in(vec![]);
        for scope in [ScopeType::Department, ScopeType::Assigned] {
            assert_eq!(
                visibility_for(&[Scope::simple(scope)], &actor),
                Visibility::Nothing
            );
        }
    }

    #[test]
    fn self_scope_reaches_no_department() {
        let actor = actor_in(vec![Uuid::now_v7()]);
        assert_eq!(
            visibility_for(&[Scope::simple(ScopeType::Own)], &actor),
            Visibility::Nothing
        );
    }

    #[test]
    fn no_scopes_at_all_sees_nothing() {
        assert_eq!(
            visibility_for(&[], &actor_in(vec![Uuid::now_v7()])),
            Visibility::Nothing
        );
    }

    #[test]
    fn a_resource_scope_naming_another_resource_type_leaks_nothing() {
        let actor = actor_in(vec![]);
        let project = Scope::resource(ResourceType::Project, Uuid::now_v7());
        assert_eq!(visibility_for(&[project], &actor), Visibility::Nothing);

        let department = Uuid::now_v7();
        assert_eq!(
            visibility_for(
                &[Scope::resource(ResourceType::Department, department)],
                &actor
            ),
            Visibility::Only(vec![department])
        );
    }

    #[test]
    fn incoherent_scopes_fail_closed() {
        let actor = actor_in(vec![Uuid::now_v7()]);
        let malformed = Scope {
            scope_type: ScopeType::Resource,
            resource_type: None,
            resource_id: None,
        };
        assert_eq!(visibility_for(&[malformed], &actor), Visibility::Nothing);
    }

    #[test]
    fn combined_scopes_union_without_duplicates() {
        let mine = Uuid::now_v7();
        let named = Uuid::now_v7();
        let actor = actor_in(vec![mine]);
        let Visibility::Only(ids) = visibility_for(
            &[
                Scope::simple(ScopeType::Department),
                Scope::simple(ScopeType::Assigned),
                Scope::resource(ResourceType::Department, named),
                Scope::resource(ResourceType::Department, mine),
            ],
            &actor,
        ) else {
            panic!("expected a filtered listing");
        };
        assert_eq!(ids.len(), 2, "duplicates must collapse: {ids:?}");
        assert!(ids.contains(&mine) && ids.contains(&named));
    }

    #[test]
    fn only_immutable_timestamp_columns_are_sortable() {
        assert_eq!(SORTS, &[("created_at", "d.created_at")]);
        assert!(SORTS.iter().all(|(_, column)| column.starts_with("d.")));
    }

    #[test]
    fn the_keyset_comparator_follows_the_direction() {
        assert_eq!(keyset_comparator(SortDirection::Desc), "<");
        assert_eq!(keyset_comparator(SortDirection::Asc), ">");
    }
}
