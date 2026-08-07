//! Explicit SQL for roles, role permissions, assignments and per-user overrides.
//!
//! Rules this file follows without exception (MODULE_GUIDE §4):
//!
//! * `query_as` with a named row struct — never `query!` macros (ADR-001).
//! * Explicit column lists — never `SELECT *`.
//! * Every value is a bind parameter. The only strings ever interpolated into SQL
//!   are `&'static str`s chosen by `PageRequest::resolve` from the allowlist below
//!   and the two comparison/direction operators, which are also `&'static str`.
//! * Writes take `&mut Transaction`, so the caller owns the boundary and the audit
//!   record commits with the change.

use sqlx::{AssertSqlSafe, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{PageRequest, SortDirection};

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub allowed_principal_type: String,
    pub version: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RolePermissionRow {
    pub permission_code: String,
    pub scope_type: String,
}

/// The subject of an authorisation operation, as the database actually describes
/// them. Never reconstructed from request input (TH-13).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubjectRow {
    pub id: Uuid,
    pub principal_type: String,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRoleRow {
    pub role_id: Uuid,
    pub code: String,
    pub name: String,
    pub is_system: bool,
    pub allowed_principal_type: String,
    pub granted_by: Option<Uuid>,
    pub granted_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OverrideRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub permission_code: String,
    pub effect: String,
    pub scope_type: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub expires_at: Option<OffsetDateTime>,
    pub reason: String,
    pub granted_by: Uuid,
    pub granted_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Sorting allowlist
// ---------------------------------------------------------------------------

/// Public sort field -> **bare** column name, chosen at compile time.
///
/// Bare rather than table-qualified because the keyset predicate has to name the
/// same column under two different aliases (see `list_roles`). A client string is
/// only ever *compared* against the left-hand side; the right-hand side is what
/// reaches SQL.
pub const ROLE_SORTS: &[(&str, &str)] = &[
    ("code", "code"),
    ("name", "name"),
    ("created_at", "created_at"),
];

pub const ROLE_DEFAULT_SORT: &str = "created_at";

// ---------------------------------------------------------------------------
// Roles — reads
// ---------------------------------------------------------------------------

const ROLE_COLUMNS: &str = "id, code, name, description, is_system, \
                            allowed_principal_type, version, created_by, created_at, updated_at";

/// One page of roles, keyset-paginated.
///
/// The cursor carries only an id, so the boundary value for the sort column is
/// re-read by a scalar sub-select rather than encoded into the cursor. That keeps
/// one cursor format working for a text sort and a timestamp sort alike, and keeps
/// the comparison a single row-wise `(sort, id)` test — which is what makes the
/// page boundary total and therefore unable to skip or repeat a row.
pub async fn list_roles(pool: &sqlx::PgPool, page: &PageRequest) -> AppResult<Vec<RoleRow>> {
    let sort = page.sort_column; // &'static str from ROLE_SORTS
    let dir = page.direction.sql(); // &'static str
    let cmp = match page.direction {
        SortDirection::Asc => ">",
        SortDirection::Desc => "<",
    };

    let sql = format!(
        "SELECT r.id, r.code, r.name, r.description, r.is_system, r.allowed_principal_type, \
                r.version, r.created_by, r.created_at, r.updated_at \
           FROM roles r \
          WHERE $1::uuid IS NULL \
             OR (r.{sort}, r.id) {cmp} ((SELECT c.{sort} FROM roles c WHERE c.id = $1), $1) \
          ORDER BY r.{sort} {dir}, r.id {dir} \
          LIMIT $2"
    );

    sqlx::query_as::<_, RoleRow>(AssertSqlSafe(sql))
        .bind(page.cursor.as_ref().map(|c| c.id))
        .bind(page.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

pub async fn find_role<'e, E>(exec: E, id: Uuid) -> AppResult<Option<RoleRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, RoleRow>(AssertSqlSafe(format!(
        "SELECT {ROLE_COLUMNS} FROM roles WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(exec)
    .await
    .map_err(AppError::from)
}

/// Load a role for mutation with the row locked until the transaction ends.
///
/// Without the lock, two concurrent `PATCH`es could each read version 3, each pass
/// the version check, and the second could overwrite a permission set the first
/// had just replaced (TH-43).
pub async fn find_role_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<RoleRow>> {
    sqlx::query_as::<_, RoleRow>(AssertSqlSafe(format!(
        "SELECT {ROLE_COLUMNS} FROM roles WHERE id = $1 FOR UPDATE"
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn role_permissions<'e, E>(exec: E, role_id: Uuid) -> AppResult<Vec<RolePermissionRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, RolePermissionRow>(
        "SELECT permission_code, scope_type FROM role_permissions \
          WHERE role_id = $1 ORDER BY permission_code",
    )
    .bind(role_id)
    .fetch_all(exec)
    .await
    .map_err(AppError::from)
}

/// How many users currently hold this role. `DELETE` is refused while this is > 0.
pub async fn count_role_assignments(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
) -> AppResult<i64> {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_role_assignments WHERE role_id = $1")
        .bind(role_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// Everyone whose effective authority changes when this role's contents change.
pub async fn role_holder_ids(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
) -> AppResult<Vec<Uuid>> {
    sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM user_role_assignments WHERE role_id = $1")
        .bind(role_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::from)
}

// ---------------------------------------------------------------------------
// Roles — writes
// ---------------------------------------------------------------------------

/// `is_system` is not a parameter: nothing reachable from the API may create a
/// system role, so the column is left at its `false` default.
pub async fn insert_role(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    code: &str,
    name: &str,
    description: &str,
    allowed_principal_type: &str,
    created_by: Uuid,
) -> AppResult<RoleRow> {
    sqlx::query_as::<_, RoleRow>(AssertSqlSafe(format!(
        "INSERT INTO roles (id, code, name, description, allowed_principal_type, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {ROLE_COLUMNS}"
    )))
    .bind(id)
    .bind(code)
    .bind(name)
    .bind(description)
    .bind(allowed_principal_type)
    .bind(created_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// `WHERE id = $1 AND version = $2` with `version = version + 1`.
///
/// `None` means zero rows matched, which the service turns into a
/// `VersionConflict` rather than a silent overwrite (MODULE_GUIDE §3.4).
/// `is_system` is in the predicate as a second, independent refusal: even a defect
/// in the delegation call above cannot rewrite a built-in role.
pub async fn update_role(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    expected_version: i32,
    name: &str,
    description: &str,
) -> AppResult<Option<RoleRow>> {
    sqlx::query_as::<_, RoleRow>(AssertSqlSafe(format!(
        "UPDATE roles SET name = $3, description = $4, version = version + 1 \
          WHERE id = $1 AND version = $2 AND is_system = false \
        RETURNING {ROLE_COLUMNS}"
    )))
    .bind(id)
    .bind(expected_version)
    .bind(name)
    .bind(description)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn delete_role_permissions(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
) -> AppResult<()> {
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

pub async fn insert_role_permission(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
    permission_code: &str,
    scope_type: &str,
    granted_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_code, scope_type, granted_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(role_id)
    .bind(permission_code)
    .bind(scope_type)
    .bind(granted_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Returns the number of rows removed. `is_system = false` is in the predicate for
/// the same reason as in `update_role`.
pub async fn delete_role(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM roles WHERE id = $1 AND is_system = false")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

pub async fn find_user<'e, E>(exec: E, user_id: Uuid) -> AppResult<Option<SubjectRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, SubjectRow>("SELECT id, principal_type, status FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(exec)
        .await
        .map_err(AppError::from)
}

/// Lock the subject for the duration of an authority change.
///
/// This is the TH-43 barrier: the delegation decision is taken against a row that
/// cannot move underneath it, so a concurrent privilege change on the same subject
/// serialises behind this one instead of interleaving with it.
pub async fn lock_user(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<Option<SubjectRow>> {
    sqlx::query_as::<_, SubjectRow>(
        "SELECT id, principal_type, status FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

// ---------------------------------------------------------------------------
// Role assignments
// ---------------------------------------------------------------------------

pub async fn list_user_roles<'e, E>(exec: E, user_id: Uuid) -> AppResult<Vec<UserRoleRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, UserRoleRow>(
        "SELECT r.id AS role_id, r.code, r.name, r.is_system, r.allowed_principal_type, \
                ura.granted_by, ura.granted_at \
           FROM user_role_assignments ura \
           JOIN roles r ON r.id = ura.role_id \
          WHERE ura.user_id = $1 \
          ORDER BY r.code",
    )
    .bind(user_id)
    .fetch_all(exec)
    .await
    .map_err(AppError::from)
}

pub async fn assignment_exists(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<bool> {
    let found: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM user_role_assignments WHERE user_id = $1 AND role_id = $2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(found.is_some())
}

pub async fn insert_role_assignment(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    granted_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_role_assignments (id, user_id, role_id, granted_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(role_id)
    .bind(granted_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Zero rows removed means the user never held the role, which is a `404` and not
/// a silent success — "remove role X" must not report success when X was never
/// there, because an operator would believe an authority they never removed is gone.
pub async fn delete_role_assignment(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    role_id: Uuid,
) -> AppResult<u64> {
    let result =
        sqlx::query("DELETE FROM user_role_assignments WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Per-user permission overrides
// ---------------------------------------------------------------------------

const OVERRIDE_COLUMNS: &str = "id, user_id, permission_code, effect, scope_type, \
                                resource_type, resource_id, expires_at, reason, \
                                granted_by, granted_at";

pub async fn list_overrides<'e, E>(exec: E, user_id: Uuid) -> AppResult<Vec<OverrideRow>>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<_, OverrideRow>(AssertSqlSafe(format!(
        "SELECT {OVERRIDE_COLUMNS} FROM user_permission_overrides \
          WHERE user_id = $1 ORDER BY permission_code, effect"
    )))
    .bind(user_id)
    .fetch_all(exec)
    .await
    .map_err(AppError::from)
}

/// Scoped to the subject on purpose: an override id from another user's account
/// must not be removable through this user's path (an IDOR that would otherwise
/// look like a harmless convenience).
pub async fn find_override_for_update(
    tx: &mut Transaction<'_, Postgres>,
    override_id: Uuid,
    user_id: Uuid,
) -> AppResult<Option<OverrideRow>> {
    sqlx::query_as::<_, OverrideRow>(AssertSqlSafe(format!(
        "SELECT {OVERRIDE_COLUMNS} FROM user_permission_overrides \
          WHERE id = $1 AND user_id = $2 FOR UPDATE"
    )))
    .bind(override_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_override(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_id: Uuid,
    permission_code: &str,
    effect: &str,
    scope_type: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
    expires_at: Option<OffsetDateTime>,
    reason: &str,
    granted_by: Uuid,
) -> AppResult<OverrideRow> {
    sqlx::query_as::<_, OverrideRow>(AssertSqlSafe(format!(
        "INSERT INTO user_permission_overrides \
             (id, user_id, permission_code, effect, scope_type, resource_type, resource_id, \
              expires_at, reason, granted_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING {OVERRIDE_COLUMNS}"
    )))
    .bind(id)
    .bind(user_id)
    .bind(permission_code)
    .bind(effect)
    .bind(scope_type)
    .bind(resource_type)
    .bind(resource_id)
    .bind(expires_at)
    .bind(reason)
    .bind(granted_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn delete_override(
    tx: &mut Transaction<'_, Postgres>,
    override_id: Uuid,
    user_id: Uuid,
) -> AppResult<u64> {
    let result =
        sqlx::query("DELETE FROM user_permission_overrides WHERE id = $1 AND user_id = $2")
            .bind(override_id)
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::pagination::{PageQuery, MAX_PAGE_SIZE};

    fn query(sort: Option<&str>) -> PageQuery {
        PageQuery {
            cursor: None,
            limit: None,
            sort: sort.map(str::to_string),
            direction: None,
        }
    }

    /// The sort allowlist is the only defence between a query string and
    /// `ORDER BY`, so it is asserted here as well as in `shared::pagination`.
    #[test]
    fn only_the_three_documented_sorts_resolve() {
        for (public, column) in ROLE_SORTS {
            let resolved = PageRequest::resolve(
                &query(Some(public)),
                ROLE_SORTS,
                ROLE_DEFAULT_SORT,
                MAX_PAGE_SIZE,
            )
            .expect("allowlisted sort");
            assert_eq!(resolved.sort_column, *column);
        }
        assert_eq!(
            ROLE_SORTS.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            vec!["code", "name", "created_at"]
        );
    }

    #[test]
    fn a_sort_outside_the_allowlist_never_reaches_sql() {
        for attack in [
            "id",
            "is_system",
            "created_at; DROP TABLE roles--",
            "(SELECT code FROM permissions)",
            "r.code, (SELECT 1)",
            "",
        ] {
            assert!(
                PageRequest::resolve(
                    &query(Some(attack)),
                    ROLE_SORTS,
                    ROLE_DEFAULT_SORT,
                    MAX_PAGE_SIZE
                )
                .is_err(),
                "accepted sort `{attack}`"
            );
        }
    }

    /// Everything interpolated into the roles query must be a compile-time
    /// constant. If this ever fails, a user string has found its way into `ORDER BY`.
    #[test]
    fn interpolated_sql_fragments_are_all_static() {
        let statics: Vec<&'static str> = ROLE_SORTS
            .iter()
            .map(|(_, column)| *column)
            .chain([SortDirection::Asc.sql(), SortDirection::Desc.sql()])
            .collect();
        for fragment in statics {
            assert!(
                fragment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "`{fragment}` is not a bare identifier"
            );
        }
    }
}
