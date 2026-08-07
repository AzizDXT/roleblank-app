//! Project persistence.
//!
//! Explicit SQL, explicit column lists, parameterised binds only. No `query!`
//! macros (ADR-001) and no `SELECT *` — an implicit column list is how a column
//! added later reaches a projection nobody re-reviewed.
//!
//! Two column lists exist for the same table on purpose. `PROJECT_COLUMNS` serves
//! internal callers; `CLIENT_PROJECT_COLUMNS` serves the client portal and does not
//! name `internal_note`, `manager_user_id`, `department_id`, `created_by` or
//! `version` at all. Combined with the separate `ClientProjectRow` struct, an
//! internal field is not merely omitted from the response — it is never read out of
//! PostgreSQL.

use sqlx::{PgPool, Postgres, Transaction};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use super::visibility::{
    ScopeFilter, CLIENT_UID_BIND, PROJECT_SCOPE_PREDICATE, PROJECT_VISIBLE_TO_CLIENT,
};
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, PageRequest, SortDirection};

/// Sortable fields. Only timestamp columns are offered because the keyset cursor
/// is `(timestamp, id)`; a `name` sort would need a different cursor shape, and
/// pairing one with the other silently skips or repeats rows at page boundaries.
pub const SORTS: &[(&str, &str)] = &[
    ("created_at", "p.created_at"),
    ("updated_at", "p.updated_at"),
];
pub const DEFAULT_SORT: &str = "p.created_at";

/// The bind-order contract from `visibility.rs`, enforced at compile time rather
/// than trusted. Every client-facing query below binds the principal's user id
/// first and starts its own parameters at `$2`; if the fragment ever moved to a
/// different placeholder, this build would stop.
const _: () = assert!(CLIENT_UID_BIND == 1);

/// Bounded so a project with a pathological number of members cannot return an
/// unbounded document (TH-33).
const MAX_ASSOCIATION_ROWS: i64 = 500;

const PROJECT_COLUMNS: &str = "p.id, p.code, p.name, p.description, p.status, \
     p.manager_user_id, p.department_id, p.start_date, p.target_date, p.internal_note, \
     p.version, p.created_by, p.created_at, p.updated_at, p.archived_at, p.completed_at";

/// The external projection. Deliberately shorter, and deliberately a different
/// constant rather than a filtered version of the one above.
const CLIENT_PROJECT_COLUMNS: &str = "p.id, p.code, p.name, p.description, p.status, \
     p.start_date, p.target_date, p.completed_at, p.created_at, p.updated_at";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectRow {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub manager_user_id: Uuid,
    pub department_id: Option<Uuid>,
    pub start_date: Option<Date>,
    pub target_date: Option<Date>,
    pub internal_note: String,
    pub version: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
}

/// The row an external principal's query produces. It has no field to put an
/// internal column in, so a `SELECT` that accidentally named one would fail to
/// decode rather than quietly succeed.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClientProjectRow {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub start_date: Option<Date>,
    pub target_date: Option<Date>,
    pub completed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectMemberRow {
    pub user_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub role_in_project: String,
    pub added_by: Option<Uuid>,
    pub added_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectClientLinkRow {
    pub client_account_id: Uuid,
    pub client_code: String,
    pub client_name: String,
    pub client_status: String,
    pub note: String,
    pub shared_by: Uuid,
    pub shared_at: OffsetDateTime,
}

/// Everything an insert needs. A struct rather than fifteen positional arguments,
/// so a future column cannot be added in the wrong position silently.
#[derive(Debug, Clone)]
pub struct NewProject {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: &'static str,
    pub manager_user_id: Uuid,
    pub department_id: Option<Uuid>,
    pub start_date: Option<Date>,
    pub target_date: Option<Date>,
    pub internal_note: String,
    pub created_by: Uuid,
}

/// The complete post-edit state of a project.
///
/// Every column is written, not just the changed ones: the caller has already
/// re-read the row `FOR UPDATE` and computed the final values, and a full write
/// removes the class of bug where a `COALESCE`-style partial update quietly keeps
/// a stale value that a CHECK constraint then rejects.
#[derive(Debug, Clone)]
pub struct ProjectUpdate {
    pub name: String,
    pub description: String,
    pub status: &'static str,
    pub manager_user_id: Uuid,
    pub department_id: Option<Uuid>,
    pub start_date: Option<Date>,
    pub target_date: Option<Date>,
    pub internal_note: String,
    pub archived_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
}

// ---------------------------------------------------------------------------
// Cursor helpers
// ---------------------------------------------------------------------------

/// The keyset cursor carries microseconds; PostgreSQL's `timestamptz` has exactly
/// microsecond resolution, so the round trip is lossless and a page boundary
/// cannot land "between" two representable instants.
pub fn cursor_instant(cursor: &Cursor) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(cursor.timestamp_micros) * 1_000).ok()
}

pub fn to_cursor(at: OffsetDateTime, id: Uuid) -> Cursor {
    Cursor {
        timestamp_micros: (at.unix_timestamp_nanos() / 1_000) as i64,
        id,
    }
}

/// Assert that an assembled SQL string is injection-free.
///
/// sqlx 0.9 refuses a non-`'static` query string unless the caller says so
/// explicitly, which is the right default. Every string that reaches this function
/// is `format!`ed from `&'static str` fragments only: the column lists above, the
/// scope or visibility predicate from `visibility.rs`, a sort column that
/// `PageRequest::resolve` chose from an allowlist, and a direction and comparator
/// selected by a `match` over an enum. **No value that came from a request is ever
/// interpolated** — request values are bound, always.
fn safe(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

/// The keyset comparison operator for a direction. A `&'static str` chosen by a
/// match — never a formatted user value.
fn keyset_comparator(direction: SortDirection) -> &'static str {
    match direction {
        SortDirection::Desc => "<",
        SortDirection::Asc => ">",
    }
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

pub async fn find(pool: &PgPool, id: Uuid) -> AppResult<Option<ProjectRow>> {
    let sql = format!("SELECT {PROJECT_COLUMNS} FROM projects p WHERE p.id = $1");
    sqlx::query_as::<_, ProjectRow>(safe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

/// Read the row under a row lock, inside the caller's transaction.
///
/// This is what makes the object-level decision honest for a mutation: the
/// department the decision is made against cannot change between the check and the
/// write (TH-43).
pub async fn find_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<ProjectRow>> {
    let sql = format!("SELECT {PROJECT_COLUMNS} FROM projects p WHERE p.id = $1 FOR UPDATE");
    sqlx::query_as::<_, ProjectRow>(safe(sql))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// Whether the actor holds a live membership of this project — the fact `ASSIGNED`
/// scope is evaluated against. Read from the database, never inferred from the
/// request.
pub async fn is_active_member(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM project_memberships
          WHERE project_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(found.is_some())
}

pub async fn is_active_member_pool(
    pool: &PgPool,
    project_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM project_memberships
          WHERE project_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;
    Ok(found.is_some())
}

/// The internal listing.
///
/// The scope predicate is part of the `WHERE` clause. There is no variant of this
/// function that returns unfiltered rows, which is what makes "fetch everything and
/// filter in Rust" unavailable rather than merely discouraged.
#[allow(clippy::too_many_arguments)]
pub async fn list(
    pool: &PgPool,
    actor_user_id: Uuid,
    filter: &ScopeFilter,
    status: Option<&str>,
    department_id: Option<Uuid>,
    request: &PageRequest,
) -> AppResult<Vec<ProjectRow>> {
    let sort = request.sort_column;
    let dir = request.direction.sql();
    let cmp = keyset_comparator(request.direction);
    let sql = format!(
        "SELECT {PROJECT_COLUMNS}
           FROM projects p
          WHERE {PROJECT_SCOPE_PREDICATE}
            AND ($10::text IS NULL OR p.status = $10)
            AND ($11::uuid IS NULL OR p.department_id = $11)
            AND ($12::timestamptz IS NULL OR ({sort}, p.id) {cmp} ($12, $13::uuid))
          ORDER BY {sort} {dir}, p.id {dir}
          LIMIT $14"
    );

    let (cursor_at, cursor_id) = match &request.cursor {
        Some(c) => (cursor_instant(c), Some(c.id)),
        None => (None, None),
    };

    sqlx::query_as::<_, ProjectRow>(safe(sql))
        .bind(actor_user_id)
        .bind(filter.global)
        .bind(filter.department_ids.as_slice())
        .bind(filter.assigned)
        .bind(filter.resource_ids.as_slice())
        .bind(filter.deny_department)
        .bind(filter.actor_department_ids.as_slice())
        .bind(filter.deny_assigned)
        .bind(filter.denied_resource_ids.as_slice())
        .bind(status)
        .bind(department_id)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

/// The client portal listing.
///
/// `$1` is the CLIENT principal's user id, as the bind-order contract in
/// `visibility.rs` requires. Every other parameter starts at `$2`.
pub async fn list_for_client(
    pool: &PgPool,
    client_user_id: Uuid,
    request: &PageRequest,
) -> AppResult<Vec<ClientProjectRow>> {
    let cmp = keyset_comparator(request.direction);
    let dir = request.direction.sql();
    let sql = format!(
        "SELECT {CLIENT_PROJECT_COLUMNS}
           FROM projects p
          WHERE {PROJECT_VISIBLE_TO_CLIENT}
            AND ($2::timestamptz IS NULL OR (p.created_at, p.id) {cmp} ($2, $3::uuid))
          ORDER BY p.created_at {dir}, p.id {dir}
          LIMIT $4"
    );

    let (cursor_at, cursor_id) = match &request.cursor {
        Some(c) => (cursor_instant(c), Some(c.id)),
        None => (None, None),
    };

    sqlx::query_as::<_, ClientProjectRow>(safe(sql))
        .bind(client_user_id)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

/// A single project, for an external principal.
///
/// A project the principal cannot see produces `None`, which the service turns
/// into `404`. There is no code path that loads the row first and decides
/// afterwards, so there is no timing or error-shape difference between "does not
/// exist" and "exists but is not yours" (TH-10).
pub async fn find_for_client(
    pool: &PgPool,
    client_user_id: Uuid,
    project_id: Uuid,
) -> AppResult<Option<ClientProjectRow>> {
    let sql = format!(
        "SELECT {CLIENT_PROJECT_COLUMNS}
           FROM projects p
          WHERE p.id = $2
            AND {PROJECT_VISIBLE_TO_CLIENT}"
    );
    sqlx::query_as::<_, ClientProjectRow>(safe(sql))
        .bind(client_user_id)
        .bind(project_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

pub async fn list_members(pool: &PgPool, project_id: Uuid) -> AppResult<Vec<ProjectMemberRow>> {
    sqlx::query_as::<_, ProjectMemberRow>(
        "SELECT pm.user_id            AS user_id,
                u.display_name        AS display_name,
                u.email               AS email,
                pm.role_in_project    AS role_in_project,
                pm.added_by           AS added_by,
                pm.added_at           AS added_at
           FROM project_memberships pm
           JOIN users u ON u.id = pm.user_id
          WHERE pm.project_id = $1 AND pm.removed_at IS NULL
          ORDER BY pm.added_at ASC, pm.user_id ASC
          LIMIT $2",
    )
    .bind(project_id)
    .bind(MAX_ASSOCIATION_ROWS)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

pub async fn list_client_links(
    pool: &PgPool,
    project_id: Uuid,
) -> AppResult<Vec<ProjectClientLinkRow>> {
    sqlx::query_as::<_, ProjectClientLinkRow>(
        "SELECT pcl.client_account_id AS client_account_id,
                ca.code              AS client_code,
                ca.name              AS client_name,
                ca.status            AS client_status,
                pcl.note             AS note,
                pcl.shared_by        AS shared_by,
                pcl.shared_at        AS shared_at
           FROM project_client_links pcl
           JOIN client_accounts ca ON ca.id = pcl.client_account_id
          WHERE pcl.project_id = $1 AND pcl.revoked_at IS NULL
          ORDER BY pcl.shared_at DESC, pcl.client_account_id DESC
          LIMIT $2",
    )
    .bind(project_id)
    .bind(MAX_ASSOCIATION_ROWS)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// The principal type of a user, so the service can refuse an external principal
/// with a legible error instead of letting `rb_require_internal_user` fire and
/// surface as an opaque invariant violation.
pub async fn user_principal_type(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> AppResult<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT principal_type FROM users WHERE id = $1 AND status = 'ACTIVE'")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::from)?;
    Ok(row.map(|(t,)| t))
}

pub async fn client_account_status(
    tx: &mut Transaction<'_, Postgres>,
    client_account_id: Uuid,
) -> AppResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT status FROM client_accounts WHERE id = $1")
        .bind(client_account_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(row.map(|(s,)| s))
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

pub async fn insert(tx: &mut Transaction<'_, Postgres>, new: &NewProject) -> AppResult<ProjectRow> {
    // Aliased `p` so the shared `PROJECT_COLUMNS` list, which qualifies every
    // column, is usable in `RETURNING` as well as in `SELECT`.
    let sql = format!(
        "INSERT INTO projects AS p
             (id, code, name, description, status, manager_user_id, department_id,
              start_date, target_date, internal_note, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         RETURNING {PROJECT_COLUMNS}"
    );
    sqlx::query_as::<_, ProjectRow>(safe(sql))
        .bind(new.id)
        .bind(&new.code)
        .bind(&new.name)
        .bind(&new.description)
        .bind(new.status)
        .bind(new.manager_user_id)
        .bind(new.department_id)
        .bind(new.start_date)
        .bind(new.target_date)
        .bind(&new.internal_note)
        .bind(new.created_by)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// The optimistic-concurrency write.
///
/// `WHERE id = $1 AND version = $2` with `version = version + 1`. `Ok(None)` means
/// the version moved under us; the caller re-reads and returns
/// `AppError::VersionConflict`. There is no variant of this function that omits
/// the version predicate.
pub async fn update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    expected_version: i32,
    patch: &ProjectUpdate,
) -> AppResult<Option<ProjectRow>> {
    let sql = format!(
        "UPDATE projects AS p
            SET name            = $3,
                description     = $4,
                status          = $5,
                manager_user_id = $6,
                department_id   = $7,
                start_date      = $8,
                target_date     = $9,
                internal_note   = $10,
                archived_at     = $11,
                completed_at    = $12,
                version         = p.version + 1
          WHERE p.id = $1 AND p.version = $2
        RETURNING {PROJECT_COLUMNS}"
    );
    sqlx::query_as::<_, ProjectRow>(safe(sql))
        .bind(id)
        .bind(expected_version)
        .bind(&patch.name)
        .bind(&patch.description)
        .bind(patch.status)
        .bind(patch.manager_user_id)
        .bind(patch.department_id)
        .bind(patch.start_date)
        .bind(patch.target_date)
        .bind(&patch.internal_note)
        .bind(patch.archived_at)
        .bind(patch.completed_at)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

pub async fn add_member(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    user_id: Uuid,
    role_in_project: &'static str,
    added_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO project_memberships (id, project_id, user_id, role_in_project, added_by)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(user_id)
    .bind(role_in_project)
    .bind(added_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Removal is an `UPDATE`, never a `DELETE`: who was on a project and when is
/// exactly the record an incident review depends on.
pub async fn remove_member(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE project_memberships SET removed_at = now()
          WHERE project_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(project_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected() == 1)
}

pub async fn share_with_client(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    client_account_id: Uuid,
    note: &str,
    shared_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO project_client_links
             (id, project_id, client_account_id, note, shared_by)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(client_account_id)
    .bind(note)
    .bind(shared_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Unsharing sets `revoked_at`/`revoked_by`. It never deletes the row: the history
/// of what was once shared with whom is what a client dispute later turns on, and
/// the partial unique index already allows the pair to be re-shared afterwards.
pub async fn unshare_from_client(
    tx: &mut Transaction<'_, Postgres>,
    project_id: Uuid,
    client_account_id: Uuid,
    revoked_by: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE project_client_links
            SET revoked_at = now(), revoked_by = $3
          WHERE project_id = $1 AND client_account_id = $2 AND revoked_at IS NULL",
    )
    .bind(project_id)
    .bind(client_account_id)
    .bind(revoked_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_survive_the_round_trip_through_a_timestamp() {
        let id = Uuid::now_v7();
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("a representable instant")
            + time::Duration::microseconds(123_456);
        let cursor = to_cursor(at, id);
        assert_eq!(cursor.id, id);
        assert_eq!(cursor_instant(&cursor), Some(at));
    }

    #[test]
    fn the_keyset_comparator_matches_the_sort_direction() {
        // Pairing DESC with `>` walks the page backwards and silently repeats rows.
        assert_eq!(keyset_comparator(SortDirection::Desc), "<");
        assert_eq!(keyset_comparator(SortDirection::Asc), ">");
    }

    #[test]
    fn the_client_column_list_names_no_internal_column() {
        for column in [
            "internal_note",
            "manager_user_id",
            "department_id",
            "created_by",
            "version",
            "archived_at",
        ] {
            assert!(
                !CLIENT_PROJECT_COLUMNS.contains(column),
                "the client projection selects `{column}` out of the database"
            );
        }
        // And the internal one still does, so the two have not been merged.
        for column in ["internal_note", "manager_user_id", "version", "created_by"] {
            assert!(PROJECT_COLUMNS.contains(column));
        }
    }

    #[test]
    fn no_column_list_is_a_wildcard() {
        for list in [PROJECT_COLUMNS, CLIENT_PROJECT_COLUMNS] {
            assert!(
                !list.contains('*'),
                "`SELECT *` is how an unreviewed column leaks"
            );
        }
    }

    #[test]
    fn only_timestamp_columns_are_sortable() {
        // A non-timestamp sort would be incompatible with the `(timestamp, id)`
        // keyset cursor and would corrupt pagination at page boundaries.
        for (public, column) in SORTS {
            assert!(
                public.ends_with("_at") && column.ends_with("_at"),
                "`{public}` is not a timestamp column"
            );
        }
        assert!(SORTS.iter().any(|(_, c)| *c == DEFAULT_SORT));
    }
}
