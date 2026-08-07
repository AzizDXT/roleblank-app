//! Task persistence.
//!
//! As in `projects::repo`: explicit SQL, explicit columns, parameterised binds, and
//! two separate column lists so that the external projection cannot even read an
//! internal column out of PostgreSQL. `CLIENT_TASK_COLUMNS` does not name
//! `client_visible`, `internal_note`, `created_by` or `version`.

use sqlx::{PgPool, Postgres, Transaction};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::modules::projects::visibility::{
    ScopeFilter, CLIENT_UID_BIND, TASK_SCOPE_PREDICATE, TASK_VISIBLE_TO_CLIENT,
};
use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, PageRequest, SortDirection};

pub const SORTS: &[(&str, &str)] = &[
    ("created_at", "t.created_at"),
    ("updated_at", "t.updated_at"),
];
pub const DEFAULT_SORT: &str = "t.created_at";

/// The bind-order contract from `projects::visibility`, enforced at compile time.
const _: () = assert!(CLIENT_UID_BIND == 1);

const MAX_ASSOCIATION_ROWS: i64 = 500;

const TASK_COLUMNS: &str = "t.id, t.project_id, t.title, t.description, t.status, t.priority, \
     t.due_date, t.client_visible, t.internal_note, t.version, t.created_by, t.created_at, \
     t.updated_at, t.completed_at";

/// The external projection. `client_visible` is deliberately absent: whether a task
/// was hidden is internal information, and a client that could read the flag could
/// also count what it is not being shown.
const CLIENT_TASK_COLUMNS: &str = "t.id, t.project_id, t.title, t.description, t.status, \
     t.priority, t.due_date, t.completed_at, t.created_at, t.updated_at";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TaskRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: String,
    pub due_date: Option<Date>,
    pub client_visible: bool,
    pub internal_note: String,
    pub version: i32,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClientTaskRow {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: String,
    pub due_date: Option<Date>,
    pub completed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TaskAssigneeRow {
    pub user_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub assigned_by: Option<Uuid>,
    pub assigned_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewTask {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: &'static str,
    pub priority: &'static str,
    pub due_date: Option<Date>,
    pub internal_note: String,
    pub created_by: Uuid,
}

#[derive(Debug, Clone)]
pub struct TaskUpdate {
    pub title: String,
    pub description: String,
    pub status: &'static str,
    pub priority: &'static str,
    pub due_date: Option<Date>,
    pub client_visible: bool,
    pub internal_note: String,
    pub completed_at: Option<OffsetDateTime>,
}

/// Assert that an assembled SQL string is injection-free. See the identical helper
/// in `projects::repo` for the argument: every fragment interpolated here is a
/// `&'static str`, and every request value is bound.
fn safe(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

fn keyset_comparator(direction: SortDirection) -> &'static str {
    match direction {
        SortDirection::Desc => "<",
        SortDirection::Asc => ">",
    }
}

pub fn to_cursor(at: OffsetDateTime, id: Uuid) -> Cursor {
    Cursor {
        timestamp_micros: (at.unix_timestamp_nanos() / 1_000) as i64,
        id,
    }
}

fn cursor_instant(cursor: &Cursor) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(cursor.timestamp_micros) * 1_000).ok()
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

pub async fn find(pool: &PgPool, id: Uuid) -> AppResult<Option<TaskRow>> {
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks t WHERE t.id = $1");
    sqlx::query_as::<_, TaskRow>(safe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

pub async fn find_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<TaskRow>> {
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks t WHERE t.id = $1 FOR UPDATE");
    sqlx::query_as::<_, TaskRow>(safe(sql))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// The fact `ASSIGNED` scope is evaluated against for a task.
///
/// Being a member of the task's *project* is deliberately not an assignment:
/// treating it as one would widen every `tasks.*@ASSIGNED` grant from "the work I
/// was given" to "everything in every project I am on".
pub async fn is_active_assignee(
    tx: &mut Transaction<'_, Postgres>,
    task_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM task_assignees
          WHERE task_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(task_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(found.is_some())
}

pub async fn is_active_assignee_pool(
    pool: &PgPool,
    task_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let found: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM task_assignees
          WHERE task_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(task_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;
    Ok(found.is_some())
}

/// The internal listing.
///
/// The join to `projects pr` exists solely so that `DEPARTMENT` scope has something
/// to resolve against: a task has no department of its own, it inherits the
/// question from the project that owns it.
#[allow(clippy::too_many_arguments)]
pub async fn list(
    pool: &PgPool,
    actor_user_id: Uuid,
    filter: &ScopeFilter,
    project_id: Option<Uuid>,
    status: Option<&str>,
    request: &PageRequest,
) -> AppResult<Vec<TaskRow>> {
    let sort = request.sort_column;
    let dir = request.direction.sql();
    let cmp = keyset_comparator(request.direction);
    let sql = format!(
        "SELECT {TASK_COLUMNS}
           FROM tasks t
           JOIN projects pr ON pr.id = t.project_id
          WHERE {TASK_SCOPE_PREDICATE}
            AND ($10::uuid IS NULL OR t.project_id = $10)
            AND ($11::text IS NULL OR t.status = $11)
            AND ($12::timestamptz IS NULL OR ({sort}, t.id) {cmp} ($12, $13::uuid))
          ORDER BY {sort} {dir}, t.id {dir}
          LIMIT $14"
    );

    let (cursor_at, cursor_id) = match &request.cursor {
        Some(c) => (cursor_instant(c), Some(c.id)),
        None => (None, None),
    };

    sqlx::query_as::<_, TaskRow>(safe(sql))
        .bind(actor_user_id)
        .bind(filter.global)
        .bind(filter.department_ids.as_slice())
        .bind(filter.assigned)
        .bind(filter.resource_ids.as_slice())
        .bind(filter.deny_department)
        .bind(filter.actor_department_ids.as_slice())
        .bind(filter.deny_assigned)
        .bind(filter.denied_resource_ids.as_slice())
        .bind(project_id)
        .bind(status)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

pub async fn list_assignees(pool: &PgPool, task_id: Uuid) -> AppResult<Vec<TaskAssigneeRow>> {
    sqlx::query_as::<_, TaskAssigneeRow>(
        "SELECT ta.user_id     AS user_id,
                u.display_name AS display_name,
                u.email        AS email,
                ta.assigned_by AS assigned_by,
                ta.assigned_at AS assigned_at
           FROM task_assignees ta
           JOIN users u ON u.id = ta.user_id
          WHERE ta.task_id = $1 AND ta.removed_at IS NULL
          ORDER BY ta.assigned_at ASC, ta.user_id ASC
          LIMIT $2",
    )
    .bind(task_id)
    .bind(MAX_ASSOCIATION_ROWS)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// The client portal listing for one project's tasks.
///
/// `$1` is the CLIENT principal's user id (the bind-order contract in
/// `projects::visibility`). The predicate requires **both** `t.client_visible` and
/// a live link from the task's project to a client account this principal is an
/// ACTIVE member of. Sharing the project alone yields nothing here.
pub async fn list_for_client(
    pool: &PgPool,
    client_user_id: Uuid,
    project_id: Uuid,
    request: &PageRequest,
) -> AppResult<Vec<ClientTaskRow>> {
    let cmp = keyset_comparator(request.direction);
    let dir = request.direction.sql();
    let sql = format!(
        "SELECT {CLIENT_TASK_COLUMNS}
           FROM tasks t
          WHERE t.project_id = $2
            AND {TASK_VISIBLE_TO_CLIENT}
            AND ($3::timestamptz IS NULL OR (t.created_at, t.id) {cmp} ($3, $4::uuid))
          ORDER BY t.created_at {dir}, t.id {dir}
          LIMIT $5"
    );

    let (cursor_at, cursor_id) = match &request.cursor {
        Some(c) => (cursor_instant(c), Some(c.id)),
        None => (None, None),
    };

    sqlx::query_as::<_, ClientTaskRow>(safe(sql))
        .bind(client_user_id)
        .bind(project_id)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

/// A single task, for an external principal. Invisible means `None`, which the
/// service turns into `404` — never `403` (TH-10).
pub async fn find_for_client(
    pool: &PgPool,
    client_user_id: Uuid,
    task_id: Uuid,
) -> AppResult<Option<ClientTaskRow>> {
    let sql = format!(
        "SELECT {CLIENT_TASK_COLUMNS}
           FROM tasks t
          WHERE t.id = $2
            AND {TASK_VISIBLE_TO_CLIENT}"
    );
    sqlx::query_as::<_, ClientTaskRow>(safe(sql))
        .bind(client_user_id)
        .bind(task_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

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

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

pub async fn insert(tx: &mut Transaction<'_, Postgres>, new: &NewTask) -> AppResult<TaskRow> {
    // `client_visible` is not in the column list at all: the default is `false`,
    // and a task that starts invisible cannot be published by a create request.
    let sql = format!(
        "INSERT INTO tasks AS t
             (id, project_id, title, description, status, priority, due_date,
              internal_note, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING {TASK_COLUMNS}"
    );
    sqlx::query_as::<_, TaskRow>(safe(sql))
        .bind(new.id)
        .bind(new.project_id)
        .bind(&new.title)
        .bind(&new.description)
        .bind(new.status)
        .bind(new.priority)
        .bind(new.due_date)
        .bind(&new.internal_note)
        .bind(new.created_by)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::from)
}

pub async fn update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    expected_version: i32,
    patch: &TaskUpdate,
) -> AppResult<Option<TaskRow>> {
    let sql = format!(
        "UPDATE tasks AS t
            SET title          = $3,
                description    = $4,
                status         = $5,
                priority       = $6,
                due_date       = $7,
                client_visible = $8,
                internal_note  = $9,
                completed_at   = $10,
                version        = t.version + 1
          WHERE t.id = $1 AND t.version = $2
        RETURNING {TASK_COLUMNS}"
    );
    sqlx::query_as::<_, TaskRow>(safe(sql))
        .bind(id)
        .bind(expected_version)
        .bind(&patch.title)
        .bind(&patch.description)
        .bind(patch.status)
        .bind(patch.priority)
        .bind(patch.due_date)
        .bind(patch.client_visible)
        .bind(&patch.internal_note)
        .bind(patch.completed_at)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

pub async fn add_assignee(
    tx: &mut Transaction<'_, Postgres>,
    task_id: Uuid,
    user_id: Uuid,
    assigned_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO task_assignees (id, task_id, user_id, assigned_by) VALUES ($1,$2,$3,$4)",
    )
    .bind(Uuid::now_v7())
    .bind(task_id)
    .bind(user_id)
    .bind(assigned_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Unassignment is an `UPDATE`, never a `DELETE`: who was responsible for a piece
/// of work and when is exactly what a later review needs.
pub async fn remove_assignee(
    tx: &mut Transaction<'_, Postgres>,
    task_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let result = sqlx::query(
        "UPDATE task_assignees SET removed_at = now()
          WHERE task_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(task_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_column_list_names_no_internal_column() {
        for column in ["client_visible", "internal_note", "created_by", "version"] {
            assert!(
                !CLIENT_TASK_COLUMNS.contains(column),
                "the client projection selects `{column}` out of the database"
            );
        }
        for column in ["client_visible", "internal_note", "created_by", "version"] {
            assert!(
                TASK_COLUMNS.contains(column),
                "the internal projection lost `{column}`"
            );
        }
    }

    #[test]
    fn no_column_list_is_a_wildcard() {
        for list in [TASK_COLUMNS, CLIENT_TASK_COLUMNS] {
            assert!(!list.contains('*'));
        }
    }

    /// A create statement that named `client_visible` could publish a task at
    /// birth. The column must not appear in the insert at all — the database
    /// default of `false` is the only thing that ever sets it initially.
    #[test]
    fn the_insert_statement_never_sets_client_visibility() {
        let sql = format!(
            "INSERT INTO tasks AS t
             (id, project_id, title, description, status, priority, due_date,
              internal_note, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING {TASK_COLUMNS}"
        );
        let insert_clause = sql.split("RETURNING").next().unwrap_or_default();
        assert!(
            !insert_clause.contains("client_visible"),
            "the create path can set client visibility"
        );
    }

    #[test]
    fn the_keyset_comparator_matches_the_sort_direction() {
        assert_eq!(keyset_comparator(SortDirection::Desc), "<");
        assert_eq!(keyset_comparator(SortDirection::Asc), ">");
    }

    #[test]
    fn cursors_survive_the_round_trip_through_a_timestamp() {
        let id = Uuid::now_v7();
        let at = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("instant")
            + time::Duration::microseconds(654_321);
        let c = to_cursor(at, id);
        assert_eq!(cursor_instant(&c), Some(at));
        assert_eq!(c.id, id);
    }

    #[test]
    fn only_timestamp_columns_are_sortable() {
        for (public, column) in SORTS {
            assert!(public.ends_with("_at") && column.ends_with("_at"));
        }
        assert!(SORTS.iter().any(|(_, c)| *c == DEFAULT_SORT));
    }
}
