//! Identity persistence. Explicit SQL, explicit columns, parameterised always.
//!
//! Two rules are load-bearing here rather than stylistic:
//!
//! * **No `SELECT *`.** Every column is named. `SELECT *` on `users` is how a
//!   column added later reaches a response struct nobody re-reviewed.
//! * **Nothing that came from a client is ever interpolated into SQL.** The only
//!   values formatted into a query string are `&'static str`s chosen from a
//!   compile-time allowlist by `PageRequest::resolve` and by `SortDirection::sql`.
//!
//! There is deliberately no `delete_user`. Accounts are archived; the runtime
//! database role holds no `DELETE` grant on `users`, so writing one would produce
//! a `42501` at runtime rather than working (ADR-004 layer 3).
//!
//! ### On `sqlx::AssertSqlSafe`
//!
//! sqlx 0.9 refuses a non-`'static` query string unless it is explicitly asserted
//! safe — a speed bump against `format!("… {user_input}")`. Four queries here build
//! their SQL with `format!`, and each is audited: the *only* interpolated values
//! are `USER_COLUMNS` / `INVITATION_COLUMNS` (module constants), the sort column
//! (`&'static str`, selected from `USER_SORTS` / `INVITATION_SORTS` by
//! `PageRequest::resolve`), the direction (`&'static str` from
//! `SortDirection::sql`) and the keyset operator (`&'static str` from
//! `keyset_operator`). Every value that originated with a caller — filters,
//! cursors, limits, search text — is a bind parameter. `sort_injection_is_refused_
//! before_any_sql_is_built` and `every_allowlisted_sort_maps_to_a_column_the_
//! cursor_can_encode` hold that property in place.

use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::platform::errors::{AppError, AppResult};
use crate::shared::pagination::{Cursor, PageRequest};

// =============================================================================
// Rows
// =============================================================================

/// The projection every user-facing query returns.
///
/// Note what is absent: there is no `password_hash` field, because the hash lives
/// in `credentials` and is never joined here. The type system, not developer
/// discipline, is what keeps it out of memory.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub email_normalized: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
    pub security_version: i32,
    pub version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub activated_at: Option<OffsetDateTime>,
    pub suspended_at: Option<OffsetDateTime>,
    pub archived_at: Option<OffsetDateTime>,
}

const USER_COLUMNS: &str = "u.id, u.email, u.email_normalized, u.display_name, \
     u.principal_type, u.status, u.mfa_required, u.mfa_enrolled, u.security_version, \
     u.version, u.created_at, u.updated_at, u.activated_at, u.suspended_at, u.archived_at";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InvitationRow {
    pub id: Uuid,
    pub email: String,
    pub email_normalized: String,
    pub principal_type: String,
    pub display_name: String,
    pub client_account_id: Option<Uuid>,
    pub department_id: Option<Uuid>,
    pub status: String,
    pub invited_by: Uuid,
    pub accepted_user_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

const INVITATION_COLUMNS: &str = "i.id, i.email, i.email_normalized, i.principal_type, \
     i.display_name, i.client_account_id, i.department_id, i.status, i.invited_by, \
     i.accepted_user_id, i.expires_at, i.accepted_at, i.created_at";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: Uuid,
    pub code: String,
    pub is_system: bool,
    pub allowed_principal_type: String,
}

/// The facts needed to rebuild an absent actor's authorisation context — used when
/// re-validating an invitation against the inviter at acceptance time.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActorBasics {
    pub principal_type: String,
    pub status: String,
    pub is_root: bool,
}

/// Everything needed to create a user. A struct rather than eleven positional
/// arguments, so that transposing `mfa_required` and `mfa_enrolled` is impossible.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub id: Uuid,
    pub email: String,
    pub email_normalized: String,
    pub display_name: String,
    pub principal_type: String,
    pub status: String,
    pub mfa_required: bool,
    pub activated: bool,
}

#[derive(Debug, Clone)]
pub struct NewInvitation {
    pub id: Uuid,
    pub email: String,
    pub email_normalized: String,
    pub display_name: String,
    pub principal_type: String,
    pub client_account_id: Option<Uuid>,
    pub department_id: Option<Uuid>,
    pub token_hash: Vec<u8>,
    pub invited_by: Uuid,
    pub expires_at: OffsetDateTime,
}

// =============================================================================
// Pagination helpers
// =============================================================================

/// Convert a cursor's microsecond timestamp back into a database value.
///
/// A cursor is client-supplied, so a value outside the representable range is an
/// invalid cursor rather than a panic.
pub fn cursor_timestamp(cursor: &Cursor) -> AppResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(cursor.timestamp_micros) * 1_000)
        .map_err(|_| AppError::field("cursor", "INVALID", "Malformed pagination cursor."))
}

pub fn to_cursor(timestamp: OffsetDateTime, id: Uuid) -> Cursor {
    Cursor {
        timestamp_micros: (timestamp.unix_timestamp_nanos() / 1_000) as i64,
        id,
    }
}

/// The only sortable fields on the user listing.
///
/// Both are timestamps, and that is a constraint of the cursor rather than an
/// oversight: a keyset cursor is `(sort key, id)`, and `Cursor` encodes a
/// timestamp. Offering `sort=display_name` would mint cursors whose sort key is
/// not the column being ordered by, which silently skips and repeats rows at page
/// boundaries. Offset pagination — the usual escape hatch — is refused outright
/// (TH-33).
pub const USER_SORTS: &[(&str, &str)] = &[
    ("created_at", "u.created_at"),
    ("updated_at", "u.updated_at"),
];
pub const USER_DEFAULT_SORT: &str = "u.created_at";

pub const INVITATION_SORTS: &[(&str, &str)] = &[
    ("created_at", "i.created_at"),
    ("expires_at", "i.expires_at"),
];
pub const INVITATION_DEFAULT_SORT: &str = "i.created_at";

/// Pick the value that matches the column actually being sorted on, so the cursor
/// and the `ORDER BY` can never disagree.
pub fn user_sort_value(row: &UserRow, sort_column: &str) -> OffsetDateTime {
    match sort_column {
        "u.updated_at" => row.updated_at,
        _ => row.created_at,
    }
}

pub fn invitation_sort_value(row: &InvitationRow, sort_column: &str) -> OffsetDateTime {
    match sort_column {
        "i.expires_at" => row.expires_at,
        _ => row.created_at,
    }
}

/// The keyset comparison operator implied by the sort direction.
fn keyset_operator(request: &PageRequest) -> &'static str {
    match request.direction {
        crate::shared::pagination::SortDirection::Desc => "<",
        crate::shared::pagination::SortDirection::Asc => ">",
    }
}

// =============================================================================
// Users — reads
// =============================================================================

/// Filters applied to the user listing.
///
/// `only_ids` and `department_ids` are **not** user input: they are derived from
/// the actor's own effective scopes by the service. A `SELF`-scoped actor gets
/// `only_ids = [their own id]`, which is what turns a narrow grant into a filtered
/// query instead of a refusal (`docs/backend/04-authorization.md` §5).
#[derive(Debug, Default, Clone)]
pub struct UserListFilters {
    pub principal_type: Option<String>,
    pub status: Option<String>,
    /// Already lowercased by the service; matched with `strpos`, not `LIKE`, so
    /// there is no wildcard metacharacter to escape.
    pub search: Option<String>,
    pub only_ids: Option<Vec<Uuid>>,
    pub department_ids: Option<Vec<Uuid>>,
}

pub async fn list_users(
    pool: &PgPool,
    request: &PageRequest,
    filters: &UserListFilters,
) -> AppResult<Vec<UserRow>> {
    let sort = request.sort_column;
    let direction = request.direction.sql();
    let operator = keyset_operator(request);

    // `sort`, `direction` and `operator` are all `&'static str` values selected
    // from compile-time allowlists. No caller-supplied text reaches this string.
    let sql = format!(
        r#"
        SELECT {USER_COLUMNS}
          FROM users u
         WHERE ($1::text IS NULL OR u.principal_type = $1)
           AND ($2::text IS NULL OR u.status = $2)
           AND ($3::text IS NULL
                OR strpos(u.email_normalized, $3) > 0
                OR strpos(lower(u.display_name), $3) > 0)
           AND ($4::uuid[] IS NULL OR u.id = ANY($4))
           AND ($5::uuid[] IS NULL
                OR EXISTS (SELECT 1
                             FROM department_memberships dm
                            WHERE dm.user_id = u.id
                              AND dm.removed_at IS NULL
                              AND dm.department_id = ANY($5)))
           AND ($6::timestamptz IS NULL OR ({sort}, u.id) {operator} ($6, $7))
         ORDER BY {sort} {direction}, u.id {direction}
         LIMIT $8
        "#
    );

    let (cursor_at, cursor_id) = match &request.cursor {
        None => (None, None),
        Some(c) => (Some(cursor_timestamp(c)?), Some(c.id)),
    };

    sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(sql))
        .bind(filters.principal_type.as_deref())
        .bind(filters.status.as_deref())
        .bind(filters.search.as_deref())
        .bind(filters.only_ids.as_deref())
        .bind(filters.department_ids.as_deref())
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

pub async fn find_user(pool: &PgPool, id: Uuid) -> AppResult<Option<UserRow>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users u WHERE u.id = $1");
    sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

/// Read the subject inside the caller's transaction and hold the row lock.
///
/// Every mutation goes through this rather than through `find_user`: the
/// authorisation decision, the ROOT check and the version check must all be made
/// against a row that cannot change underneath them (TH-43).
pub async fn find_user_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<UserRow>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users u WHERE u.id = $1 FOR UPDATE");
    sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

pub async fn find_user_by_email(
    tx: &mut Transaction<'_, Postgres>,
    email_normalized: &str,
) -> AppResult<Option<UserRow>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users u WHERE u.email_normalized = $1");
    sqlx::query_as::<_, UserRow>(sqlx::AssertSqlSafe(sql))
        .bind(email_normalized)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// Is this user the system owner?
///
/// Read inside the transaction rather than through `AppState::is_root_user`, so
/// that the ROOT check and the mutation it guards observe the same snapshot.
pub async fn is_root(tx: &mut Transaction<'_, Postgres>, user_id: Uuid) -> AppResult<bool> {
    let found: Option<(Uuid,)> =
        sqlx::query_as("SELECT root_user_id FROM system_ownership WHERE root_user_id = $1")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::from)?;
    Ok(found.is_some())
}

/// Remove the system owner from a candidate set.
///
/// Filtering happens in SQL, in one statement, *before* the caller acts on any of
/// the ids — which is precisely the requirement ADR-004 places on bulk operations:
/// "select all" must not be able to sweep the owner up and discover it midway
/// through a partially applied change.
pub async fn exclude_root_ids(
    tx: &mut Transaction<'_, Postgres>,
    ids: &[Uuid],
) -> AppResult<Vec<Uuid>> {
    let kept: Vec<Uuid> = sqlx::query_scalar(
        "SELECT u.id
           FROM users u
          WHERE u.id = ANY($1)
            AND NOT EXISTS (SELECT 1 FROM system_ownership o WHERE o.root_user_id = u.id)",
    )
    .bind(ids)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(kept)
}

pub async fn current_version(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<i32>> {
    sqlx::query_scalar("SELECT version FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// The facts needed to rebuild an absent principal's actor context.
pub async fn actor_basics(pool: &PgPool, user_id: Uuid) -> AppResult<Option<ActorBasics>> {
    sqlx::query_as::<_, ActorBasics>(
        r#"
        SELECT u.principal_type AS principal_type,
               u.status         AS status,
               (o.root_user_id IS NOT NULL) AS is_root
          FROM users u
          LEFT JOIN system_ownership o ON o.root_user_id = u.id
         WHERE u.id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)
}

// =============================================================================
// Users — writes
// =============================================================================

pub async fn insert_user(tx: &mut Transaction<'_, Postgres>, user: &NewUser) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO users (
            id, email, email_normalized, display_name,
            principal_type, status, mfa_required, mfa_enrolled, activated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, false,
                  CASE WHEN $8 THEN now() ELSE NULL END)
        "#,
    )
    .bind(user.id)
    .bind(&user.email)
    .bind(&user.email_normalized)
    .bind(&user.display_name)
    .bind(&user.principal_type)
    .bind(&user.status)
    .bind(user.mfa_required)
    .bind(user.activated)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

pub async fn insert_credentials(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    password_hash: &str,
) -> AppResult<()> {
    sqlx::query("INSERT INTO credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(password_hash)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;
    Ok(())
}

/// Update profile fields under optimistic concurrency.
///
/// Returns the number of rows affected. Zero means the caller's `version` was
/// stale; the service re-reads and returns `VERSION_CONFLICT` rather than
/// overwriting whatever the other writer did.
pub async fn update_profile(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    display_name: &str,
    email: &str,
    email_normalized: &str,
    expected_version: i32,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE users
           SET display_name     = $3,
               email            = $4,
               email_normalized = $5,
               version          = version + 1
         WHERE id = $1 AND version = $2
        "#,
    )
    .bind(id)
    .bind(expected_version)
    .bind(display_name)
    .bind(email)
    .bind(email_normalized)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Move an account to a new status, stamping the matching timestamp.
///
/// The `CASE` expressions keep `suspended_at` / `archived_at` / `activated_at`
/// consistent with `status` in the same statement, so there is no window in which
/// a row says `SUSPENDED` with no suspension time.
pub async fn set_status(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    status: &str,
    expected_version: i32,
) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        UPDATE users
           SET status       = $3,
               suspended_at = CASE WHEN $3 = 'SUSPENDED' THEN now() ELSE NULL END,
               archived_at  = CASE WHEN $3 = 'ARCHIVED'  THEN now() ELSE archived_at END,
               activated_at = CASE WHEN $3 = 'ACTIVE' AND activated_at IS NULL
                                   THEN now() ELSE activated_at END,
               version      = version + 1
         WHERE id = $1 AND version = $2
        "#,
    )
    .bind(id)
    .bind(expected_version)
    .bind(status)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Revoke every live session belonging to a user, inside the caller's transaction.
///
/// Suspension that does not end existing sessions is not suspension. Doing it in
/// the same transaction as the status change means there is no window — and no
/// background job that can fail independently — in which a suspended account still
/// holds a usable token.
pub async fn revoke_all_sessions(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    reason: &str,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE sessions
            SET revoked_at = now(), revocation_reason = $2
          WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// =============================================================================
// Roles
// =============================================================================

pub async fn find_role(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
) -> AppResult<Option<RoleRow>> {
    sqlx::query_as::<_, RoleRow>(
        "SELECT id, code, is_system, allowed_principal_type FROM roles WHERE id = $1",
    )
    .bind(role_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

pub async fn find_role_by_code(
    tx: &mut Transaction<'_, Postgres>,
    code: &str,
) -> AppResult<Option<RoleRow>> {
    sqlx::query_as::<_, RoleRow>(
        "SELECT id, code, is_system, allowed_principal_type FROM roles WHERE code = $1",
    )
    .bind(code)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

/// The `(permission_code, scope_type)` pairs a role carries.
///
/// Loaded so the delegation guard can check a role **permission by permission**.
/// Checking only "may I assign roles?" is the classic escalation hole.
pub async fn role_permissions(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
) -> AppResult<Vec<(String, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT permission_code, scope_type FROM role_permissions WHERE role_id = $1",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(rows)
}

pub async fn assign_role(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    role_id: Uuid,
    granted_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_role_assignments (id, user_id, role_id, granted_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, role_id) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(role_id)
    .bind(granted_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

// =============================================================================
// Invitations
// =============================================================================

pub async fn insert_invitation(
    tx: &mut Transaction<'_, Postgres>,
    invitation: &NewInvitation,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO invitations (
            id, email, email_normalized, principal_type, display_name,
            client_account_id, department_id, token_hash, status, invited_by, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING', $9, $10)
        "#,
    )
    .bind(invitation.id)
    .bind(&invitation.email)
    .bind(&invitation.email_normalized)
    .bind(&invitation.principal_type)
    .bind(&invitation.display_name)
    .bind(invitation.client_account_id)
    .bind(invitation.department_id)
    .bind(&invitation.token_hash)
    .bind(invitation.invited_by)
    .bind(invitation.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

pub async fn insert_invitation_role(
    tx: &mut Transaction<'_, Postgres>,
    invitation_id: Uuid,
    role_id: Uuid,
    scope_type: &str,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO invitation_roles (invitation_id, role_id, scope_type)
         VALUES ($1, $2, $3)
         ON CONFLICT (invitation_id, role_id) DO NOTHING",
    )
    .bind(invitation_id)
    .bind(role_id)
    .bind(scope_type)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// Look an invitation up by the SHA-256 digest of the presented token and hold the
/// row lock.
///
/// The lookup is by digest — the plaintext token is never stored — and `FOR UPDATE`
/// is what makes two simultaneous acceptances deterministic: the second one blocks
/// here and observes `status = 'ACCEPTED'` once the first commits.
pub async fn find_invitation_by_token_for_update(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8],
) -> AppResult<Option<InvitationRow>> {
    let sql = format!(
        "SELECT {INVITATION_COLUMNS} FROM invitations i WHERE i.token_hash = $1 FOR UPDATE"
    );
    sqlx::query_as::<_, InvitationRow>(sqlx::AssertSqlSafe(sql))
        .bind(token_hash)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// A non-locking lookup by token digest.
///
/// Used only to obtain the address and name needed to validate and hash a password
/// *before* a transaction is opened — Argon2id costs tens of milliseconds and must
/// not be run while holding a pooled connection and a row lock. Nothing is decided
/// on this read; every check is repeated under `FOR UPDATE`.
pub async fn find_invitation_by_token(
    pool: &PgPool,
    token_hash: &[u8],
) -> AppResult<Option<InvitationRow>> {
    let sql = format!("SELECT {INVITATION_COLUMNS} FROM invitations i WHERE i.token_hash = $1");
    sqlx::query_as::<_, InvitationRow>(sqlx::AssertSqlSafe(sql))
        .bind(token_hash)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

pub async fn find_invitation_for_update(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<Option<InvitationRow>> {
    let sql = format!("SELECT {INVITATION_COLUMNS} FROM invitations i WHERE i.id = $1 FOR UPDATE");
    sqlx::query_as::<_, InvitationRow>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::from)
}

pub async fn list_invitations(
    pool: &PgPool,
    request: &PageRequest,
    status: Option<&str>,
) -> AppResult<Vec<InvitationRow>> {
    let sort = request.sort_column;
    let direction = request.direction.sql();
    let operator = keyset_operator(request);

    let sql = format!(
        r#"
        SELECT {INVITATION_COLUMNS}
          FROM invitations i
         WHERE ($1::text IS NULL OR i.status = $1)
           AND ($2::timestamptz IS NULL OR ({sort}, i.id) {operator} ($2, $3))
         ORDER BY {sort} {direction}, i.id {direction}
         LIMIT $4
        "#
    );

    let (cursor_at, cursor_id) = match &request.cursor {
        None => (None, None),
        Some(c) => (Some(cursor_timestamp(c)?), Some(c.id)),
    };

    sqlx::query_as::<_, InvitationRow>(sqlx::AssertSqlSafe(sql))
        .bind(status)
        .bind(cursor_at)
        .bind(cursor_id)
        .bind(request.fetch_limit())
        .fetch_all(pool)
        .await
        .map_err(AppError::from)
}

pub async fn invitation_role_ids(
    tx: &mut Transaction<'_, Postgres>,
    invitation_id: Uuid,
) -> AppResult<Vec<Uuid>> {
    sqlx::query_scalar("SELECT role_id FROM invitation_roles WHERE invitation_id = $1")
        .bind(invitation_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::from)
}

/// Role ids for a whole page of invitations, in one round trip rather than one per
/// row. A listing must not become N+1 queries simply because it renders a
/// relationship.
pub async fn invitation_roles_for(
    pool: &PgPool,
    invitation_ids: &[Uuid],
) -> AppResult<Vec<(Uuid, Uuid)>> {
    if invitation_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT invitation_id, role_id FROM invitation_roles WHERE invitation_id = ANY($1)",
    )
    .bind(invitation_ids)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

/// Consume an invitation. **Single-use, gated on rows affected.**
///
/// `WHERE id = $1 AND status = 'PENDING'` is the whole mechanism: of two concurrent
/// acceptances exactly one sees `rows_affected == 1`, and the loser's entire
/// transaction — including the user row it had already inserted — rolls back.
pub async fn mark_invitation_accepted(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    accepted_user_id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE invitations
            SET status = 'ACCEPTED', accepted_user_id = $2, accepted_at = now()
          WHERE id = $1 AND status = 'PENDING'",
    )
    .bind(id)
    .bind(accepted_user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

pub async fn mark_invitation_revoked(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE invitations
            SET status = 'REVOKED', revoked_at = now()
          WHERE id = $1 AND status = 'PENDING'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

/// Retire an invitation whose window has closed.
///
/// Housekeeping only: expiry is already enforced by the `expires_at` comparison at
/// acceptance, so this never changes a decision — it stops an expired row from
/// occupying the `one PENDING per email` partial unique index forever.
pub async fn mark_invitation_expired(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> AppResult<u64> {
    let result = sqlx::query(
        "UPDATE invitations SET status = 'EXPIRED' WHERE id = $1 AND status = 'PENDING'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

// =============================================================================
// Client memberships
// =============================================================================

pub async fn insert_client_membership(
    tx: &mut Transaction<'_, Postgres>,
    client_account_id: Uuid,
    user_id: Uuid,
    status: &str,
    invited_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO client_memberships (
            id, client_account_id, user_id, status, invited_by, activated_at
        ) VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'ACTIVE' THEN now() ELSE NULL END)
        ON CONFLICT (client_account_id, user_id) DO NOTHING
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(client_account_id)
    .bind(user_id)
    .bind(status)
    .bind(invited_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

// =============================================================================
// Department memberships
// =============================================================================

/// Place an invitee in the department their invitation named.
///
/// The database refuses this for a non-INTERNAL principal
/// (`trg_department_memberships_internal_only`), so an external account cannot
/// enter an internal structure even if this call were reached with the wrong
/// principal type.
pub async fn insert_department_membership(
    tx: &mut Transaction<'_, Postgres>,
    department_id: Uuid,
    user_id: Uuid,
    added_by: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO department_memberships (id, department_id, user_id, role_in_department, added_by)
         VALUES ($1, $2, $3, 'MEMBER', $4)",
    )
    .bind(Uuid::now_v7())
    .bind(department_id)
    .bind(user_id)
    .bind(added_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

// =============================================================================
// Settings
// =============================================================================

/// Read a system setting.
///
/// DEVIATION, deliberate and temporary: this reaches into `system_settings`
/// directly instead of calling `modules::settings::service`, because that module
/// does not exist yet. It is a read of a single documented key with no
/// authorisation consequence of its own — the registration mode is *consulted*
/// here, never written — and it should move behind the settings service as soon as
/// that service lands.
pub async fn read_setting(pool: &PgPool, key: &str) -> AppResult<Option<serde_json::Value>> {
    sqlx::query_scalar::<_, serde_json::Value>("SELECT value FROM system_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::pagination::{PageQuery, SortDirection};

    fn request(direction: Option<&str>, sort: Option<&str>) -> PageRequest {
        PageRequest::resolve(
            &PageQuery {
                cursor: None,
                limit: None,
                sort: sort.map(str::to_string),
                direction: direction.map(str::to_string),
            },
            USER_SORTS,
            USER_DEFAULT_SORT,
            100,
        )
        .expect("valid page request")
    }

    #[test]
    fn cursors_round_trip_through_the_database_representation() {
        let now = OffsetDateTime::now_utc();
        let id = Uuid::now_v7();
        let cursor = to_cursor(now, id);
        let back = cursor_timestamp(&cursor).expect("representable");
        // Microsecond precision — the resolution PostgreSQL stores.
        assert_eq!(
            back.unix_timestamp_nanos() / 1_000,
            now.unix_timestamp_nanos() / 1_000
        );
        assert_eq!(cursor.id, id);
    }

    #[test]
    fn an_unrepresentable_cursor_is_a_validation_error_not_a_panic() {
        let cursor = Cursor {
            timestamp_micros: i64::MAX,
            id: Uuid::now_v7(),
        };
        assert!(cursor_timestamp(&cursor).is_err());
    }

    /// The keyset comparison must follow the sort direction, or the second page of
    /// an ascending listing silently repeats the first.
    #[test]
    fn the_keyset_operator_follows_the_sort_direction() {
        assert_eq!(keyset_operator(&request(Some("asc"), None)), ">");
        assert_eq!(keyset_operator(&request(Some("desc"), None)), "<");
        assert_eq!(
            keyset_operator(&request(None, None)),
            "<",
            "the default is newest-first"
        );
    }

    #[test]
    fn the_sort_value_matches_the_column_being_ordered_by() {
        let row = UserRow {
            id: Uuid::now_v7(),
            email: "a@b.com".into(),
            email_normalized: "a@b.com".into(),
            display_name: "A".into(),
            principal_type: "INTERNAL".into(),
            status: "ACTIVE".into(),
            mfa_required: false,
            mfa_enrolled: false,
            security_version: 1,
            version: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
            activated_at: None,
            suspended_at: None,
            archived_at: None,
        };
        assert_eq!(user_sort_value(&row, "u.created_at"), row.created_at);
        assert_eq!(user_sort_value(&row, "u.updated_at"), row.updated_at);
    }

    /// Sort keys are resolved from an allowlist, so an injection attempt never
    /// reaches the formatted SQL — it fails validation first.
    #[test]
    fn sort_injection_is_refused_before_any_sql_is_built() {
        for attack in [
            "created_at; DROP TABLE users--",
            "(SELECT password_hash FROM credentials)",
            "u.email_normalized",
            "*",
            "",
        ] {
            let query = PageQuery {
                cursor: None,
                limit: None,
                sort: Some(attack.to_string()),
                direction: None,
            };
            assert!(
                PageRequest::resolve(&query, USER_SORTS, USER_DEFAULT_SORT, 100).is_err(),
                "accepted sort `{attack}`"
            );
        }
    }

    #[test]
    fn every_allowlisted_sort_maps_to_a_column_the_cursor_can_encode() {
        for (public, column) in USER_SORTS {
            assert!(
                column.starts_with("u."),
                "`{public}` must be table-qualified"
            );
            assert!(
                column.ends_with("_at"),
                "`{public}` is not a timestamp; the (timestamp, id) cursor cannot encode it"
            );
        }
        for (public, column) in INVITATION_SORTS {
            assert!(
                column.starts_with("i."),
                "`{public}` must be table-qualified"
            );
            assert!(column.ends_with("_at"));
        }
    }

    #[test]
    fn direction_renders_as_a_static_keyword() {
        assert_eq!(SortDirection::Asc.sql(), "ASC");
        assert_eq!(SortDirection::Desc.sql(), "DESC");
    }
}
