//! Loading the authenticated principal from a bearer token.
//!
//! This runs on **every** authenticated request and is the hottest path in the
//! system. It is also where several security properties are enforced at once, so
//! the queries are written out explicitly rather than composed from helpers.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::modules::authorization::domain::{
    ActorContext, Grant, PrincipalType, ResourceType, Scope, ScopeType,
};
use crate::platform::crypto::tokens;
use crate::platform::errors::AppError;

/// Session facts the request needs after authentication.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub principal_type: PrincipalType,
    pub is_root: bool,
    pub pending_mfa: bool,
    pub mfa_verified_at: Option<OffsetDateTime>,
    pub auth_level: String,
    pub security_version: i32,
    pub mfa_required: bool,
    pub mfa_enrolled: bool,
    pub display_name: String,
    pub email: String,
}

/// An authenticated request context: who, and what they may do.
#[derive(Debug, Clone)]
pub struct Principal {
    pub session: SessionInfo,
    pub actor: ActorContext,
}

impl Principal {
    pub fn user_id(&self) -> Uuid {
        self.session.user_id
    }
    pub fn is_root(&self) -> bool {
        self.session.is_root
    }
    pub fn is_external(&self) -> bool {
        self.session.principal_type.is_external()
    }

    /// Whether the session satisfies the step-up window right now.
    ///
    /// Computed per request from `mfa_verified_at`, never cached on the session
    /// row — a cached boolean would keep saying "recently verified" after the
    /// window closed.
    pub fn has_recent_step_up(&self, window: std::time::Duration) -> bool {
        match self.session.mfa_verified_at {
            None => false,
            Some(at) => {
                let elapsed = OffsetDateTime::now_utc() - at;
                elapsed.is_positive()
                    && elapsed <= time::Duration::try_from(window).unwrap_or(time::Duration::ZERO)
            }
        }
    }
}

/// Resolve a bearer token to a principal.
///
/// Returns `AuthenticationFailed` — the single undifferentiated failure — for
/// every rejection reason: malformed token, unknown token, expired access,
/// exceeded idle or absolute lifetime, revoked session, and non-ACTIVE user.
/// Distinguishing any of these is an oracle (TH-23).
pub async fn authenticate(pool: &PgPool, bearer: &str) -> Result<Principal, AppError> {
    // Shape check before touching the database. A flood of 100 KB garbage tokens
    // would otherwise each cost an indexed lookup.
    if !tokens::is_well_formed(bearer, tokens::ACCESS_TOKEN_PREFIX) {
        return Err(AppError::AuthenticationFailed);
    }

    let token_hash = tokens::hash_token(bearer);

    // One query establishes: the session exists, is unrevoked, is inside all three
    // lifetimes, belongs to an ACTIVE user, and whether that user is the owner.
    //
    // The user-status join is what makes suspension effective immediately, with no
    // background job and no fan-out UPDATE that could fail independently (ADR-005).
    let row: Option<SessionRow> = sqlx::query_as::<_, SessionRow>(
        r#"
        SELECT  s.id                AS session_id,
                s.user_id           AS user_id,
                s.pending_mfa       AS pending_mfa,
                s.mfa_verified_at   AS mfa_verified_at,
                s.auth_level        AS auth_level,
                u.principal_type    AS principal_type,
                u.security_version  AS security_version,
                u.mfa_required      AS mfa_required,
                u.mfa_enrolled      AS mfa_enrolled,
                u.display_name      AS display_name,
                u.email             AS email,
                (o.root_user_id IS NOT NULL) AS is_root
          FROM sessions s
          JOIN users u  ON u.id = s.user_id
          LEFT JOIN system_ownership o ON o.root_user_id = s.user_id
         WHERE s.access_token_hash   = $1
           AND s.revoked_at          IS NULL
           AND s.access_expires_at   > now()
           AND s.idle_expires_at     > now()
           AND s.absolute_expires_at > now()
           AND u.status              = 'ACTIVE'
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;

    let Some(row) = row else {
        return Err(AppError::AuthenticationFailed);
    };

    let principal_type = PrincipalType::parse(&row.principal_type)
        .ok_or_else(|| AppError::Internal("user has an unrecognised principal_type".into()))?;

    // Touch last activity. Errors here are logged, not propagated: failing an
    // otherwise valid request because a bookkeeping write failed would be a
    // self-inflicted outage.
    if let Err(e) = sqlx::query(
        "UPDATE sessions SET last_activity_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(row.session_id)
    .execute(pool)
    .await
    {
        tracing::warn!(error.kind = ?std::mem::discriminant(&e), "failed to update session activity");
    }

    let session = SessionInfo {
        session_id: row.session_id,
        user_id: row.user_id,
        principal_type,
        is_root: row.is_root,
        pending_mfa: row.pending_mfa,
        mfa_verified_at: row.mfa_verified_at,
        auth_level: row.auth_level,
        security_version: row.security_version,
        mfa_required: row.mfa_required,
        mfa_enrolled: row.mfa_enrolled,
        display_name: row.display_name,
        email: row.email,
    };

    let actor = load_actor(pool, row.user_id, principal_type, row.is_root).await?;
    Ok(Principal { session, actor })
}

/// Load everything the evaluator needs about an actor.
///
/// Read fresh on every request. There is no cache: stale authority is a security
/// bug, and the alternative is two indexed queries (ADR-003, §11 of
/// `docs/backend/04-authorization.md`).
pub async fn load_actor(
    pool: &PgPool,
    user_id: Uuid,
    principal_type: PrincipalType,
    is_root: bool,
) -> Result<ActorContext, AppError> {
    // Grants: role-derived allows unioned with per-user overrides. One round trip.
    let grant_rows: Vec<GrantRow> = sqlx::query_as::<_, GrantRow>(
        r#"
        SELECT rp.permission_code AS permission_code,
               rp.scope_type      AS scope_type,
               'ALLOW'            AS effect,
               NULL::text         AS resource_type,
               NULL::uuid         AS resource_id
          FROM user_role_assignments ura
          JOIN role_permissions      rp ON rp.role_id = ura.role_id
         WHERE ura.user_id = $1

        UNION ALL

        SELECT o.permission_code, o.scope_type, o.effect, o.resource_type, o.resource_id
          FROM user_permission_overrides o
         WHERE o.user_id = $1
           AND (o.expires_at IS NULL OR o.expires_at > now())
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;

    let mut allows = Vec::with_capacity(grant_rows.len());
    let mut denies = Vec::new();
    for r in grant_rows {
        let Some(scope_type) = ScopeType::parse(&r.scope_type) else {
            // Unparseable authorisation data must not silently become a wider
            // grant. Skipping it fails closed and is loud.
            tracing::error!(scope = %r.scope_type, "unrecognised scope_type in the database; ignoring the grant");
            continue;
        };
        let scope = match scope_type {
            ScopeType::Resource => {
                let (Some(rt), Some(rid)) = (
                    r.resource_type.as_deref().and_then(ResourceType::parse),
                    r.resource_id,
                ) else {
                    tracing::error!("RESOURCE-scoped grant is missing its object; ignoring");
                    continue;
                };
                Scope::resource(rt, rid)
            }
            other => Scope::simple(other),
        };
        let grant = Grant {
            permission_code: r.permission_code,
            scope,
        };
        match r.effect.as_str() {
            "DENY" => denies.push(grant),
            "ALLOW" => allows.push(grant),
            other => {
                tracing::error!(effect = %other, "unrecognised override effect; ignoring the grant");
            }
        }
    }

    // Department membership resolves DEPARTMENT scope. Only live memberships in
    // active departments count — leaving a department must remove authority
    // immediately, and an archived department grants nothing.
    let department_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT dm.department_id
          FROM department_memberships dm
          JOIN departments d ON d.id = dm.department_id
         WHERE dm.user_id = $1 AND dm.removed_at IS NULL AND d.status = 'ACTIVE'
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;

    // Client memberships are the root of all external visibility. PENDING,
    // SUSPENDED and REMOVED memberships deliberately grant nothing: a
    // self-registered client sees an empty world until someone activates it.
    let client_account_ids: Vec<Uuid> = if principal_type.is_external() {
        sqlx::query_scalar(
            r#"
            SELECT cm.client_account_id
              FROM client_memberships cm
              JOIN client_accounts ca ON ca.id = cm.client_account_id
             WHERE cm.user_id = $1 AND cm.status = 'ACTIVE' AND ca.status = 'ACTIVE'
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::from)?
    } else {
        Vec::new()
    };

    Ok(ActorContext {
        user_id,
        principal_type,
        is_root,
        department_ids,
        client_account_ids,
        allows,
        denies,
    })
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    session_id: Uuid,
    user_id: Uuid,
    pending_mfa: bool,
    mfa_verified_at: Option<OffsetDateTime>,
    auth_level: String,
    principal_type: String,
    security_version: i32,
    mfa_required: bool,
    mfa_enrolled: bool,
    display_name: String,
    email: String,
    is_root: bool,
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    permission_code: String,
    scope_type: String,
    effect: String,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn principal_with(mfa_verified_at: Option<OffsetDateTime>) -> Principal {
        Principal {
            session: SessionInfo {
                session_id: Uuid::now_v7(),
                user_id: Uuid::now_v7(),
                principal_type: PrincipalType::Internal,
                is_root: false,
                pending_mfa: false,
                mfa_verified_at,
                auth_level: "MFA".into(),
                security_version: 1,
                mfa_required: true,
                mfa_enrolled: true,
                display_name: "Test".into(),
                email: "t@example.com".into(),
            },
            actor: ActorContext::empty(Uuid::now_v7(), PrincipalType::Internal),
        }
    }

    #[test]
    fn step_up_requires_a_verification_inside_the_window() {
        let window = Duration::from_secs(600);
        assert!(!principal_with(None).has_recent_step_up(window));
        assert!(principal_with(Some(OffsetDateTime::now_utc())).has_recent_step_up(window));
        assert!(principal_with(Some(
            OffsetDateTime::now_utc() - time::Duration::seconds(300)
        ))
        .has_recent_step_up(window));
    }

    #[test]
    fn step_up_expires_when_the_window_closes() {
        let window = Duration::from_secs(600);
        assert!(!principal_with(Some(
            OffsetDateTime::now_utc() - time::Duration::seconds(601)
        ))
        .has_recent_step_up(window));
        assert!(
            !principal_with(Some(OffsetDateTime::now_utc() - time::Duration::hours(24)))
                .has_recent_step_up(window)
        );
    }

    /// A clock skew or a corrupted row must not produce an indefinitely valid
    /// step-up. A verification timestamp in the future is refused.
    #[test]
    fn a_future_verification_timestamp_does_not_satisfy_step_up() {
        let window = Duration::from_secs(600);
        assert!(
            !principal_with(Some(OffsetDateTime::now_utc() + time::Duration::hours(1)))
                .has_recent_step_up(window)
        );
    }

    #[test]
    fn a_zero_window_never_satisfies_step_up() {
        assert!(!principal_with(Some(OffsetDateTime::now_utc())).has_recent_step_up(Duration::ZERO));
    }
}
