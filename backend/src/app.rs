//! Application state and the authorisation helpers every service uses.
//!
//! `AppState` is a plain struct of `Arc`s — no dependency-injection container, no
//! service locator. Adding a dependency is a visible change to one struct, which
//! is exactly the reviewability the security-critical layers need.

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::modules::audit;
use crate::modules::authentication::principal::Principal;
use crate::modules::authorization::domain::{Decision, Target};
use crate::modules::authorization::{catalog, evaluator};
use crate::platform::config::Config;
use crate::platform::crypto::{aead, password};
use crate::platform::errors::{AppError, AppResult};
use crate::platform::http::rate_limit::RateLimiter;
use crate::platform::observability::metrics::Metrics;
use crate::shared::secret::Secret;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub hasher: Arc<password::Hasher>,
    pub keyring: Arc<aead::KeyRing>,
    /// HMAC key for the audit chain. Held separately from every other secret so
    /// that compromising one capability does not compromise the other (ADR-006).
    pub chain_key: Arc<Secret<Vec<u8>>>,
    pub limiter: Arc<dyn RateLimiter>,
    pub metrics: Arc<Metrics>,
}

// No manual `impl FromRef<AppState> for AppState` is needed or permitted: axum
// provides a blanket `impl<T: Clone> FromRef<T> for T`, so writing one here is a
// conflicting implementation. The extractors in `platform::http::extract` are
// generic over `S where AppState: FromRef<S>`, which the blanket impl satisfies
// when `S == AppState`.

impl AppState {
    /// Evaluate an authorisation decision without acting on it.
    ///
    /// Used where the caller needs the *reason* — to audit a denial, or to decide
    /// between filtering a list and refusing it outright.
    pub fn decide(&self, principal: &Principal, permission: &str, target: &Target) -> Decision {
        evaluator::evaluate(&principal.actor, permission, target)
    }

    /// The standard authorisation gate.
    ///
    /// On denial, the error is shaped for the principal type: an external
    /// principal gets `404` rather than `403`, because a `403` would confirm that
    /// the object exists (see `docs/backend/04-authorization.md` §10).
    ///
    /// Callers must pass a `Target::Resource` built from the **loaded** row, not
    /// from the path parameter. Authorising against an id the caller supplied is
    /// route-level authorisation wearing an object-level costume.
    pub fn require(
        &self,
        principal: &Principal,
        permission: &str,
        target: &Target,
    ) -> AppResult<()> {
        let decision = self.decide(principal, permission, target);
        if decision.is_allowed() {
            return Ok(());
        }

        self.metrics.authz_denial(decision.reason());
        tracing::info!(
            actor.id = %principal.user_id(),
            actor.type = %principal.session.principal_type,
            permission = %permission,
            reason = decision.reason(),
            "authorization denied"
        );

        // An unknown permission code arriving from a request means the caller is
        // probing the authorisation surface; it is a different signal from a
        // legitimate-but-unauthorised call and is reported as such.
        if matches!(decision, Decision::DenyUnknownPermission) {
            return Err(AppError::UnknownPermission);
        }

        Err(AppError::AuthorizationDenied.hide_from_external(principal.is_external()))
    }

    /// Require a recent second-factor verification.
    ///
    /// Enforced entirely server-side. A client may *prompt* based on the
    /// `STEP_UP_REQUIRED` response, but nothing about the requirement depends on
    /// the client behaving.
    pub fn require_step_up(&self, principal: &Principal) -> AppResult<()> {
        if principal.has_recent_step_up(self.config.sessions.step_up_window) {
            return Ok(());
        }
        Err(AppError::StepUpRequired {
            window_seconds: self.config.sessions.step_up_window.as_secs(),
        })
    }

    /// Require step-up only when the permission is flagged dangerous.
    pub fn require_step_up_for(&self, principal: &Principal, permission: &str) -> AppResult<()> {
        if catalog::is_dangerous(permission) {
            self.require_step_up(principal)?;
        }
        Ok(())
    }

    /// Refuse any operation targeting the system owner.
    ///
    /// The application half of the ROOT invariant. The database refuses the same
    /// operations independently (ADR-004), so this is the legible error rather
    /// than the only barrier.
    pub fn guard_root(&self, subject_is_root: bool) -> AppResult<()> {
        if subject_is_root {
            return Err(AppError::RootProtected);
        }
        Ok(())
    }

    /// Is this user the system owner?
    ///
    /// Read from `system_ownership` rather than from a cached flag: ownership is
    /// immutable, but a cache that is wrong once is wrong forever.
    pub async fn is_root_user(&self, user_id: Uuid) -> AppResult<bool> {
        let found: Option<(Uuid,)> =
            sqlx::query_as("SELECT root_user_id FROM system_ownership WHERE root_user_id = $1")
                .bind(user_id)
                .fetch_optional(&self.db)
                .await
                .map_err(AppError::from)?;
        Ok(found.is_some())
    }

    /// The system owner's id, if the system has been initialised.
    pub async fn root_user_id(&self) -> AppResult<Option<Uuid>> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT root_user_id FROM system_ownership WHERE id")
                .fetch_optional(&self.db)
                .await
                .map_err(AppError::from)?;
        Ok(row.map(|(id,)| id))
    }

    /// Start a transaction.
    ///
    /// Services open the transaction, re-read the subject `FOR UPDATE` where the
    /// decision depends on it, authorise, mutate, audit, and commit — all inside
    /// this boundary. That is what closes the TOCTOU window (TH-43).
    pub async fn begin(&self) -> AppResult<sqlx::Transaction<'_, sqlx::Postgres>> {
        self.db.begin().await.map_err(AppError::from)
    }

    /// Append an audit event inside an open transaction.
    pub async fn audit(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        event: audit::AuditEvent,
    ) -> AppResult<Uuid> {
        let id = audit::append(tx, &self.chain_key, event).await?;
        self.metrics.audit_written();
        Ok(id)
    }

    /// Bump a user's security version.
    ///
    /// Called on every privilege change. Nothing depends on it for correctness
    /// today — authorisation is recomputed per request — but it is the signal a
    /// client uses to notice its capability set moved, and it is the invalidation
    /// key any future cache must use.
    pub async fn bump_security_version(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_id: Uuid,
    ) -> AppResult<()> {
        sqlx::query("UPDATE users SET security_version = security_version + 1 WHERE id = $1")
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }
}

// `not_found_or_denied` used to live here: a second expression of the rule that an
// external principal sees `404` where an internal one sees `403`. It had no callers
// at all, while `AppError::hide_from_external` — the same rule — has seven.
//
// Deleted rather than kept "in case it is useful", because the risk is specific:
// two implementations of one security rule drift the moment somebody teaches one of
// them about a new error variant and not the other, and the dead one is the one
// nobody re-reads. There is now exactly one place that decides how a refusal is
// shaped for an outsider.
