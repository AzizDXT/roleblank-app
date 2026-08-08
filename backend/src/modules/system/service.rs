//! System service: liveness, readiness and the authenticated information probe.

use crate::app::AppState;
use crate::modules::authentication::principal::Principal;
use crate::platform::database;
use crate::platform::errors::AppResult;

use super::dto::SystemInfoResponse;
use super::repo;

/// Readiness: may this process safely receive traffic?
///
/// Two conditions, both necessary:
///
///   1. the database answers, and
///   2. every migration this binary carries has been applied.
///
/// The second is not pedantry. A replica talking to a database migrated by a
/// different build is not merely degraded — it will write rows that violate
/// constraints the other build relies on, or read columns that do not exist yet.
/// Refusing traffic is the correct behaviour, and it is what makes a rolling
/// deploy that forgot `roleblank-api migrate` fail visibly instead of corrupting
/// data.
///
/// **This function returns a bare `bool` on purpose.** The reason for a failure is
/// logged, never returned. `AppError::from(sqlx::Error)` can carry an internal
/// string, `migrations_are_current` knows the schema version, and the driver's own
/// message can contain the connection string including the database hostname —
/// none of which an unauthenticated caller may learn (TH-35). Collapsing every
/// failure mode to `false` here means there is no code path from a driver message
/// to the probe body at all, rather than a promise that the handler will remember
/// not to format one.
pub async fn is_ready(state: &AppState) -> bool {
    if let Err(error) = database::ping(&state.db).await {
        // Logged with the request id; the caller is told only `not_ready`.
        tracing::warn!(
            error.code = error.code(),
            "readiness probe: database is not reachable"
        );
        return false;
    }

    match database::migrations_are_current(&state.db).await {
        Ok(true) => true,
        Ok(false) => {
            tracing::error!(
                "readiness probe: the schema is not at the version this build expects; \
                 refusing traffic until `roleblank-api migrate` has run"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                error.code = error.code(),
                "readiness probe: could not read the migration state"
            );
            false
        }
    }
}

/// `GET /api/v1/system/info`.
///
/// Requires authentication and nothing else: there is no permission code for
/// "read the environment name", and inventing one would put a meaningless entry in
/// the catalogue that every role would then need. The protection is the field list
/// itself — see `dto::SystemInfoResponse` for what is deliberately absent.
///
/// The same body is served to an external CLIENT principal. That is safe because
/// none of the three fields is an internal fact: the environment is visible from
/// the URL, `initialized` is already observable from the bootstrap endpoint's
/// behaviour, and a *non-sensitive* feature flag key is not a capability — see the
/// note in `modules::settings`.
///
/// The qualifier is load-bearing and was missing. `enabled_feature_flag_keys` now
/// excludes `is_security_sensitive` rows in the query itself; without that filter
/// this endpoint handed the names of the security-relevant toggles to every
/// principal that could authenticate, including one outside the company.
pub async fn info(state: &AppState, principal: &Principal) -> AppResult<SystemInfoResponse> {
    let initialized = repo::is_initialized(&state.db).await?;

    // The feature list is company-internal and stops at the client envelope.
    //
    // The query already excludes rows marked `is_security_sensitive`, and that
    // remains the primary control — but it is a control over *which* flags, not over
    // *who* may read them, and it depends on somebody correctly classifying every
    // future flag. A flag does not have to be security-sensitive to be an internal
    // fact: "billing_v2", "new_onboarding" and "layoff_tooling" are all ordinary
    // rollout switches and none of them is a customer's business.
    //
    // An external principal therefore gets the two facts a client portal genuinely
    // needs — which deployment it is talking to, and whether that deployment is set
    // up — and no capability list at all.
    let enabled_features = if principal.is_external() {
        Vec::new()
    } else {
        repo::enabled_feature_flag_keys(&state.db).await?
    };

    Ok(SystemInfoResponse {
        environment: state.config.environment.as_str().to_string(),
        initialized,
        enabled_features,
    })
}
