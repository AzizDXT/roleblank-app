//! Request and response types for projects.
//!
//! Two rules shape this file, both of them security rules rather than style:
//!
//! 1. **Request DTOs are closed.** Every one carries `deny_unknown_fields`, and
//!    none of them contains `id`, `status` (on create), `version` (except as the
//!    optimistic-concurrency token), `created_by`, or any other field the endpoint
//!    is not explicitly authorising a change to. That is the mass-assignment
//!    defence (TH-12).
//!
//! 2. **The internal and external projections are different Rust types.**
//!    `ClientProjectResponse` does not have an `internal_note` field that is
//!    skipped — it has no such field at all, and neither `created_by`,
//!    `manager_user_id`, `department_id` nor `version`. A `#[serde(skip)]` can be
//!    removed by a careless edit and nothing fails to compile; a missing field
//!    cannot be leaked by any serialisation change, because there is nothing to
//!    leak (TH-10, TH-11).

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::platform::errors::AppError;

// ---------------------------------------------------------------------------
// Domain enums
// ---------------------------------------------------------------------------

/// Mirrors the `projects.status` CHECK constraint exactly. A value the database
/// would reject must never reach it, so the parse side is exhaustive and closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectStatus {
    Active,
    Paused,
    Completed,
    Archived,
}

impl ProjectStatus {
    pub const ALLOWED: &'static [&'static str] = &["ACTIVE", "PAUSED", "COMPLETED", "ARCHIVED"];

    pub fn as_str(self) -> &'static str {
        match self {
            ProjectStatus::Active => "ACTIVE",
            ProjectStatus::Paused => "PAUSED",
            ProjectStatus::Completed => "COMPLETED",
            ProjectStatus::Archived => "ARCHIVED",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ACTIVE" => Some(ProjectStatus::Active),
            "PAUSED" => Some(ProjectStatus::Paused),
            "COMPLETED" => Some(ProjectStatus::Completed),
            "ARCHIVED" => Some(ProjectStatus::Archived),
            _ => None,
        }
    }

    /// Archiving is terminal. Nothing leaves `ARCHIVED`, because the archive
    /// timestamp and the status are tied together by
    /// `projects_archive_consistent`, and an "unarchive" would silently rewrite
    /// the record of when the project ended.
    pub fn can_transition_to(self, next: ProjectStatus) -> bool {
        use ProjectStatus::*;
        if self == next {
            return true;
        }
        match (self, next) {
            (Archived, _) => false,
            (Active, Paused | Completed | Archived) => true,
            (Paused, Active | Completed | Archived) => true,
            // Reopening a finished project is legitimate; scope changes late.
            (Completed, Active | Paused | Archived) => true,
            _ => false,
        }
    }

    /// `completed_at` is derived, never accepted from a request: a caller that
    /// could set it independently of `status` could produce a "completed" project
    /// with no completion date, or the reverse.
    ///
    /// An existing timestamp is preserved, so re-saving a finished project does not
    /// silently restate when it finished.
    pub fn completed_at_for(
        self,
        existing: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Option<OffsetDateTime> {
        match self {
            ProjectStatus::Completed => existing.or(Some(now)),
            _ => None,
        }
    }

    /// Likewise for `archived_at`, which the database ties to the status with the
    /// `projects_archive_consistent` CHECK. Getting this wrong in code turns a
    /// business error into an opaque 500 from a constraint violation.
    pub fn archived_at_for(
        self,
        existing: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Option<OffsetDateTime> {
        match self {
            ProjectStatus::Archived => existing.or(Some(now)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectRole {
    Member,
    Lead,
}

impl ProjectRole {
    pub const ALLOWED: &'static [&'static str] = &["MEMBER", "LEAD"];

    pub fn as_str(self) -> &'static str {
        match self {
            ProjectRole::Member => "MEMBER",
            ProjectRole::Lead => "LEAD",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "MEMBER" => Some(ProjectRole::Member),
            "LEAD" => Some(ProjectRole::Lead),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire format for calendar dates
// ---------------------------------------------------------------------------

/// `YYYY-MM-DD`, in both directions.
///
/// `time::Date`'s own serde implementation is a *compound* form, not an ISO
/// string: it emits a structure and refuses `"2024-01-31"` on the way in. Relying
/// on it would have produced an API that neither accepts nor emits the date format
/// every client expects, and the failure is silent at compile time — which is
/// exactly why the round trip is asserted in this module's tests.
///
/// Shared with `modules::tasks::dto`, so the two modules cannot drift into
/// different date formats on the same API.
pub(crate) mod date_iso {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::BorrowedFormatItem;
    use time::macros::format_description;
    use time::Date;

    const FORMAT: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day]");
    const EXPECTED: &str = "a calendar date in the form YYYY-MM-DD";

    pub fn serialize<S: Serializer>(date: &Date, serializer: S) -> Result<S::Ok, S::Error> {
        let text = date.format(FORMAT).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }

    /// Retained deliberately even though no DTO currently deserialises a
    /// non-optional date — every date on the wire today is `Option<Date>` and
    /// goes through `option` below.
    ///
    /// This is one half of a serde `with` module: `#[serde(with = "date_iso")]`
    /// resolves *both* `serialize` and `deserialize`, so deleting this to silence
    /// dead-code would break the next person who adds a required date field, and
    /// would do so with an error pointing at their attribute rather than at the
    /// missing function.
    #[allow(dead_code)]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Date, D::Error> {
        let raw = String::deserialize(deserializer)?;
        // The rejected value is deliberately not echoed into the message: an error
        // that reflects its input is a reflection gadget and a log-injection vector.
        Date::parse(&raw, FORMAT).map_err(|_| D::Error::custom(EXPECTED))
    }

    pub mod option {
        use super::{Date, Deserialize, Deserializer, Serializer, EXPECTED, FORMAT};
        use serde::de::Error as _;

        pub fn serialize<S: Serializer>(
            date: &Option<Date>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match date {
                Some(d) => super::serialize(d, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Date>, D::Error> {
            match Option::<String>::deserialize(deserializer)? {
                None => Ok(None),
                Some(raw) => Date::parse(&raw, FORMAT)
                    .map(Some)
                    .map_err(|_| D::Error::custom(EXPECTED)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Request DTOs
// ---------------------------------------------------------------------------

/// Distinguishes "field absent" from "field explicitly null" in a PATCH body.
///
/// Without it, `{"department_id": null}` (detach the project from its department)
/// is indistinguishable from omitting the key (leave it alone), and one of those
/// two meanings would silently become the other.
fn explicit_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// The same absent-versus-null distinction for a calendar date, routed through
/// `date_iso` so a PATCH accepts the same format a GET emits.
fn explicit_date<'de, D>(deserializer: D) -> Result<Option<Option<Date>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    date_iso::option::deserialize(deserializer).map(Some)
}

/// `POST /api/v1/projects`.
///
/// Deliberately absent: `id` (server-assigned), `status` (always starts `ACTIVE`),
/// `version`, `created_by`, `archived_at`, `completed_at`, and anything to do with
/// client sharing — sharing is a separate, dangerous, step-up-gated endpoint and
/// must never be a field on a create body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectRequest {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub manager_user_id: Uuid,
    #[serde(default)]
    pub department_id: Option<Uuid>,
    #[serde(default, with = "date_iso::option")]
    pub start_date: Option<Date>,
    #[serde(default, with = "date_iso::option")]
    pub target_date: Option<Date>,
    #[serde(default)]
    pub internal_note: Option<String>,
}

/// `PATCH /api/v1/projects/{id}`.
///
/// `code` is absent on purpose: a project code is referenced by humans and by
/// external documents, so renaming it is a migration, not an edit.
/// `status` may not be set to `ARCHIVED` here — archiving has its own endpoint and
/// its own permission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateProjectRequest {
    /// The optimistic-concurrency token. Mandatory: an update without one is a
    /// silent last-writer-wins overwrite (TH-44).
    pub version: i32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub manager_user_id: Option<Uuid>,
    #[serde(default, deserialize_with = "explicit_option")]
    pub department_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "explicit_date")]
    pub start_date: Option<Option<Date>>,
    #[serde(default, deserialize_with = "explicit_date")]
    pub target_date: Option<Option<Date>>,
    #[serde(default)]
    pub internal_note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveProjectRequest {
    pub version: i32,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddProjectMemberRequest {
    pub user_id: Uuid,
    #[serde(default)]
    pub role_in_project: Option<String>,
}

/// `POST /api/v1/projects/{id}/clients` — the external trust boundary.
///
/// There is no `tasks` field and no `include_tasks` flag: sharing a project shares
/// the project, never its task list. A task becomes visible only through its own
/// `client_visible` flag (`docs/backend/04-authorization.md` §9).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareProjectRequest {
    pub client_account_id: Uuid,
    #[serde(default)]
    pub note: Option<String>,
}

/// Query parameters for `GET /api/v1/projects`.
///
/// The pagination fields are spelled out rather than `#[serde(flatten)]`ed from
/// `PageQuery`, because serde disables `deny_unknown_fields` on any struct that
/// flattens — and an unbounded, unvalidated query surface is exactly what the
/// closed-DTO rule exists to prevent.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectListQuery {
    pub status: Option<String>,
    pub department_id: Option<Uuid>,
    pub cursor: Option<String>,
    pub limit: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
}

impl ProjectListQuery {
    pub fn page(&self) -> crate::shared::pagination::PageQuery {
        crate::shared::pagination::PageQuery {
            cursor: self.cursor.clone(),
            limit: self.limit.clone(),
            sort: self.sort.clone(),
            direction: self.direction.clone(),
        }
    }

    pub fn parsed_status(&self) -> Result<Option<ProjectStatus>, AppError> {
        match self.status.as_deref() {
            None => Ok(None),
            Some(raw) => crate::shared::validation::parse_enum(
                "status",
                raw,
                ProjectStatus::parse,
                ProjectStatus::ALLOWED,
            )
            .map(Some),
        }
    }
}

/// Query parameters for the client portal listing. Deliberately narrower than the
/// internal one: an external principal cannot filter by department, because it
/// must not learn that departments exist.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProjectListQuery {
    pub cursor: Option<String>,
    pub limit: Option<String>,
}

impl ClientProjectListQuery {
    pub fn page(&self) -> crate::shared::pagination::PageQuery {
        crate::shared::pagination::PageQuery {
            cursor: self.cursor.clone(),
            limit: self.limit.clone(),
            sort: None,
            direction: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Response DTOs — internal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ProjectResponse {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: ProjectStatus,
    pub manager_user_id: Uuid,
    pub department_id: Option<Uuid>,
    #[serde(with = "date_iso::option")]
    pub start_date: Option<Date>,
    #[serde(with = "date_iso::option")]
    pub target_date: Option<Date>,
    pub internal_note: String,
    pub version: i32,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub archived_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectMemberResponse {
    pub user_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub role_in_project: ProjectRole,
    pub added_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectClientLinkResponse {
    pub client_account_id: Uuid,
    pub client_code: String,
    pub client_name: String,
    pub client_status: String,
    pub note: String,
    pub shared_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub shared_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Response DTO — external (client portal)
// ---------------------------------------------------------------------------

/// What an external principal is allowed to see about a project.
///
/// **This type has no `internal_note`, `created_by`, `manager_user_id`,
/// `department_id` or `version` field.** They are not skipped, not renamed and not
/// conditionally serialised: they are absent from the type, so no change to serde
/// attributes, no `flatten`, and no future "just add the row struct here" can
/// reintroduce them. `projects::tests` asserts this against the serialised JSON.
#[derive(Debug, Clone, Serialize)]
pub struct ClientProjectResponse {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: String,
    pub status: ProjectStatus,
    #[serde(with = "date_iso::option")]
    pub start_date: Option<Date>,
    #[serde(with = "date_iso::option")]
    pub target_date: Option<Date>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Keys that must never appear in an external projection, in any module.
    pub(crate) const FORBIDDEN_CLIENT_KEYS: &[&str] = &[
        "internal_note",
        "created_by",
        "manager_user_id",
        "department_id",
        "version",
    ];

    fn fully_populated_client_project() -> ClientProjectResponse {
        ClientProjectResponse {
            id: Uuid::now_v7(),
            code: "acme-rollout".into(),
            name: "Acme rollout".into(),
            description: "Phase two".into(),
            status: ProjectStatus::Active,
            start_date: Date::from_calendar_date(2024, time::Month::January, 31).ok(),
            target_date: Date::from_calendar_date(2024, time::Month::June, 30).ok(),
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The single most important test in this module. Every field is populated so
    /// that nothing is omitted merely because it was `None`.
    #[test]
    fn the_client_projection_cannot_contain_an_internal_field() {
        let json = serde_json::to_value(fully_populated_client_project()).expect("serialise");
        let Value::Object(map) = &json else {
            panic!("expected an object")
        };
        for key in FORBIDDEN_CLIENT_KEYS {
            assert!(
                !map.contains_key(*key),
                "ClientProjectResponse leaked `{key}`: {json}"
            );
        }
        // And nothing that merely *looks* like one either.
        let text = json.to_string();
        assert!(
            !text.contains("internal"),
            "leaked an internal-looking key: {text}"
        );
    }

    #[test]
    fn the_internal_projection_does_carry_the_internal_fields() {
        // The mirror of the test above: if these ever disappear from the internal
        // type, the two projections have been accidentally merged.
        let json = serde_json::to_value(ProjectResponse {
            id: Uuid::now_v7(),
            code: "c".into(),
            name: "n".into(),
            description: String::new(),
            status: ProjectStatus::Active,
            manager_user_id: Uuid::now_v7(),
            department_id: None,
            start_date: None,
            target_date: None,
            internal_note: "do not tell the client".into(),
            version: 1,
            created_by: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            archived_at: None,
            completed_at: None,
        })
        .expect("serialise");
        for key in FORBIDDEN_CLIENT_KEYS {
            assert!(json.get(*key).is_some(), "ProjectResponse lost `{key}`");
        }
    }

    // ---- closed request DTOs ------------------------------------------------

    fn create_body_with(extra: &str) -> String {
        format!(
            r#"{{"code":"c","name":"n","manager_user_id":"00000000-0000-7000-8000-000000000001"{extra}}}"#
        )
    }

    #[test]
    fn create_rejects_every_field_it_does_not_own() {
        assert!(serde_json::from_str::<CreateProjectRequest>(&create_body_with("")).is_ok());
        for attack in [
            r#","id":"00000000-0000-7000-8000-000000000002""#,
            r#","status":"ARCHIVED""#,
            r#","version":99"#,
            r#","created_by":"00000000-0000-7000-8000-000000000002""#,
            r#","client_visible":true"#,
            r#","archived_at":"2024-01-01T00:00:00Z""#,
            r#","completed_at":"2024-01-01T00:00:00Z""#,
            r#","client_account_id":"00000000-0000-7000-8000-000000000002""#,
            r#","principal_type":"INTERNAL""#,
        ] {
            assert!(
                serde_json::from_str::<CreateProjectRequest>(&create_body_with(attack)).is_err(),
                "CreateProjectRequest accepted `{attack}`"
            );
        }
    }

    #[test]
    fn update_rejects_every_field_it_does_not_own() {
        assert!(serde_json::from_str::<UpdateProjectRequest>(r#"{"version":1}"#).is_ok());
        for attack in [
            r#"{"version":1,"id":"00000000-0000-7000-8000-000000000002"}"#,
            r#"{"version":1,"code":"renamed"}"#,
            r#"{"version":1,"created_by":"00000000-0000-7000-8000-000000000002"}"#,
            r#"{"version":1,"client_visible":true}"#,
            r#"{"version":1,"archived_at":"2024-01-01T00:00:00Z"}"#,
            r#"{"version":1,"completed_at":"2024-01-01T00:00:00Z"}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateProjectRequest>(attack).is_err(),
                "UpdateProjectRequest accepted `{attack}`"
            );
        }
        // `version` is not optional: an update with no concurrency token is refused.
        assert!(serde_json::from_str::<UpdateProjectRequest>(r#"{"name":"x"}"#).is_err());
    }

    #[test]
    fn sharing_never_accepts_a_task_flag() {
        assert!(serde_json::from_str::<ShareProjectRequest>(
            r#"{"client_account_id":"00000000-0000-7000-8000-000000000002"}"#
        )
        .is_ok());
        for attack in [
            r#"{"client_account_id":"00000000-0000-7000-8000-000000000002","include_tasks":true}"#,
            r#"{"client_account_id":"00000000-0000-7000-8000-000000000002","client_visible":true}"#,
            r#"{"client_account_id":"00000000-0000-7000-8000-000000000002","tasks":["x"]}"#,
        ] {
            assert!(
                serde_json::from_str::<ShareProjectRequest>(attack).is_err(),
                "ShareProjectRequest accepted `{attack}`"
            );
        }
    }

    #[test]
    fn list_queries_are_closed_too() {
        assert!(serde_json::from_str::<ProjectListQuery>(r#"{"status":"ACTIVE"}"#).is_ok());
        assert!(serde_json::from_str::<ProjectListQuery>(r#"{"internal_note":"x"}"#).is_err());
        // The client portal query is narrower still.
        assert!(serde_json::from_str::<ClientProjectListQuery>(r#"{"limit":"10"}"#).is_ok());
        for attack in [
            r#"{"department_id":"x"}"#,
            r#"{"status":"ACTIVE"}"#,
            r#"{"sort":"name"}"#,
        ] {
            assert!(
                serde_json::from_str::<ClientProjectListQuery>(attack).is_err(),
                "ClientProjectListQuery accepted `{attack}`"
            );
        }
    }

    #[test]
    fn absent_and_explicitly_null_are_different_in_a_patch() {
        let absent: UpdateProjectRequest =
            serde_json::from_str(r#"{"version":1}"#).expect("absent");
        assert_eq!(absent.department_id, None, "absent means `leave it alone`");

        let cleared: UpdateProjectRequest =
            serde_json::from_str(r#"{"version":1,"department_id":null}"#).expect("null");
        assert_eq!(
            cleared.department_id,
            Some(None),
            "explicit null means `detach`"
        );

        let set: UpdateProjectRequest = serde_json::from_str(
            r#"{"version":1,"department_id":"00000000-0000-7000-8000-000000000002"}"#,
        )
        .expect("value");
        assert!(matches!(set.department_id, Some(Some(_))));
    }

    /// Guards the wire format in both directions. `time::Date`'s own serde
    /// implementation is a compound form that neither emits nor accepts
    /// `"2024-01-31"`, so relying on it would have shipped an API no client could
    /// use — and nothing about that failure is visible at compile time.
    #[test]
    fn dates_are_accepted_and_emitted_as_iso_calendar_dates() {
        let request: CreateProjectRequest = serde_json::from_str(
            r#"{"code":"c","name":"n","manager_user_id":"00000000-0000-7000-8000-000000000001",
                "start_date":"2024-01-31","target_date":"2024-06-30"}"#,
        )
        .expect("a request with ISO dates");
        assert_eq!(
            request.start_date,
            Date::from_calendar_date(2024, time::Month::January, 31).ok()
        );

        let json = serde_json::to_value(fully_populated_client_project()).expect("serialise");
        assert_eq!(json["start_date"], serde_json::json!("2024-01-31"));
        assert_eq!(json["target_date"], serde_json::json!("2024-06-30"));

        // A PATCH accepts exactly what a GET emits, including an explicit null.
        let patch: UpdateProjectRequest =
            serde_json::from_str(r#"{"version":1,"start_date":"2024-01-31"}"#).expect("patch");
        assert!(matches!(patch.start_date, Some(Some(_))));
        let cleared: UpdateProjectRequest =
            serde_json::from_str(r#"{"version":1,"start_date":null}"#).expect("patch");
        assert_eq!(cleared.start_date, Some(None));

        for bad in [
            r#""31/01/2024""#,
            r#""2024-13-01""#,
            r#""not a date""#,
            "1706659200",
        ] {
            let body = format!(
                r#"{{"code":"c","name":"n","manager_user_id":"00000000-0000-7000-8000-000000000001","start_date":{bad}}}"#
            );
            let err = serde_json::from_str::<CreateProjectRequest>(&body)
                .expect_err("malformed date accepted");
            // The rejected value must not be reflected back in the message.
            assert!(
                !err.to_string().contains("31/01"),
                "the rejected input was echoed: {err}"
            );
        }
    }

    // ---- status transitions -------------------------------------------------

    #[test]
    fn status_parsing_is_exact_and_closed() {
        for s in ProjectStatus::ALLOWED {
            assert_eq!(ProjectStatus::parse(s).map(|p| p.as_str()), Some(*s));
        }
        for bad in [
            "active",
            "DELETED",
            "",
            "ACTIVE; DROP TABLE projects",
            " ACTIVE",
        ] {
            assert_eq!(ProjectStatus::parse(bad), None, "accepted `{bad}`");
        }
    }

    #[test]
    fn archived_is_terminal() {
        use ProjectStatus::*;
        for next in [Active, Paused, Completed] {
            assert!(
                !Archived.can_transition_to(next),
                "a project escaped ARCHIVED into {next:?}"
            );
        }
        assert!(
            Archived.can_transition_to(Archived),
            "a no-op is always allowed"
        );
    }

    #[test]
    fn ordinary_project_transitions_are_permitted() {
        use ProjectStatus::*;
        assert!(Active.can_transition_to(Paused));
        assert!(Paused.can_transition_to(Active));
        assert!(Active.can_transition_to(Completed));
        assert!(
            Completed.can_transition_to(Active),
            "reopening is legitimate"
        );
        for from in [Active, Paused, Completed] {
            assert!(from.can_transition_to(Archived));
        }
    }

    /// The database enforces `(status = 'ARCHIVED') = (archived_at IS NOT NULL)`.
    /// Getting it wrong in code turns a business rule into an opaque 500, so the
    /// correspondence is asserted for every status in the catalogue.
    #[test]
    fn derived_timestamps_match_the_check_constraints() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let earlier = now - time::Duration::days(1);

        for raw in ProjectStatus::ALLOWED {
            let status = ProjectStatus::parse(raw).expect("catalogue status");
            for existing in [None, Some(earlier)] {
                assert_eq!(
                    status == ProjectStatus::Archived,
                    status.archived_at_for(existing, now).is_some(),
                    "(status = 'ARCHIVED') = (archived_at IS NOT NULL) violated for {raw}"
                );
                assert_eq!(
                    status == ProjectStatus::Completed,
                    status.completed_at_for(existing, now).is_some(),
                    "completed_at must be set exactly when the status is COMPLETED ({raw})"
                );
            }
        }

        // An existing instant is preserved rather than restated.
        assert_eq!(
            ProjectStatus::Archived.archived_at_for(Some(earlier), now),
            Some(earlier)
        );
        assert_eq!(
            ProjectStatus::Archived.archived_at_for(None, now),
            Some(now)
        );
        assert_eq!(
            ProjectStatus::Completed.completed_at_for(Some(earlier), now),
            Some(earlier)
        );
    }

    #[test]
    fn project_roles_are_closed() {
        assert_eq!(ProjectRole::parse("LEAD"), Some(ProjectRole::Lead));
        for bad in ["OWNER", "lead", "ADMIN", ""] {
            assert_eq!(ProjectRole::parse(bad), None, "accepted `{bad}`");
        }
    }
}
