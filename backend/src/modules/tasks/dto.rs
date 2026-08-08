//! Request and response types for tasks.
//!
//! The same two rules as the projects DTOs, plus one that is specific to this
//! module: **`client_visible` is not a create-time field.** A task is created
//! invisible, and becomes visible only through an explicit, separately audited
//! edit (`TASK.CLIENT_VISIBILITY_CHANGED`). That removes the failure mode where a
//! bulk import, a template, or a copied request body publishes internal work to a
//! client as a side effect of creating it.

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::modules::projects::dto::date_iso;
use crate::platform::errors::AppError;

// ---------------------------------------------------------------------------
// Domain enums
// ---------------------------------------------------------------------------

/// Mirrors the `tasks.status` CHECK constraint exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskStatus {
    Todo,
    InProgress,
    Blocked,
    Done,
    Cancelled,
}

impl TaskStatus {
    pub const ALLOWED: &'static [&'static str] =
        &["TODO", "IN_PROGRESS", "BLOCKED", "DONE", "CANCELLED"];

    pub fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Todo => "TODO",
            TaskStatus::InProgress => "IN_PROGRESS",
            TaskStatus::Blocked => "BLOCKED",
            TaskStatus::Done => "DONE",
            TaskStatus::Cancelled => "CANCELLED",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "TODO" => Some(TaskStatus::Todo),
            "IN_PROGRESS" => Some(TaskStatus::InProgress),
            "BLOCKED" => Some(TaskStatus::Blocked),
            "DONE" => Some(TaskStatus::Done),
            "CANCELLED" => Some(TaskStatus::Cancelled),
            _ => None,
        }
    }

    /// Cancellation is terminal. A cancelled task is a record that the work was
    /// dropped; resurrecting it would erase that, and the row is never deleted
    /// precisely so the record survives.
    pub fn can_transition_to(self, next: TaskStatus) -> bool {
        use TaskStatus::*;
        if self == next {
            return true;
        }
        match (self, next) {
            (Cancelled, _) => false,
            (Todo, InProgress | Blocked | Done | Cancelled) => true,
            (InProgress, Todo | Blocked | Done | Cancelled) => true,
            (Blocked, Todo | InProgress | Done | Cancelled) => true,
            // Reopening finished work is legitimate; cancelling it after the fact
            // is not — it was done.
            (Done, Todo | InProgress) => true,
            _ => false,
        }
    }

    /// `tasks_completion_consistent` is `(status = 'DONE') = (completed_at IS NOT
    /// NULL)`. This function is the single place that decides the timestamp, so the
    /// CHECK constraint is a backstop rather than the thing that discovers a bug.
    ///
    /// Note the "otherwise `None`" half: moving a task *out* of `DONE` must clear
    /// the completion timestamp, not leave it behind.
    pub fn completed_at_for(
        self,
        existing: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Option<OffsetDateTime> {
        match self {
            // Keep the original completion instant when the task was already done:
            // re-saving a finished task must not silently restate when it finished.
            TaskStatus::Done => existing.or(Some(now)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Urgent,
}

impl TaskPriority {
    pub const ALLOWED: &'static [&'static str] = &["LOW", "NORMAL", "HIGH", "URGENT"];

    pub fn as_str(self) -> &'static str {
        match self {
            TaskPriority::Low => "LOW",
            TaskPriority::Normal => "NORMAL",
            TaskPriority::High => "HIGH",
            TaskPriority::Urgent => "URGENT",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "LOW" => Some(TaskPriority::Low),
            "NORMAL" => Some(TaskPriority::Normal),
            "HIGH" => Some(TaskPriority::High),
            "URGENT" => Some(TaskPriority::Urgent),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Request DTOs
// ---------------------------------------------------------------------------

/// Distinguishes "field absent" from "field explicitly null" in a PATCH body,
/// routed through the
/// shared `date_iso` format so a PATCH accepts exactly what a GET emits.
fn explicit_date<'de, D>(deserializer: D) -> Result<Option<Option<Date>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    date_iso::option::deserialize(deserializer).map(Some)
}

/// `POST /api/v1/tasks`.
///
/// Absent on purpose:
///
/// * `client_visible` — a new task is always invisible to clients; see the module
///   comment. Making it visible is a distinct, separately audited edit.
/// * `status` — a task always starts `TODO`.
/// * `assignees` — assignment is `tasks.assign`, a different permission, so it
///   cannot be smuggled in on a body that only `tasks.create` authorised.
/// * `id`, `version`, `created_by`, `completed_at`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTaskRequest {
    pub project_id: Uuid,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default, with = "date_iso::option")]
    pub due_date: Option<Date>,
    #[serde(default)]
    pub internal_note: Option<String>,
}

/// `PATCH /api/v1/tasks/{id}`.
///
/// `client_visible` is accepted here and nowhere else. The endpoint requires
/// `tasks.update`, which is `INTERNAL`-only, so an external principal cannot reach
/// this DTO at all — the envelope check denies before the body is ever considered.
/// `project_id` is absent: moving a task between projects would move it across a
/// different set of client links, which is a share operation wearing an edit's
/// clothes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTaskRequest {
    pub version: i32,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default, deserialize_with = "explicit_date")]
    pub due_date: Option<Option<Date>>,
    #[serde(default)]
    pub internal_note: Option<String>,
    #[serde(default)]
    pub client_visible: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignTaskRequest {
    pub user_id: Uuid,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskListQuery {
    pub project_id: Option<Uuid>,
    pub status: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
}

impl TaskListQuery {
    pub fn page(&self) -> crate::shared::pagination::PageQuery {
        crate::shared::pagination::PageQuery {
            cursor: self.cursor.clone(),
            limit: self.limit.clone(),
            sort: self.sort.clone(),
            direction: self.direction.clone(),
        }
    }

    pub fn parsed_status(&self) -> Result<Option<TaskStatus>, AppError> {
        match self.status.as_deref() {
            None => Ok(None),
            Some(raw) => crate::shared::validation::parse_enum(
                "status",
                raw,
                TaskStatus::parse,
                TaskStatus::ALLOWED,
            )
            .map(Some),
        }
    }
}

/// Cancellation carries an optional concurrency token as a query parameter,
/// because a `DELETE` has no body.
///
/// It is honoured when supplied: cancelling a task that someone else has since
/// moved to `DONE` is exactly the lost update the `version` column exists to catch.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelTaskQuery {
    pub version: Option<i32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTaskListQuery {
    pub cursor: Option<String>,
    pub limit: Option<String>,
}

impl ClientTaskListQuery {
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
// Response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct TaskResponse {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: TaskStatus,
    pub priority: TaskPriority,
    #[serde(with = "date_iso::option")]
    pub due_date: Option<Date>,
    pub client_visible: bool,
    pub internal_note: String,
    pub version: i32,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskAssigneeResponse {
    pub user_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub assigned_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub assigned_at: OffsetDateTime,
}

/// What an external principal is allowed to see about a task.
///
/// **No `internal_note`, `created_by`, `version` or `client_visible` field
/// exists on this type.** `client_visible` is excluded along with the rest: it is
/// an internal control, and echoing it back would tell a client which of the
/// project's tasks were deliberately hidden — a count they should not have.
/// `tasks::tests` asserts the absence against the serialised JSON.
#[derive(Debug, Clone, Serialize)]
pub struct ClientTaskResponse {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: TaskStatus,
    pub priority: TaskPriority,
    #[serde(with = "date_iso::option")]
    pub due_date: Option<Date>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FORBIDDEN_CLIENT_KEYS: &[&str] = &[
        "internal_note",
        "created_by",
        "version",
        "client_visible",
        "manager_user_id",
        "department_id",
        "assignees",
    ];

    fn fully_populated_client_task() -> ClientTaskResponse {
        ClientTaskResponse {
            id: Uuid::now_v7(),
            project_id: Uuid::now_v7(),
            title: "Ship phase two".into(),
            description: "The client-facing description".into(),
            status: TaskStatus::InProgress,
            priority: TaskPriority::High,
            due_date: Date::from_calendar_date(2024, time::Month::March, 1).ok(),
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn the_client_projection_cannot_contain_an_internal_field() {
        let json = serde_json::to_value(fully_populated_client_task()).expect("serialise");
        let Value::Object(map) = &json else {
            panic!("expected an object")
        };
        for key in FORBIDDEN_CLIENT_KEYS {
            assert!(
                !map.contains_key(*key),
                "ClientTaskResponse leaked `{key}`: {json}"
            );
        }
        let text = json.to_string();
        assert!(
            !text.contains("internal"),
            "leaked an internal-looking key: {text}"
        );
        assert!(
            !text.contains("visible"),
            "the client must not learn which tasks were hidden from it: {text}"
        );
    }

    #[test]
    fn the_internal_projection_still_carries_the_internal_fields() {
        let json = serde_json::to_value(TaskResponse {
            id: Uuid::now_v7(),
            project_id: Uuid::now_v7(),
            title: "t".into(),
            description: String::new(),
            status: TaskStatus::Todo,
            priority: TaskPriority::Normal,
            due_date: None,
            client_visible: false,
            internal_note: "do not tell the client".into(),
            version: 1,
            created_by: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            completed_at: None,
        })
        .expect("serialise");
        for key in ["internal_note", "created_by", "version", "client_visible"] {
            assert!(json.get(key).is_some(), "TaskResponse lost `{key}`");
        }
    }

    // ---- closed request DTOs ------------------------------------------------

    fn create_body_with(extra: &str) -> String {
        format!(r#"{{"project_id":"00000000-0000-7000-8000-000000000001","title":"t"{extra}}}"#)
    }

    /// `client_visible` on a create body is the single most dangerous field this
    /// module could accept, so it is tested first and by name.
    #[test]
    fn create_never_accepts_client_visibility_or_anything_else_it_does_not_own() {
        assert!(serde_json::from_str::<CreateTaskRequest>(&create_body_with("")).is_ok());
        for attack in [
            r#","client_visible":true"#,
            r#","status":"DONE""#,
            r#","id":"00000000-0000-7000-8000-000000000002""#,
            r#","version":1"#,
            r#","created_by":"00000000-0000-7000-8000-000000000002""#,
            r#","completed_at":"2024-01-01T00:00:00Z""#,
            r#","assignees":["00000000-0000-7000-8000-000000000002"]"#,
            r#","assignee_user_id":"00000000-0000-7000-8000-000000000002""#,
        ] {
            assert!(
                serde_json::from_str::<CreateTaskRequest>(&create_body_with(attack)).is_err(),
                "CreateTaskRequest accepted `{attack}`"
            );
        }
    }

    #[test]
    fn update_accepts_client_visibility_but_nothing_it_does_not_own() {
        assert!(
            serde_json::from_str::<UpdateTaskRequest>(r#"{"version":1,"client_visible":true}"#)
                .is_ok(),
            "an internal principal must be able to publish a task deliberately"
        );
        for attack in [
            r#"{"version":1,"id":"00000000-0000-7000-8000-000000000002"}"#,
            r#"{"version":1,"project_id":"00000000-0000-7000-8000-000000000002"}"#,
            r#"{"version":1,"created_by":"00000000-0000-7000-8000-000000000002"}"#,
            r#"{"version":1,"completed_at":"2024-01-01T00:00:00Z"}"#,
            r#"{"version":1,"assignees":[]}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdateTaskRequest>(attack).is_err(),
                "UpdateTaskRequest accepted `{attack}`"
            );
        }
        assert!(
            serde_json::from_str::<UpdateTaskRequest>(r#"{"title":"x"}"#).is_err(),
            "an update without a concurrency token is refused"
        );
    }

    #[test]
    fn assignment_accepts_exactly_one_field() {
        assert!(serde_json::from_str::<AssignTaskRequest>(
            r#"{"user_id":"00000000-0000-7000-8000-000000000002"}"#
        )
        .is_ok());
        for attack in [
            r#"{"user_id":"00000000-0000-7000-8000-000000000002","principal_type":"CLIENT"}"#,
            r#"{"user_id":"00000000-0000-7000-8000-000000000002","role":"LEAD"}"#,
            r#"{}"#,
        ] {
            assert!(
                serde_json::from_str::<AssignTaskRequest>(attack).is_err(),
                "AssignTaskRequest accepted `{attack}`"
            );
        }
    }

    #[test]
    fn the_client_list_query_is_narrower_than_the_internal_one() {
        assert!(serde_json::from_str::<TaskListQuery>(r#"{"status":"TODO"}"#).is_ok());
        assert!(serde_json::from_str::<TaskListQuery>(r#"{"client_visible":"true"}"#).is_err());
        assert!(serde_json::from_str::<ClientTaskListQuery>(r#"{"limit":"5"}"#).is_ok());
        for attack in [
            r#"{"status":"TODO"}"#,
            r#"{"project_id":"x"}"#,
            r#"{"sort":"title"}"#,
        ] {
            assert!(
                serde_json::from_str::<ClientTaskListQuery>(attack).is_err(),
                "ClientTaskListQuery accepted `{attack}`"
            );
        }
    }

    #[test]
    fn due_dates_use_the_same_iso_wire_format_as_projects() {
        let request: CreateTaskRequest = serde_json::from_str(
            r#"{"project_id":"00000000-0000-7000-8000-000000000001","title":"t","due_date":"2024-03-01"}"#,
        )
        .expect("a request with an ISO date");
        assert_eq!(
            request.due_date,
            Date::from_calendar_date(2024, time::Month::March, 1).ok()
        );

        let json = serde_json::to_value(fully_populated_client_task()).expect("serialise");
        assert_eq!(json["due_date"], serde_json::json!("2024-03-01"));

        for bad in [r#""01/03/2024""#, r#""2024-02-31""#, "0"] {
            let body = format!(
                r#"{{"project_id":"00000000-0000-7000-8000-000000000001","title":"t","due_date":{bad}}}"#
            );
            assert!(
                serde_json::from_str::<CreateTaskRequest>(&body).is_err(),
                "accepted a malformed date {bad}"
            );
        }
    }

    #[test]
    fn absent_and_explicitly_null_due_dates_are_different() {
        let absent: UpdateTaskRequest = serde_json::from_str(r#"{"version":1}"#).expect("absent");
        assert_eq!(absent.due_date, None);
        let cleared: UpdateTaskRequest =
            serde_json::from_str(r#"{"version":1,"due_date":null}"#).expect("null");
        assert_eq!(cleared.due_date, Some(None));
    }

    // ---- status transitions and completion coherence ------------------------

    #[test]
    fn status_parsing_is_exact_and_closed() {
        for s in TaskStatus::ALLOWED {
            assert_eq!(TaskStatus::parse(s).map(|t| t.as_str()), Some(*s));
        }
        for bad in [
            "todo",
            "IN PROGRESS",
            "DELETED",
            "",
            "DONE; DROP TABLE tasks",
        ] {
            assert_eq!(TaskStatus::parse(bad), None, "accepted `{bad}`");
        }
        for p in TaskPriority::ALLOWED {
            assert_eq!(TaskPriority::parse(p).map(|t| t.as_str()), Some(*p));
        }
        assert_eq!(TaskPriority::parse("CRITICAL"), None);
    }

    #[test]
    fn cancelled_is_terminal() {
        use TaskStatus::*;
        for next in [Todo, InProgress, Blocked, Done] {
            assert!(
                !Cancelled.can_transition_to(next),
                "a cancelled task escaped into {next:?}"
            );
        }
        assert!(Cancelled.can_transition_to(Cancelled));
    }

    #[test]
    fn finished_work_can_be_reopened_but_not_retroactively_cancelled() {
        use TaskStatus::*;
        assert!(Done.can_transition_to(InProgress));
        assert!(Done.can_transition_to(Todo));
        assert!(
            !Done.can_transition_to(Cancelled),
            "it was done; that is a fact"
        );
        assert!(!Done.can_transition_to(Blocked));
    }

    #[test]
    fn ordinary_task_transitions_are_permitted() {
        use TaskStatus::*;
        for from in [Todo, InProgress, Blocked] {
            for to in [Todo, InProgress, Blocked, Done, Cancelled] {
                assert!(
                    from.can_transition_to(to),
                    "{from:?} -> {to:?} should be an ordinary move"
                );
            }
        }
    }

    /// The database enforces `(status = 'DONE') = (completed_at IS NOT NULL)`. Any
    /// disagreement between this function and that constraint is a 500 in
    /// production, so the correspondence is asserted for every status.
    #[test]
    fn completed_at_is_set_exactly_when_the_status_is_done() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let earlier = now - time::Duration::days(1);

        assert_eq!(TaskStatus::Done.completed_at_for(None, now), Some(now));
        // An already-finished task keeps its original completion instant.
        assert_eq!(
            TaskStatus::Done.completed_at_for(Some(earlier), now),
            Some(earlier)
        );

        for status in [
            TaskStatus::Todo,
            TaskStatus::InProgress,
            TaskStatus::Blocked,
            TaskStatus::Cancelled,
        ] {
            assert_eq!(
                status.completed_at_for(Some(earlier), now),
                None,
                "{status:?} must clear completed_at, or the CHECK constraint fires"
            );
            assert_eq!(status.completed_at_for(None, now), None);
        }
    }

    /// Stated as the constraint itself, over every status, so the two can never
    /// drift apart in a way a reviewer has to reason about.
    #[test]
    fn the_completion_invariant_holds_for_every_status() {
        let now = OffsetDateTime::UNIX_EPOCH;
        for raw in TaskStatus::ALLOWED {
            let status = TaskStatus::parse(raw).expect("catalogue status");
            for existing in [None, Some(now - time::Duration::hours(3))] {
                let derived = status.completed_at_for(existing, now);
                assert_eq!(
                    status == TaskStatus::Done,
                    derived.is_some(),
                    "(status = 'DONE') = (completed_at IS NOT NULL) violated for {raw}"
                );
            }
        }
    }
}
