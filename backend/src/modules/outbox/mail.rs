//! Outbound mail behind a trait.
//!
//! The production provider is `SmtpProvider` — SMTP over TLS and nothing else.
//! Alongside it are three development implementations, and the rule they all obey
//! is that none of them ever pretends a message was delivered: one records that a
//! message was due, one writes it to disk for a developer to read, and one refuses
//! outright. `Config::validate_production`
//! already refuses to start production with either development sink selected.
//!
//! The security property that shapes every implementation: **a password-reset or
//! invitation message body contains a single-use bearer token.** Whoever reads the
//! body can take over the account. Logs are the widest-read, longest-lived,
//! least-access-controlled store in most deployments, so the body and the subject
//! are never written to one. See `docs/backend/02-threat-model.md` TH-35.

use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use crate::platform::config::{MailProviderKind, SmtpConfig};
use crate::platform::observability::sanitize;

/// What a message is for. A closed enum rather than a string, so a provider can
/// safely log *which kind* of message it handled without any risk that the label
/// carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailKind {
    PasswordReset,
    Invitation,
}

impl MailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MailKind::PasswordReset => "PASSWORD_RESET",
            MailKind::Invitation => "INVITATION",
        }
    }
}

/// One message ready to hand to a provider.
///
/// `subject` and `body_text` are treated as secret-bearing throughout. There is no
/// `Debug`-safe rendering of them and, notably, **no `#[derive(Debug)]`** on this
/// struct that would print them: an accidental `tracing::debug!(?mail)` in a future
/// handler would otherwise put a live reset token in the log stream. `Debug` is
/// implemented by hand below to redact.
#[derive(Clone)]
pub struct OutboundMail {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub kind: MailKind,
}

impl std::fmt::Debug for OutboundMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundMail")
            .field("kind", &self.kind.as_str())
            .field("to_domain", &recipient_domain(&self.to))
            .field("subject", &"<redacted>")
            .field("body_text", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// No provider is wired up. Returned by `DisabledProvider`, which is the
    /// production default until a real provider exists.
    #[error("no mail provider is configured")]
    ProviderNotConfigured,

    /// The address is structurally unusable. Retrying cannot fix it.
    #[error("the recipient address is not usable")]
    InvalidRecipient,

    /// The provider could not deliver right now. May succeed on a retry.
    #[error("mail transport failed: {0}")]
    Transport(&'static str),
}

impl MailError {
    /// A fixed label per variant.
    ///
    /// Every string a provider produces is a compile-time constant, so nothing
    /// derived from the recipient, the subject or the body can ever reach a log
    /// line or the outbox's `last_error` column through this path.
    pub fn label(&self) -> &'static str {
        match self {
            MailError::ProviderNotConfigured => "provider_not_configured",
            MailError::InvalidRecipient => "invalid_recipient",
            MailError::Transport(_) => "transport",
        }
    }

    /// Whether a retry could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        match self {
            // Retryable on purpose. The provider is chosen by configuration, so a
            // redeploy can make this succeed; exhausting the attempt budget and
            // dead-lettering loudly is a better outcome than silently discarding a
            // password reset on the first try.
            MailError::ProviderNotConfigured => true,
            MailError::InvalidRecipient => false,
            MailError::Transport(_) => true,
        }
    }
}

#[async_trait]
pub trait MailProvider: Send + Sync {
    async fn send(&self, message: &OutboundMail) -> Result<(), MailError>;

    /// A stable, non-secret identifier for this provider, used in start-up logs and
    /// in the readiness payload so an operator can see which sink is active.
    fn name(&self) -> &'static str;
}

/// The domain part of an address, and nothing else.
///
/// The local part is the personally identifying half — it is frequently the
/// person's real name, and on its own it is enough to enumerate accounts from a log
/// export. The domain is enough to answer the only operational question a log needs
/// to answer ("are we failing to deliver to one tenant or to everyone?"), so that
/// is all that is ever emitted.
///
/// The *last* `@` separates local part from domain, because the local part may
/// legitimately contain a quoted `@`.
pub fn recipient_domain(address: &str) -> &str {
    match address.rsplit_once('@') {
        Some((_local, domain)) if !domain.is_empty() => domain,
        // No `@`, or an empty domain. Returning a constant rather than the input
        // guarantees a malformed address cannot smuggle the whole string into a log
        // under a field named "domain".
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// LogSinkProvider
// ---------------------------------------------------------------------------

/// Records that a message was due, without recording what it said.
///
/// It logs three things and only three things: the kind, the recipient's domain,
/// and a freshly generated message id. It must **never** log `body_text` or
/// `subject` — both carry the single-use token that grants account access, and a
/// log line is not a place a bearer credential can be recalled from.
pub struct LogSinkProvider;

#[async_trait]
impl MailProvider for LogSinkProvider {
    async fn send(&self, message: &OutboundMail) -> Result<(), MailError> {
        // A per-message id so a developer can correlate "the flow said it sent
        // something" with "the sink saw something", without either end needing the
        // content.
        let message_id = Uuid::now_v7();
        tracing::info!(
            mail.provider = self.name(),
            mail.kind = message.kind.as_str(),
            // Sanitised even though it is only a domain: an address arriving from a
            // path that skipped validation could still carry a CR/LF and forge a log
            // record (TH-32).
            mail.recipient_domain = %sanitize::log_value(recipient_domain(&message.to)),
            mail.message_id = %message_id,
            "development mail sink accepted a message; subject and body are deliberately not logged"
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "dev_sink"
    }
}

// ---------------------------------------------------------------------------
// FileSinkProvider
// ---------------------------------------------------------------------------

/// Writes the complete message — including the live token — to a file.
///
/// **This writes secrets to disk in plaintext and is development-only.** It exists
/// so a developer can complete a password-reset flow locally without a mail server.
/// Production refuses to start with it selected (`Config::validate_production`).
/// The directory should be inside a container or a scratch path that is not backed
/// up.
pub struct FileSinkProvider {
    directory: String,
}

impl FileSinkProvider {
    pub fn new(directory: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Full RFC-822-ish rendering. Only ever written to the file, never logged.
    fn render(message: &OutboundMail, message_id: Uuid) -> String {
        format!(
            "X-RoleBlank-Message-Id: {message_id}\n\
             X-RoleBlank-Kind: {kind}\n\
             To: {to}\n\
             Subject: {subject}\n\
             \n\
             {body}\n",
            kind = message.kind.as_str(),
            to = message.to,
            subject = message.subject,
            body = message.body_text,
        )
    }
}

#[async_trait]
impl MailProvider for FileSinkProvider {
    async fn send(&self, message: &OutboundMail) -> Result<(), MailError> {
        let message_id = Uuid::now_v7();
        // The file name is a UUID we generate, never anything derived from the
        // recipient: a filename built from an address is a path-traversal primitive
        // (`../../etc/cron.d/x@evil`) and a way to leak the address to anyone who
        // can list the directory.
        let path = PathBuf::from(&self.directory).join(format!("{message_id}.txt"));
        let contents = Self::render(message, message_id);

        // `tokio`'s `fs` feature is not enabled for this crate, and enabling it for
        // a development-only sink is not justified. Blocking file I/O is therefore
        // moved onto the blocking pool rather than run inline: a stalled disk would
        // otherwise block a runtime worker thread and stall unrelated tasks.
        let write_result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, contents)
        })
        .await;

        match write_result {
            Ok(Ok(())) => {
                tracing::info!(
                    mail.provider = self.name(),
                    mail.kind = message.kind.as_str(),
                    mail.recipient_domain = %sanitize::log_value(recipient_domain(&message.to)),
                    mail.message_id = %message_id,
                    "development mail file sink wrote a message to disk"
                );
                Ok(())
            }
            Ok(Err(e)) => {
                // Only the `io::ErrorKind` label is kept. The `Display` form of an
                // io error contains the full path, which here contains the mail
                // directory and would be echoed into `outbox_events.last_error`.
                tracing::warn!(kind = ?e.kind(), "mail file sink could not write the message");
                Err(MailError::Transport("file sink write failed"))
            }
            // The blocking task panicked or was cancelled. Treated as transport so
            // the outbox retries rather than dead-lettering a deliverable message.
            Err(_) => Err(MailError::Transport("file sink task did not complete")),
        }
    }

    fn name(&self) -> &'static str {
        "dev_file"
    }
}

// ---------------------------------------------------------------------------
// DisabledProvider
// ---------------------------------------------------------------------------

/// Refuses every message.
///
/// This is the production default, and it is the *correct* production default
/// while no real provider exists. The alternative — accepting the message and
/// returning `Ok` — would report a successful password reset to a user who will
/// never receive the email, locking them out with no signal anywhere. Failing
/// loudly puts the failure in the outbox, in the logs, and eventually in a
/// dead-letter row an operator can see. The brief forbids fake email success.
pub struct DisabledProvider;

#[async_trait]
impl MailProvider for DisabledProvider {
    async fn send(&self, message: &OutboundMail) -> Result<(), MailError> {
        tracing::warn!(
            mail.provider = self.name(),
            mail.kind = message.kind.as_str(),
            mail.recipient_domain = %sanitize::log_value(recipient_domain(&message.to)),
            "mail was requested but no provider is configured; the message was NOT delivered"
        );
        Err(MailError::ProviderNotConfigured)
    }

    fn name(&self) -> &'static str {
        "disabled"
    }
}

/// The production transport: SMTP over TLS.
///
/// Two properties this type is responsible for, both of which are the sort of thing
/// that fails silently if got wrong:
///
/// 1. **Credentials never cross the wire in clear text.** Either TLS is established
///    before the first byte (implicit, port 465), or STARTTLS is *required* before
///    authenticating (port 587). `lettre`'s `starttls_relay` builder rejects a
///    server that does not offer STARTTLS rather than continuing unencrypted, which
///    is the difference between required and opportunistic.
/// 2. **A failure is reported as a failure.** Every error becomes a retryable
///    `Transport` — except a malformed address, which no amount of retrying fixes —
///    so the outbox retries and eventually dead-letters loudly. Nothing here can
///    report success for a message that was not accepted by the server.
///
/// The connection pool lives in `AsyncSmtpTransport`, so one instance is shared by
/// the whole worker rather than reconnecting per message.
pub struct SmtpProvider {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl SmtpProvider {
    /// Build the transport, or explain why it could not be built.
    ///
    /// Returns `Err` with a non-secret reason. The caller turns that into a startup
    /// failure: a mail transport that cannot be constructed must stop the process,
    /// not degrade into a sink that quietly drops invitations.
    pub fn new(config: &SmtpConfig) -> Result<Self, String> {
        let from: lettre::message::Mailbox = config
            .from
            .parse()
            .map_err(|_| format!("RB_SMTP_FROM is not a valid address: {}", config.from))?;

        let credentials = lettre::transport::smtp::authentication::Credentials::new(
            config.username.clone(),
            config.password.expose().clone(),
        );

        let builder = if config.implicit_tls {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&config.host)
        } else {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&config.host)
        }
        .map_err(|e| format!("could not build the SMTP transport: {e}"))?;

        Ok(Self {
            transport: builder
                .port(config.port)
                .credentials(credentials)
                .timeout(Some(std::time::Duration::from_secs(15)))
                .build(),
            from,
        })
    }
}

#[async_trait]
impl MailProvider for SmtpProvider {
    async fn send(&self, message: &OutboundMail) -> Result<(), MailError> {
        use lettre::AsyncTransport;

        let to: lettre::message::Mailbox = message
            .to
            .parse()
            .map_err(|_| MailError::InvalidRecipient)?;

        let email = lettre::Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(message.subject.clone())
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(message.body_text.clone())
            .map_err(|_| MailError::InvalidRecipient)?;

        match self.transport.send(email).await {
            Ok(_) => {
                // Domain only, never the local part — the local part is frequently
                // the person's real name and is enough to enumerate accounts from a
                // log export.
                tracing::info!(
                    mail.provider = "smtp",
                    mail.kind = message.kind.as_str(),
                    mail.recipient_domain = %sanitize::log_value(recipient_domain(&message.to)),
                    "mail delivered"
                );
                Ok(())
            }
            Err(e) => {
                // The error text can carry the server's response, which may quote
                // the recipient address. Only the coarse class is logged, and the
                // error surfaced upward is a fixed string.
                tracing::warn!(
                    mail.provider = "smtp",
                    mail.kind = message.kind.as_str(),
                    mail.recipient_domain = %sanitize::log_value(recipient_domain(&message.to)),
                    mail.permanent = e.is_permanent(),
                    "SMTP delivery failed"
                );
                if e.is_permanent() {
                    Err(MailError::InvalidRecipient)
                } else {
                    Err(MailError::Transport("smtp delivery failed"))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "smtp"
    }
}

/// Build the configured provider.
///
/// Returns `Arc<dyn ...>` rather than a concrete type so the worker, the services
/// and the tests all share one instance and one abstraction; swapping in a real
/// SMTP provider later is a change to this function and nothing else.
pub fn build(kind: &MailProviderKind) -> Arc<dyn MailProvider> {
    match kind {
        MailProviderKind::DevSink => Arc::new(LogSinkProvider),
        MailProviderKind::DevFile { directory } => {
            Arc::new(FileSinkProvider::new(directory.clone()))
        }
        MailProviderKind::Disabled => Arc::new(DisabledProvider),
        MailProviderKind::Smtp(smtp) => match SmtpProvider::new(smtp) {
            Ok(provider) => Arc::new(provider),
            Err(reason) => {
                // Reached only if configuration validation passed and the transport
                // still could not be built. Falling back to `DisabledProvider` keeps
                // the failure loud — every message errors and the outbox retries —
                // rather than silently discarding mail.
                tracing::error!(
                    reason = %reason,
                    "SMTP transport could not be constructed; mail will NOT be delivered"
                );
                Arc::new(DisabledProvider)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "rb_reset_7Qw9ZmK2pL5vR8tYnE4hJ6cD1sG0aB3x";

    fn smtp() -> SmtpConfig {
        SmtpConfig {
            host: "smtp.example.com".into(),
            port: 465,
            implicit_tls: true,
            username: "no-reply@example.com".into(),
            password: crate::shared::secret::Secret::new("hunter2".into()),
            from: "RoleBlank <no-reply@example.com>".into(),
        }
    }

    /// A transport that cannot be constructed must say so, not degrade quietly.
    #[test]
    fn an_unusable_sender_address_is_refused_at_construction() {
        let mut config = smtp();
        config.from = "not an address".into();
        let error = match SmtpProvider::new(&config) {
            Err(e) => e,
            Ok(_) => panic!("an invalid sender address was accepted"),
        };
        assert!(error.contains("RB_SMTP_FROM"), "{error}");
    }

    /// Both TLS modes must build. STARTTLS is the one that could silently degrade to
    /// plaintext if the wrong builder were used, so it is named explicitly here.
    #[test]
    fn both_tls_modes_build_a_transport() {
        assert!(SmtpProvider::new(&smtp()).is_ok());
        let mut starttls = smtp();
        starttls.implicit_tls = false;
        starttls.port = 587;
        assert!(SmtpProvider::new(&starttls).is_ok());
    }

    /// The SMTP configuration holds a password. It must never render it, and the
    /// `Secret` wrapper must not be defeated by deriving `Debug` on the outer type.
    #[test]
    fn the_smtp_configuration_never_renders_its_credentials() {
        let rendered = format!("{:?}", smtp());
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("no-reply@example.com") || rendered.contains("<redacted>"));
        assert!(rendered.contains("smtp.example.com"));
    }

    fn reset_mail(to: &str) -> OutboundMail {
        OutboundMail {
            to: to.to_string(),
            subject: "Reset your password".to_string(),
            body_text: format!("Open https://os.example.com/reset?token={TOKEN} to continue."),
            kind: MailKind::PasswordReset,
        }
    }

    // ---- redaction -------------------------------------------------------

    /// The helper every provider funnels its logging through. If this leaks, every
    /// provider leaks.
    #[test]
    fn only_the_domain_of_an_address_is_ever_exposed() {
        assert_eq!(recipient_domain("alice@example.com"), "example.com");
        // The local part must never appear in the output, in any form.
        assert!(!recipient_domain("alice@example.com").contains("alice"));
        // Sub-addressing and dots in the local part.
        assert_eq!(
            recipient_domain("first.last+tag@corp.example.co.uk"),
            "corp.example.co.uk"
        );
        // A quoted local part containing `@`: the *last* `@` is the separator.
        assert_eq!(
            recipient_domain("\"weird@local\"@example.com"),
            "example.com"
        );
    }

    #[test]
    fn a_malformed_address_cannot_smuggle_itself_into_a_domain_field() {
        for bad in ["", "no-at-sign", "trailing@", "@", "alice@"] {
            assert_eq!(
                recipient_domain(bad),
                "unknown",
                "`{bad}` should not have produced a domain"
            );
        }
    }

    /// Combined with `log_value`, a forged-log-record attempt in the address is
    /// neutralised before it reaches a log line.
    #[test]
    fn a_crlf_in_the_domain_cannot_forge_a_log_record() {
        let logged = sanitize::log_value(recipient_domain(
            "alice@example.com\r\n{\"level\":\"INFO\",\"msg\":\"reset approved\"}",
        ));
        assert!(!logged.contains('\n'));
        assert!(!logged.contains('\r'));
    }

    /// The `Debug` impl is the other place a token could escape — an
    /// `error!(?mail)` anywhere in a handler.
    #[test]
    fn debug_formatting_redacts_the_token_and_the_local_part() {
        let rendered = format!("{:?}", reset_mail("alice@example.com"));
        assert!(
            !rendered.contains(TOKEN),
            "the token leaked through Debug: {rendered}"
        );
        assert!(
            !rendered.contains("alice"),
            "the local part leaked through Debug: {rendered}"
        );
        assert!(
            !rendered.contains("Reset your password"),
            "the subject leaked: {rendered}"
        );
        assert!(rendered.contains("example.com"));
        assert!(rendered.contains("PASSWORD_RESET"));
    }

    // ---- log sink --------------------------------------------------------

    #[tokio::test]
    async fn the_log_sink_accepts_a_message_and_reports_success() {
        let p = LogSinkProvider;
        assert_eq!(p.name(), "dev_sink");
        assert!(p.send(&reset_mail("alice@example.com")).await.is_ok());
    }

    /// The sink's entire logging surface is `kind`, `recipient_domain(..)` and a
    /// generated UUID. None of the three can contain the token or the local part —
    /// asserted here on the values themselves, since the tracing output is not
    /// capturable without installing a global subscriber that would then be shared
    /// with every other test in the binary.
    #[test]
    fn the_log_sinks_field_values_contain_neither_token_nor_local_part() {
        let mail = reset_mail("alice@example.com");
        let fields = [
            mail.kind.as_str().to_string(),
            sanitize::log_value(recipient_domain(&mail.to)),
            Uuid::now_v7().to_string(),
        ];
        for field in fields {
            assert!(!field.contains(TOKEN), "field `{field}` carries the token");
            assert!(
                !field.contains("alice"),
                "field `{field}` carries the local part"
            );
            assert!(
                !field.contains("Reset your password"),
                "field `{field}` carries the subject"
            );
        }
    }

    // ---- disabled --------------------------------------------------------

    #[tokio::test]
    async fn the_disabled_provider_always_fails_and_never_reports_success() {
        let p = DisabledProvider;
        assert_eq!(p.name(), "disabled");
        for kind in [MailKind::PasswordReset, MailKind::Invitation] {
            let mut mail = reset_mail("alice@example.com");
            mail.kind = kind;
            let err = p
                .send(&mail)
                .await
                .expect_err("the disabled provider must never succeed");
            assert!(matches!(err, MailError::ProviderNotConfigured));
            assert_eq!(err.label(), "provider_not_configured");
        }
        // Repeated calls stay failed — there is no "first one is free" path.
        for _ in 0..10 {
            assert!(p.send(&reset_mail("bob@example.com")).await.is_err());
        }
    }

    // ---- file sink -------------------------------------------------------

    fn scratch_dir() -> PathBuf {
        // A fresh, unguessable subdirectory per test run so parallel tests cannot
        // read each other's files or collide on a name.
        std::env::temp_dir().join(format!("roleblank-mail-test-{}", Uuid::now_v7()))
    }

    #[tokio::test]
    async fn the_file_sink_creates_its_directory_and_round_trips_the_message() {
        let dir = scratch_dir();
        assert!(
            !dir.exists(),
            "precondition: the directory must not exist yet"
        );

        let p = FileSinkProvider::new(dir.to_string_lossy().to_string());
        assert_eq!(p.name(), "dev_file");
        let mail = reset_mail("alice@example.com");
        p.send(&mail)
            .await
            .expect("the file sink should write the message");

        let entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("the directory should have been created")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one message file should exist");

        let path = entries[0].path();
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("txt"));
        // The filename is a UUID, not the address.
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        assert!(
            Uuid::parse_str(stem).is_ok(),
            "filename `{stem}` is not a UUID"
        );
        assert!(!stem.contains("alice"));

        let contents = std::fs::read_to_string(&path).expect("the file should be readable");
        assert!(contents.contains("alice@example.com"));
        assert!(contents.contains("Subject: Reset your password"));
        // The whole point of this sink: the developer can read the live token.
        assert!(contents.contains(TOKEN));
        assert!(contents.contains("X-RoleBlank-Kind: PASSWORD_RESET"));
        // Headers and body are separated by a blank line.
        assert!(contents.contains("\n\n"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_file_sink_writes_one_file_per_message() {
        let dir = scratch_dir();
        let p = FileSinkProvider::new(dir.to_string_lossy().to_string());
        for i in 0..5 {
            let mut mail = reset_mail(&format!("user{i}@example.com"));
            mail.kind = MailKind::Invitation;
            p.send(&mail).await.expect("write should succeed");
        }
        let count = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(count, 5, "each message must get its own file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unwritable directory must surface as a retryable transport error carrying
    /// only a fixed label — never the path, which names the mail directory.
    #[tokio::test]
    async fn the_file_sink_reports_a_write_failure_without_leaking_the_path() {
        // Point the sink at a path whose parent is a *file*, which cannot be turned
        // into a directory on any platform.
        let blocker = std::env::temp_dir().join(format!("roleblank-blocker-{}", Uuid::now_v7()));
        std::fs::write(&blocker, b"not a directory").expect("test setup");
        let p = FileSinkProvider::new(blocker.join("sub").to_string_lossy().to_string());

        let err = p
            .send(&reset_mail("alice@example.com"))
            .await
            .expect_err("writing under a regular file must fail");
        assert_eq!(err.label(), "transport");
        assert!(err.is_retryable());
        let rendered = err.to_string();
        assert!(
            !rendered.contains("roleblank-blocker"),
            "the path leaked: {rendered}"
        );
        assert!(
            !rendered.contains("alice"),
            "the recipient leaked: {rendered}"
        );

        let _ = std::fs::remove_file(&blocker);
    }

    // ---- factory ---------------------------------------------------------

    #[test]
    fn the_factory_maps_every_configured_kind() {
        assert_eq!(build(&MailProviderKind::DevSink).name(), "dev_sink");
        assert_eq!(
            build(&MailProviderKind::DevFile {
                directory: "/tmp/x".into()
            })
            .name(),
            "dev_file"
        );
        assert_eq!(build(&MailProviderKind::Disabled).name(), "disabled");
        assert_eq!(
            build(&MailProviderKind::Smtp(Box::new(smtp()))).name(),
            "smtp"
        );
    }

    #[test]
    fn error_labels_are_fixed_and_carry_no_content() {
        assert_eq!(
            MailError::ProviderNotConfigured.label(),
            "provider_not_configured"
        );
        assert_eq!(MailError::InvalidRecipient.label(), "invalid_recipient");
        assert_eq!(MailError::Transport("x").label(), "transport");
        assert!(!MailError::InvalidRecipient.is_retryable());
        assert!(MailError::Transport("x").is_retryable());
    }
}
