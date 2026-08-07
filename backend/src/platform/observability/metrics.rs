//! A small, self-contained Prometheus metrics registry.
//!
//! **Why hand-rolled rather than a metrics crate.** The whole registry is ~150
//! lines of atomics and a formatter. Pulling in `metrics` + `metrics-exporter-
//! prometheus` (or `prometheus`) adds a transitive dependency tree, a global
//! recorder installed by side effect, and — the part that actually matters here —
//! a generic label API that accepts any `&str` from any call site. This module
//! deliberately offers *no* API that can accept an arbitrary label, so the
//! cardinality bound below is a property of the type signatures rather than a
//! convention someone has to remember. Fewer dependencies on the audit surface of
//! a security-sensitive service is a bonus, not the reason.
//!
//! **The two invariants this module exists to enforce:**
//!
//! 1. *Label cardinality is bounded.* Every distinct label combination is a live
//!    time series held in memory here and, worse, forever in the scraper's
//!    storage. A route label taken from the concrete request path
//!    (`/api/v1/projects/6f9a…`) creates one series per project — an attacker who
//!    can issue requests to non-existent ids then grows the process's memory
//!    without bound. That is a denial of service delivered through the metrics
//!    endpoint (TH-33). Only *route patterns* are accepted, they are validated,
//!    and the total series count is hard-capped. Every other label in this file is
//!    drawn from a closed set of `&'static str`s.
//! 2. *No principal identifier is ever a label.* No user id, no email, no session
//!    id, no token. `/metrics` is an operational endpoint that is routinely
//!    scraped by infrastructure with far weaker access control than the API
//!    itself; anything put here should be assumed to be readable by everyone with
//!    access to the monitoring stack. There is deliberately no method on `Metrics`
//!    that takes a `Uuid` or an email, and a test asserts the rendered output
//!    contains neither an `@` nor a UUID.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

/// Metric name prefix. A single namespace so an operator can find everything this
/// service emits with one prefix match.
const NS: &str = "roleblank";

/// Fixed latency buckets in milliseconds.
///
/// Fixed rather than configurable: buckets are part of the recording rule and
/// dashboard contract, and a bucket set that differs between two deployments makes
/// their histograms un-mergeable. The spread is roughly logarithmic because
/// latency distributions are, and the top bucket sits at the request timeout's
/// order of magnitude so a saturated service is visible rather than lost in
/// `+Inf`.
pub const LATENCY_BUCKETS_MS: [u64; 10] = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

/// Maximum number of distinct `http_requests_total` series.
///
/// A realistic API has on the order of (routes × methods × status classes) series;
/// a few hundred. 1000 leaves generous headroom while still being a hard ceiling.
pub const MAX_HTTP_SERIES: usize = 1000;

/// Longest accepted route pattern. A pattern longer than this is not a pattern.
const MAX_ROUTE_LEN: usize = 120;

/// Substituted for anything that fails route-pattern validation. Its presence in
/// the output is itself the alert: it means a call site passed a concrete path.
const UNPATTERNED_ROUTE: &str = "__unpatterned__";

/// Substituted once the series cap is reached, so counts are still *totalled*
/// rather than silently dropped.
const OVERFLOW_ROUTE: &str = "__cardinality_capped__";

/// The closed set of authorisation-denial reasons.
///
/// These mirror `authorization::domain::Decision::reason()`, which returns a
/// `&'static str` from a closed enum — so the values arriving at `authz_denial`
/// are already bounded today. The allowlist is applied anyway, because the method
/// signature takes `&str` and a future call site could pass a formatted string
/// containing a permission code or a scope fragment derived from request input.
/// That would be the unbounded-cardinality vector of invariant 1, arriving through
/// a side door. Anything unrecognised is folded into `other`, so this family is
/// exactly `AUTHZ_DENIAL_REASONS.len()` series forever, whatever a caller does.
///
/// The breakdown is worth keeping rather than collapsing to a bare total: a spike
/// in `no_grant` is a misconfigured role, while a spike in `unknown_permission`
/// means somebody is enumerating the authorisation surface. Those need different
/// people woken up.
const AUTHZ_DENIAL_REASONS: [&str; 6] = [
    "unknown_permission",
    "principal_envelope",
    "explicit_deny",
    "no_grant",
    "out_of_scope",
    "other",
];

/// Index of the `other` bucket — the last entry, by construction.
const AUTHZ_OTHER_INDEX: usize = AUTHZ_DENIAL_REASONS.len() - 1;

/// A bounded, fully validated label set. Constructing one is the only way to reach
/// the counter map, which is what makes the cardinality bound structural.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HttpSeries {
    /// One of a fixed list of `&'static str`s — never the raw request method.
    method: &'static str,
    /// A validated route *pattern*.
    route: String,
    /// `1xx`..`5xx`. The exact status is not a label: 500 distinct codes × routes
    /// is the cardinality explosion this module exists to prevent, and alerting is
    /// written against classes anyway.
    class: &'static str,
}

/// A latency histogram with the fixed buckets above.
///
/// Deliberately **unlabelled**. A per-route histogram is (routes × 11) series and
/// is the single most common way a metrics endpoint becomes the memory hog; if
/// per-route latency is needed later it should be added as an explicit, separately
/// capped registry rather than by loosening this one.
#[derive(Debug)]
struct Histogram {
    /// Non-cumulative counts; `render` accumulates them. Storing non-cumulative
    /// means one atomic increment per observation instead of `N`.
    buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; LATENCY_BUCKETS_MS.len()],
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, millis: u64) {
        // `count` is incremented *before* the bucket so that a concurrent `render`
        // can never observe a bucket total exceeding `count`, which would render a
        // non-monotonic `le` sequence and make the histogram invalid to a scraper.
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(millis, Ordering::Relaxed);
        // Linear scan over ten elements: cheaper than a binary search at this size
        // and obviously correct.
        for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if millis <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Above the last bound: counted only in `+Inf`, which is `count`.
    }
}

#[derive(Debug)]
pub struct Metrics {
    http_requests: RwLock<HashMap<HttpSeries, AtomicU64>>,
    /// Latched so the "you have blown the cardinality budget" alarm is raised once
    /// rather than on every subsequent request.
    cardinality_alarm_raised: AtomicBool,
    latency: Histogram,
    auth_failures: AtomicU64,
    /// One counter per entry in `AUTHZ_DENIAL_REASONS`. A fixed-size array rather
    /// than a map, so the family's cardinality is decided at compile time.
    authz_denials: [AtomicU64; AUTHZ_DENIAL_REASONS.len()],
    rate_limit_events: AtomicU64,
    outbox_failures: AtomicU64,
    audit_events_written: AtomicU64,
    db_pool_size: AtomicU64,
    db_pool_idle: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            http_requests: RwLock::new(HashMap::new()),
            cardinality_alarm_raised: AtomicBool::new(false),
            latency: Histogram::new(),
            auth_failures: AtomicU64::new(0),
            authz_denials: [const { AtomicU64::new(0) }; AUTHZ_DENIAL_REASONS.len()],
            rate_limit_events: AtomicU64::new(0),
            outbox_failures: AtomicU64::new(0),
            audit_events_written: AtomicU64::new(0),
            db_pool_size: AtomicU64::new(0),
            db_pool_idle: AtomicU64::new(0),
        }
    }

    // ---- recording ---------------------------------------------------------

    /// Record one finished HTTP request.
    ///
    /// `route_pattern` **must** be the matched route template
    /// (`/api/v1/projects/{id}`), which axum exposes via `MatchedPath` and which
    /// `routes::ROUTE_TABLE` is unit-tested to contain. Passing the concrete URI is
    /// not merely discouraged — it is detected and folded into a single
    /// `__unpatterned__` series, because the alternative is unbounded memory growth
    /// driven by request input.
    pub fn http_request(&self, method: &str, route_pattern: &str, status: u16) {
        let series = HttpSeries {
            method: normalise_method(method),
            route: normalise_route(route_pattern),
            class: status_class(status),
        };
        self.increment_series(series);
    }

    /// Record a request's total handling time.
    pub fn latency(&self, elapsed: Duration) {
        // `as_millis` is u128; a duration that does not fit in u64 milliseconds is
        // ~584 million years, but it is saturated rather than cast, because a
        // wrapping cast here would land the observation in the wrong bucket.
        let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.latency.observe(millis);
    }

    /// Directly observe a millisecond value. Exposed for callers that already have
    /// a measurement, and for tests.
    pub fn latency_ms(&self, millis: u64) {
        self.latency.observe(millis);
    }

    pub fn auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an authorisation denial, bucketed by reason.
    ///
    /// `reason` is matched against `AUTHZ_DENIAL_REASONS` and anything unrecognised
    /// lands in `other`. The string is never used as a label directly — see the
    /// comment on that constant for the failure that prevents.
    pub fn authz_denial(&self, reason: &str) {
        let index = AUTHZ_DENIAL_REASONS
            .iter()
            .position(|known| *known == reason)
            // `position` can find `other` itself, which is harmless and correct.
            .unwrap_or(AUTHZ_OTHER_INDEX);
        self.authz_denials[index].fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limit_event(&self) {
        self.rate_limit_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn outbox_failure(&self) {
        self.outbox_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn audit_written(&self) {
        self.audit_events_written.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the pool gauges. Called from the metrics handler rather than on a
    /// timer, so there is no background task to leak.
    pub fn db_pool(&self, size: u32, idle: usize) {
        self.db_pool_size.store(u64::from(size), Ordering::Relaxed);
        // `usize` -> `u64` is lossless on every target this builds for, and a pool
        // cannot have more idle connections than `u32::MAX` anyway.
        self.db_pool_idle.store(idle as u64, Ordering::Relaxed);
    }

    /// Number of live `http_requests_total` series. Exposed for the cap test and
    /// for an operator sanity check.
    pub fn http_series_count(&self) -> usize {
        self.read_series().len()
    }

    fn increment_series(&self, series: HttpSeries) {
        // Fast path: the series already exists, so a shared read lock plus one
        // relaxed atomic add is enough. Under steady state every request takes
        // this path, so the write lock is not on the hot path.
        {
            let map = self.read_series();
            if let Some(counter) = map.get(&series) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let mut map = match self.http_requests.write() {
            Ok(g) => g,
            // A poisoned lock means a panic happened while the map was mutable.
            // Metrics must never be the reason a request fails, so the poison is
            // recovered from rather than propagated; the panic itself is already
            // an alarm elsewhere.
            Err(poisoned) => {
                tracing::error!("metrics registry lock was poisoned; recovering");
                poisoned.into_inner()
            }
        };

        // Re-check under the write lock: another thread may have inserted between
        // dropping the read guard and taking the write guard.
        if !map.contains_key(&series) && map.len() >= MAX_HTTP_SERIES {
            if !self.cardinality_alarm_raised.swap(true, Ordering::Relaxed) {
                tracing::error!(
                    series = map.len(),
                    "http metric cardinality cap reached; further label combinations are \
                     folded into a single overflow series. A route pattern is almost \
                     certainly being built from a concrete path."
                );
            }
            // Fold into one overflow series so totals stay correct even though the
            // breakdown is lost. This can add at most one entry beyond the cap.
            let overflow = HttpSeries {
                method: "OTHER",
                route: OVERFLOW_ROUTE.to_string(),
                class: "other",
            };
            map.entry(overflow)
                .or_default()
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        map.entry(series)
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }

    fn read_series(&self) -> std::sync::RwLockReadGuard<'_, HashMap<HttpSeries, AtomicU64>> {
        match self.http_requests.read() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::error!("metrics registry lock was poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }

    // ---- rendering ---------------------------------------------------------

    /// Render the Prometheus text exposition format (version 0.0.4).
    ///
    /// `write!` into a `String` is infallible, so the `Result` is discarded rather
    /// than unwrapped — this module must contain no panic path, because a panic in
    /// the metrics handler would be reachable by anyone who can scrape it.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        // --- http_requests_total --------------------------------------------
        let _ = writeln!(
            out,
            "# HELP {NS}_http_requests_total Total HTTP requests by method, route pattern and status class."
        );
        let _ = writeln!(out, "# TYPE {NS}_http_requests_total counter");
        {
            let map = self.read_series();
            // Sorted so the output is stable across scrapes and across process
            // restarts; an unstable ordering makes diffs between two scrapes
            // useless when debugging.
            let mut rows: Vec<(&HttpSeries, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.load(Ordering::Relaxed)))
                .collect();
            rows.sort_by(|a, b| {
                (a.0.route.as_str(), a.0.method, a.0.class).cmp(&(
                    b.0.route.as_str(),
                    b.0.method,
                    b.0.class,
                ))
            });
            for (series, value) in rows {
                let _ = writeln!(
                    out,
                    "{NS}_http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {}",
                    escape_label(series.method),
                    escape_label(&series.route),
                    escape_label(series.class),
                    value
                );
            }
        }

        // --- latency histogram ----------------------------------------------
        let _ = writeln!(
            out,
            "# HELP {NS}_http_request_duration_ms Request handling latency in milliseconds."
        );
        let _ = writeln!(out, "# TYPE {NS}_http_request_duration_ms histogram");
        let total = self.latency.count.load(Ordering::Relaxed);
        let mut cumulative = 0u64;
        for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative = cumulative.saturating_add(self.latency.buckets[i].load(Ordering::Relaxed));
            let _ = writeln!(
                out,
                "{NS}_http_request_duration_ms_bucket{{le=\"{bound}\"}} {cumulative}"
            );
        }
        // `+Inf` must be >= every other bucket or the histogram is invalid. Under
        // concurrent observation the loads above are not a consistent snapshot, so
        // the maximum is taken rather than trusting either value alone.
        let inf = cumulative.max(total);
        let _ = writeln!(
            out,
            "{NS}_http_request_duration_ms_bucket{{le=\"+Inf\"}} {inf}"
        );
        let _ = writeln!(
            out,
            "{NS}_http_request_duration_ms_sum {}",
            self.latency.sum_ms.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "{NS}_http_request_duration_ms_count {inf}");

        // --- authz_denials_total (labelled by a closed reason set) -----------
        let _ = writeln!(
            out,
            "# HELP {NS}_authz_denials_total Requests refused by the authorization evaluator, by reason."
        );
        let _ = writeln!(out, "# TYPE {NS}_authz_denials_total counter");
        for (i, reason) in AUTHZ_DENIAL_REASONS.iter().enumerate() {
            // Every reason is emitted even at zero. A series that only appears on
            // its first occurrence cannot be alerted on with `rate()`, because
            // there is no prior sample to compare against — the alert fires late,
            // exactly when it matters most.
            let _ = writeln!(
                out,
                "{NS}_authz_denials_total{{reason=\"{}\"}} {}",
                escape_label(reason),
                self.authz_denials[i].load(Ordering::Relaxed)
            );
        }

        // --- flat counters ---------------------------------------------------
        let counters: [(&str, &str, u64); 4] = [
            (
                "auth_failures_total",
                "Authentication attempts that failed, for any reason.",
                self.auth_failures.load(Ordering::Relaxed),
            ),
            (
                "rate_limit_events_total",
                "Requests refused by a rate limiter.",
                self.rate_limit_events.load(Ordering::Relaxed),
            ),
            (
                "outbox_failures_total",
                "Outbox deliveries that failed and were rescheduled or dead-lettered.",
                self.outbox_failures.load(Ordering::Relaxed),
            ),
            (
                "audit_events_written_total",
                "Audit chain entries appended.",
                self.audit_events_written.load(Ordering::Relaxed),
            ),
        ];
        for (name, help, value) in counters {
            let _ = writeln!(out, "# HELP {NS}_{name} {help}");
            let _ = writeln!(out, "# TYPE {NS}_{name} counter");
            let _ = writeln!(out, "{NS}_{name} {value}");
        }

        // --- gauges -----------------------------------------------------------
        let gauges: [(&str, &str, u64); 2] = [
            (
                "db_pool_size",
                "Connections currently held by the database pool.",
                self.db_pool_size.load(Ordering::Relaxed),
            ),
            (
                "db_pool_idle",
                "Idle connections in the database pool.",
                self.db_pool_idle.load(Ordering::Relaxed),
            ),
        ];
        for (name, help, value) in gauges {
            let _ = writeln!(out, "# HELP {NS}_{name} {help}");
            let _ = writeln!(out, "# TYPE {NS}_{name} gauge");
            let _ = writeln!(out, "{NS}_{name} {value}");
        }

        out
    }
}

/// Map an HTTP method onto a fixed, closed set.
///
/// The raw method string is never used as a label: it is attacker-controlled on
/// any request, and `curl -X $(head -c 200 /dev/urandom | base64)` would otherwise
/// mint a series per request.
fn normalise_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    }
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

fn normalise_route(route: &str) -> String {
    if is_route_pattern(route) {
        route.to_string()
    } else {
        UNPATTERNED_ROUTE.to_string()
    }
}

/// Whether a string is a plausible route *template* rather than a concrete path.
///
/// This is the enforcement point for invariant 1. It is intentionally strict and
/// fails closed: anything it is unsure about becomes `__unpatterned__`, which
/// costs one series and is loudly visible on a dashboard, whereas the failure it
/// prevents is unbounded memory growth.
fn is_route_pattern(route: &str) -> bool {
    if !route.starts_with('/') || route.len() > MAX_ROUTE_LEN {
        return false;
    }
    for segment in route.split('/').skip(1) {
        if segment.is_empty() {
            // Trailing slash, or the root path. Harmless.
            continue;
        }
        // `starts_with('{')`/`ends_with('}')` guarantee those bytes are ASCII, so
        // the slice below is on a character boundary.
        if segment.starts_with('{') && segment.ends_with('}') && segment.len() >= 2 {
            let name = &segment[1..segment.len() - 1];
            let ok = !name.is_empty()
                && name.len() <= 40
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*');
            if !ok {
                return false;
            }
            continue;
        }
        if segment.len() > 40 {
            return false;
        }
        // A literal path segment in this API is a lowercase word, a version marker
        // or a hyphenated word. Anything else — an `@`, a percent-escape, a space —
        // means user input reached the label.
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return false;
        }
        // An all-digit segment is a numeric id, never a route literal.
        if segment.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if looks_like_an_identifier(segment) {
            return false;
        }
    }
    true
}

/// Detect the shapes concrete identifiers take in this system: a UUID, or a long
/// run of hex (a token digest, a hash prefix).
fn looks_like_an_identifier(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    // Canonical UUID: 8-4-4-4-12.
    if bytes.len() == 36 {
        let dashes_placed = [8usize, 13, 18, 23].iter().all(|i| bytes[*i] == b'-');
        let rest_is_hex = bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit());
        if dashes_placed && rest_is_hex {
            return true;
        }
    }
    // 16+ hex characters is not a word.
    if segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

/// Escape a label value per the exposition format (`\`, `"` and newline).
///
/// Every value reaching here has already been restricted to a safe character set,
/// so this can never actually fire — it exists so that a future call site that
/// widens the character set cannot silently emit a malformed exposition document
/// that breaks the scraper for every other metric.
fn escape_label(value: &str) -> String {
    if !value.contains(['\\', '"', '\n']) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_line<'a>(rendered: &'a str, prefix: &str) -> Option<&'a str> {
        rendered.lines().find(|l| l.starts_with(prefix))
    }

    #[test]
    fn counters_increment() {
        let m = Metrics::new();
        m.auth_failure();
        m.auth_failure();
        m.authz_denial("no_grant");
        m.rate_limit_event();
        m.outbox_failure();
        m.audit_written();

        let out = m.render();
        assert_eq!(
            metric_line(&out, "roleblank_auth_failures_total "),
            Some("roleblank_auth_failures_total 2")
        );
        assert!(
            out.contains("roleblank_authz_denials_total{reason=\"no_grant\"} 1"),
            "{out}"
        );
        assert_eq!(
            metric_line(&out, "roleblank_rate_limit_events_total "),
            Some("roleblank_rate_limit_events_total 1")
        );
        assert_eq!(
            metric_line(&out, "roleblank_outbox_failures_total "),
            Some("roleblank_outbox_failures_total 1")
        );
        assert_eq!(
            metric_line(&out, "roleblank_audit_events_written_total "),
            Some("roleblank_audit_events_written_total 1")
        );
    }

    #[test]
    fn http_requests_are_counted_per_label_set() {
        let m = Metrics::new();
        m.http_request("GET", "/api/v1/projects/{id}", 200);
        m.http_request("GET", "/api/v1/projects/{id}", 204);
        m.http_request("GET", "/api/v1/projects/{id}", 404);
        m.http_request("POST", "/api/v1/projects", 201);

        let out = m.render();
        assert!(out.contains(
            "roleblank_http_requests_total{method=\"GET\",route=\"/api/v1/projects/{id}\",status=\"2xx\"} 2"
        ), "{out}");
        assert!(out.contains(
            "roleblank_http_requests_total{method=\"GET\",route=\"/api/v1/projects/{id}\",status=\"4xx\"} 1"
        ));
        assert!(out.contains(
            "roleblank_http_requests_total{method=\"POST\",route=\"/api/v1/projects\",status=\"2xx\"} 1"
        ));
        assert_eq!(m.http_series_count(), 3);
    }

    #[test]
    fn gauges_are_set_not_accumulated() {
        let m = Metrics::new();
        m.db_pool(10, 7);
        m.db_pool(12, 3);
        let out = m.render();
        assert_eq!(
            metric_line(&out, "roleblank_db_pool_size "),
            Some("roleblank_db_pool_size 12")
        );
        assert_eq!(
            metric_line(&out, "roleblank_db_pool_idle "),
            Some("roleblank_db_pool_idle 3")
        );
    }

    // ---- histogram ---------------------------------------------------------

    fn bucket_values(rendered: &str) -> Vec<u64> {
        rendered
            .lines()
            .filter(|l| l.starts_with("roleblank_http_request_duration_ms_bucket"))
            .filter_map(|l| l.rsplit(' ').next())
            .filter_map(|v| v.parse::<u64>().ok())
            .collect()
    }

    #[test]
    fn observations_land_in_the_right_bucket() {
        let m = Metrics::new();
        // Boundaries are inclusive (`le`), so 5 belongs to the `le="5"` bucket.
        m.latency_ms(5);
        m.latency_ms(6); // le=10
        m.latency_ms(0); // le=5
        let out = m.render();
        let buckets = bucket_values(&out);
        assert_eq!(
            buckets.len(),
            LATENCY_BUCKETS_MS.len() + 1,
            "missing +Inf bucket"
        );
        assert_eq!(
            buckets[0], 2,
            "le=5 should hold the 0ms and 5ms observations"
        );
        assert_eq!(buckets[1], 3, "le=10 is cumulative and must include le=5");
        assert_eq!(*buckets.last().unwrap_or(&0), 3);
    }

    #[test]
    fn buckets_are_cumulative_and_monotonic() {
        let m = Metrics::new();
        for ms in [0, 3, 7, 40, 99, 100, 101, 900, 4999, 5000, 5001, 60_000] {
            m.latency_ms(ms);
        }
        let out = m.render();
        let buckets = bucket_values(&out);
        assert!(
            buckets.windows(2).all(|w| w[0] <= w[1]),
            "cumulative `le` buckets must be monotonically non-decreasing: {buckets:?}"
        );
        assert_eq!(
            *buckets.last().unwrap_or(&0),
            12,
            "+Inf must count every observation"
        );
    }

    /// An observation above the largest bound must not be dropped, and must not be
    /// counted in any finite bucket.
    #[test]
    fn observations_above_the_top_bound_only_reach_infinity() {
        let m = Metrics::new();
        m.latency_ms(u64::MAX);
        let buckets = bucket_values(&m.render());
        for (i, v) in buckets.iter().take(LATENCY_BUCKETS_MS.len()).enumerate() {
            assert_eq!(*v, 0, "bucket {i} should be empty");
        }
        assert_eq!(*buckets.last().unwrap_or(&0), 1);
    }

    #[test]
    fn a_duration_is_converted_without_wrapping() {
        let m = Metrics::new();
        m.latency(Duration::from_millis(250));
        m.latency(Duration::from_secs(u64::MAX / 2)); // absurd, must saturate
        let buckets = bucket_values(&m.render());
        assert_eq!(buckets[5], 1, "250ms belongs to le=250");
        assert_eq!(*buckets.last().unwrap_or(&0), 2);
    }

    // ---- cardinality -------------------------------------------------------

    /// The property this module exists for: request input cannot grow the series
    /// table without bound.
    #[test]
    fn concrete_paths_never_become_labels() {
        let m = Metrics::new();
        for i in 0..500 {
            // What a careless call site does: the *concrete* URI.
            m.http_request("GET", &format!("/api/v1/projects/{i}"), 200);
        }
        m.http_request(
            "GET",
            "/api/v1/users/018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b",
            200,
        );
        assert_eq!(
            m.http_series_count(),
            1,
            "concrete paths must collapse into a single __unpatterned__ series"
        );
        assert!(m.render().contains(UNPATTERNED_ROUTE));
    }

    #[test]
    fn the_series_table_is_hard_capped() {
        let m = Metrics::new();
        // Every one of these *is* a valid pattern, so validation cannot save us —
        // only the cap can.
        for i in 0..(MAX_HTTP_SERIES * 3) {
            m.http_request("GET", &format!("/api/v1/a{i}/{{id}}"), 200);
        }
        assert!(
            m.http_series_count() <= MAX_HTTP_SERIES + 1,
            "series table grew past the cap: {}",
            m.http_series_count()
        );
        assert!(
            m.render().contains(OVERFLOW_ROUTE),
            "overflow series should be reported"
        );
    }

    #[test]
    fn unknown_methods_collapse_to_other() {
        let m = Metrics::new();
        for i in 0..100 {
            m.http_request(&format!("BREW{i}"), "/api/v1/projects", 200);
        }
        assert_eq!(m.http_series_count(), 1);
        assert!(m.render().contains("method=\"OTHER\""));
    }

    /// The denial-reason label takes a `&str`, so it is the other place an
    /// unbounded label could enter. The family must stay exactly six series no
    /// matter what is passed, and nothing hostile may reach the output.
    #[test]
    fn authz_denial_reasons_are_a_closed_set() {
        let m = Metrics::new();
        // The real reasons, from `Decision::reason()`.
        for reason in [
            "unknown_permission",
            "principal_envelope",
            "explicit_deny",
            "no_grant",
            "out_of_scope",
        ] {
            m.authz_denial(reason);
        }
        // And a pile of things a future call site might wrongly interpolate.
        for i in 0..500 {
            m.authz_denial(&format!(
                "no_grant for user alice{i}@example.com on projects.read"
            ));
        }
        m.authz_denial("018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b");
        m.authz_denial("reason\"with\\quotes\nand a newline");
        m.authz_denial("");

        let out = m.render();
        let denial_lines: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("roleblank_authz_denials_total{"))
            .collect();
        assert_eq!(
            denial_lines.len(),
            AUTHZ_DENIAL_REASONS.len(),
            "the denial family must stay a closed set: {denial_lines:?}"
        );
        // The five real reasons each got exactly one, and everything else was
        // folded into `other` — so nothing was silently dropped either.
        for reason in [
            "unknown_permission",
            "principal_envelope",
            "explicit_deny",
            "no_grant",
            "out_of_scope",
        ] {
            assert!(
                out.contains(&format!(
                    "roleblank_authz_denials_total{{reason=\"{reason}\"}} 1"
                )),
                "reason `{reason}` was not counted: {out}"
            );
        }
        assert!(
            out.contains("roleblank_authz_denials_total{reason=\"other\"} 503"),
            "{out}"
        );
        assert!(
            !out.contains('@'),
            "an email reached the denial label: {out}"
        );
        assert!(
            !out.contains("alice"),
            "a principal reached the denial label: {out}"
        );
    }

    #[test]
    fn route_pattern_validation_accepts_templates_and_rejects_instances() {
        for good in [
            "/",
            "/health",
            "/health/ready",
            "/api/v1/projects",
            "/api/v1/projects/{id}",
            "/api/v1/projects/{project_id}/tasks/{task_id}",
            "/api/v1/well-known.json",
            "/api/v1/files/{*path}",
        ] {
            assert!(is_route_pattern(good), "`{good}` should be accepted");
        }
        for bad in [
            "api/v1/projects",                                    // no leading slash
            "/api/v1/projects/42",                                // numeric id
            "/api/v1/users/018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b", // uuid
            "/api/v1/tokens/deadbeefdeadbeefdeadbeef",            // hex blob
            "/api/v1/users/alice@example.com",                    // an email in the path
            "/api/v1/search?q=secret",                            // a query string
            "/api/v1/projects/{}",                                // empty placeholder
            "/api/v1/projects/{id",                               // unbalanced
            "/api/v1/a b",                                        // whitespace
            "/api/v1/pro\njects",                                 // newline
        ] {
            assert!(!is_route_pattern(bad), "`{bad}` should be rejected");
        }
        // Length bound.
        let long = format!("/{}", "a".repeat(MAX_ROUTE_LEN + 10));
        assert!(!is_route_pattern(&long));
    }

    #[test]
    fn status_classes_are_bounded() {
        assert_eq!(status_class(100), "1xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(302), "3xx");
        assert_eq!(status_class(429), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(999), "other");
        assert_eq!(status_class(0), "other");
    }

    // ---- exposition format & leakage --------------------------------------

    #[test]
    fn rendering_is_valid_exposition_format() {
        let m = Metrics::new();
        m.http_request("GET", "/api/v1/projects/{id}", 200);
        m.latency_ms(12);
        m.db_pool(5, 2);
        m.authz_denial("no_grant");
        let out = m.render();

        // Every metric family must be preceded by HELP and TYPE.
        for family in [
            "roleblank_http_requests_total",
            "roleblank_http_request_duration_ms",
            "roleblank_auth_failures_total",
            "roleblank_authz_denials_total",
            "roleblank_rate_limit_events_total",
            "roleblank_outbox_failures_total",
            "roleblank_audit_events_written_total",
            "roleblank_db_pool_size",
            "roleblank_db_pool_idle",
        ] {
            assert!(
                out.contains(&format!("# HELP {family} ")),
                "missing HELP for {family}"
            );
            assert!(
                out.contains(&format!("# TYPE {family} ")),
                "missing TYPE for {family}"
            );
        }

        // Every sample line must be `name[{labels}] value` with a numeric value.
        for line in out.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let (_, value) = line.rsplit_once(' ').unwrap_or(("", ""));
            assert!(
                value.parse::<u64>().is_ok(),
                "sample line has no numeric value: `{line}`"
            );
            assert!(
                line.starts_with("roleblank_"),
                "sample outside the namespace: `{line}`"
            );
            assert_eq!(
                line.matches('"').count() % 2,
                0,
                "unbalanced label quoting: `{line}`"
            );
        }
        assert!(
            out.ends_with('\n'),
            "exposition text must end with a newline"
        );
    }

    /// The second invariant, asserted directly on the bytes an operator would
    /// scrape. Anything that can identify a principal must be absent.
    #[test]
    fn the_rendered_output_never_contains_a_principal_identifier() {
        let m = Metrics::new();
        // Feed it exactly what a careless call site would.
        m.http_request("GET", "/api/v1/users/alice@example.com", 200);
        m.http_request(
            "GET",
            "/api/v1/users/018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b/sessions",
            200,
        );
        m.http_request("POST", "/api/v1/auth/login", 401);
        m.authz_denial("denied for 018f3a1e-6b7c-7f2a-9c31-2b4d5e6f7a8b");
        let out = m.render();

        assert!(
            !out.contains('@'),
            "an email reached the metrics output:\n{out}"
        );
        assert!(
            !out.contains("alice"),
            "a local part reached the metrics output:\n{out}"
        );
        assert!(
            !out.contains("018f3a1e"),
            "a UUID reached the metrics output:\n{out}"
        );
        assert!(
            !out.lines().any(looks_like_a_uuid_anywhere),
            "a UUID-shaped token reached the metrics output:\n{out}"
        );
    }

    /// Scan for the canonical 8-4-4-4-12 shape anywhere in a line.
    fn looks_like_a_uuid_anywhere(line: &str) -> bool {
        let bytes = line.as_bytes();
        if bytes.len() < 36 {
            return false;
        }
        (0..=bytes.len() - 36).any(|start| {
            line.get(start..start + 36)
                .is_some_and(looks_like_an_identifier)
        })
    }

    #[test]
    fn label_escaping_cannot_break_the_document() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("a\"b"), "a\\\"b");
        assert_eq!(escape_label("a\\b"), "a\\\\b");
        assert_eq!(escape_label("a\nb"), "a\\nb");
    }

    #[test]
    fn concurrent_recording_totals_correctly() {
        use std::sync::Arc;
        let m = Arc::new(Metrics::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = m.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    m.http_request("GET", "/api/v1/projects/{id}", 200);
                    m.latency_ms(7);
                    m.auth_failure();
                    m.authz_denial("no_grant");
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let out = m.render();
        assert!(out.contains("roleblank_auth_failures_total 4000"), "{out}");
        assert!(
            out.contains("roleblank_authz_denials_total{reason=\"no_grant\"} 4000"),
            "{out}"
        );
        assert!(
            out.contains(
                "roleblank_http_requests_total{method=\"GET\",route=\"/api/v1/projects/{id}\",status=\"2xx\"} 4000"
            ),
            "{out}"
        );
        assert!(out.contains("roleblank_http_request_duration_ms_count 4000"));
        assert_eq!(m.http_series_count(), 1);
    }
}
