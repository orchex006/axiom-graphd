//! Redacted structured diagnostics (task B-007).
//!
//! Every diagnostic record is one JSON object per line with exactly the keys
//! `level`, `target` and `message` (docs/16-CLI-AND-CONTROL-API.md section 1:
//! stdout carries a single JSON object, diagnostics go to stderr). A message is
//! scrubbed through [`graph_core::redact::scrub`] *before* it reaches a sink, so
//! credentials, bearer values, connection strings, JWT/PEM material and absolute
//! host paths cannot be recorded even if a caller interpolates untrusted text
//! into the message.
//!
//! Repeated failures are the normal state of a broken deployment, so records are
//! rate limited per target inside a sliding one-minute window. When a target
//! exceeds the limit the sink receives exactly one notice and the remaining
//! records are suppressed, which keeps an error loop from filling the disk while
//! still reporting that suppression happened.
//!
//! The writer is injected, so the daemon writes to stderr and tests assert on an
//! in-memory buffer without capturing the process's own streams.

use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};

use graph_core::error::AxiomError;
use graph_core::redact;

pub use graph_core::config::LogLevel;

/// Length of the per-target rate-limit window.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Minimum level a sink records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelFilter(LogLevel);

impl Default for LevelFilter {
    fn default() -> Self {
        Self(LogLevel::Info)
    }
}

impl LevelFilter {
    /// Record everything at or above `level`.
    #[must_use]
    pub const fn at_least(level: LogLevel) -> Self {
        Self(level)
    }

    /// The configured minimum level.
    #[must_use]
    pub const fn level(self) -> LogLevel {
        self.0
    }

    /// True when a record at `level` should be written.
    ///
    /// [LogLevel::rank] is ordered by severity (0 is the most severe), so a
    /// record is written when it is at least as severe as the configured floor.
    #[must_use]
    pub const fn allows(self, level: LogLevel) -> bool {
        level.rank() <= self.0.rank()
    }
}

/// What happened to one attempted record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The record was written.
    Recorded,
    /// The record was below the configured level.
    Filtered,
    /// One notice was written and further records are suppressed for now.
    SuppressionNotice,
    /// The record was suppressed by the rate limit.
    Suppressed,
}

impl RecordOutcome {
    /// True when bytes reached the sink.
    #[must_use]
    pub const fn was_written(self) -> bool {
        matches!(self, Self::Recorded | Self::SuppressionNotice)
    }
}

#[derive(Debug)]
struct Window {
    started: Instant,
    count: u32,
    notice_emitted: bool,
}

/// Structured, redacted, rate-limited diagnostic sink.
pub struct Telemetry {
    writer: Box<dyn Write + Send>,
    filter: LevelFilter,
    rate_limit_per_window: u32,
    windows: HashMap<String, Window>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("filter", &self.filter)
            .field("rate_limit_per_window", &self.rate_limit_per_window)
            .field("targets", &self.windows.len())
            .finish_non_exhaustive()
    }
}

impl Telemetry {
    /// A sink writing to an arbitrary writer.
    pub fn new(
        writer: Box<dyn Write + Send>,
        filter: LevelFilter,
        rate_limit_per_window: u32,
    ) -> Self {
        Self {
            writer,
            filter,
            rate_limit_per_window,
            windows: HashMap::new(),
        }
    }

    /// A sink writing JSON records to this process's stderr.
    #[must_use]
    pub fn stderr(filter: LevelFilter) -> Self {
        Self::new(Box::new(std::io::stderr()), filter, 600)
    }

    /// Configured minimum level.
    #[must_use]
    pub const fn filter(&self) -> LevelFilter {
        self.filter
    }

    /// Records written for `target` inside the current window.
    #[must_use]
    pub fn recorded_for(&self, target: &str) -> u32 {
        self.windows.get(target).map_or(0, |window| window.count)
    }

    /// Write one record using the current instant.
    pub fn record(&mut self, level: LogLevel, target: &str, message: &str) -> RecordOutcome {
        self.record_at(Instant::now(), level, target, message)
    }

    /// Write one record against an explicit clock (test seam).
    pub fn record_at(
        &mut self,
        now: Instant,
        level: LogLevel,
        target: &str,
        message: &str,
    ) -> RecordOutcome {
        if !self.filter.allows(level) {
            return RecordOutcome::Filtered;
        }
        if !self.within_rate_limit(now, target) {
            return if self.mark_notice(now, target) {
                let notice = "further records for this target are suppressed until the rate-limit window resets";
                self.write_line(level, target, notice);
                RecordOutcome::SuppressionNotice
            } else {
                RecordOutcome::Suppressed
            };
        }
        self.write_line(level, target, message);
        RecordOutcome::Recorded
    }

    /// Record a typed failure without leaking its context.
    pub fn record_error(&mut self, target: &str, error: &AxiomError) -> RecordOutcome {
        let message = error.to_string();
        self.record(LogLevel::Error, target, &message)
    }

    /// Flush the sink.
    ///
    /// # Errors
    /// Propagates the writer's I/O error.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn within_rate_limit(&mut self, now: Instant, target: &str) -> bool {
        let limit = self.rate_limit_per_window;
        let window = self.windows.entry(target.to_string()).or_insert(Window {
            started: now,
            count: 0,
            notice_emitted: false,
        });
        if now.saturating_duration_since(window.started) >= RATE_WINDOW {
            window.started = now;
            window.count = 0;
            window.notice_emitted = false;
        }
        if limit == 0 {
            return false;
        }
        if window.count < limit {
            window.count += 1;
            return true;
        }
        false
    }

    fn mark_notice(&mut self, now: Instant, target: &str) -> bool {
        let window = self.windows.entry(target.to_string()).or_insert(Window {
            started: now,
            count: 0,
            notice_emitted: false,
        });
        if window.notice_emitted {
            return false;
        }
        window.notice_emitted = true;
        true
    }

    fn write_line(&mut self, level: LogLevel, target: &str, message: &str) {
        let record = serde_json::json!({
            "level": level.as_str(),
            "target": target,
            "message": redact::scrub(message),
        });
        // `serde_json::to_string` escapes newlines and quotes, so one record is
        // always exactly one line even when the message contains them.
        let mut line = match serde_json::to_string(&record) {
            Ok(encoded) => encoded,
            Err(_) => return,
        };
        line.push('\n');
        let _ = self.writer.write_all(line.as_bytes());
        let _ = self.writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_core::error::ErrorCode;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("sink lock").clone()).expect("utf8")
        }

        fn lines(&self) -> Vec<String> {
            self.text().lines().map(ToOwned::to_owned).collect()
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn telemetry(limit: u32) -> (Telemetry, Sink) {
        let sink = Sink::default();
        let writer = Telemetry::new(
            Box::new(sink.clone()),
            LevelFilter::at_least(LogLevel::Trace),
            limit,
        );
        (writer, sink)
    }

    #[test]
    fn records_are_single_line_json_with_exactly_three_keys() {
        let (mut telemetry, sink) = telemetry(10);
        let outcome = telemetry.record(LogLevel::Warn, "queue", "job retry\nsecond line");
        assert_eq!(outcome, RecordOutcome::Recorded);
        let lines = sink.lines();
        assert_eq!(
            lines.len(),
            1,
            "a newline inside a message must not split a record"
        );
        let value: serde_json::Value = serde_json::from_str(&lines[0]).expect("json");
        let object = value.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["level", "message", "target"]);
        assert_eq!(object["level"], serde_json::Value::from("warn"));
        assert_eq!(object["target"], serde_json::Value::from("queue"));
    }

    #[test]
    fn secrets_and_paths_never_reach_the_sink() {
        // Assembled at runtime: the source never contains a contiguous
        // credential or machine path, the assertions are on the values.
        let marker = format!("{} {}", concat!("Bea", "rer"), "QQQQQQQQ.RRRR");
        let jwt = concat!("eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxIn0", ".c2lnbmF0dXJl");
        let host_path = concat!(r"C:\Users", r"\me\repo\index.sqlite");

        let (mut telemetry, sink) = telemetry(50);
        telemetry.record(LogLevel::Error, "control", &marker);
        telemetry.record(LogLevel::Error, "analysis", jwt);
        telemetry.record(
            LogLevel::Error,
            "store",
            &format!("failed to open {host_path}"),
        );
        let text = sink.text();
        assert!(!text.contains("QQQQQQQQ"));
        assert!(!text.contains("c2lnbmF0dXJl"));
        assert!(!text.contains("Users"));
        assert!(text.contains(redact::REDACTED));
        assert!(text.contains(redact::REDACTED_PATH));
    }

    #[test]
    fn level_filter_drops_lower_levels() {
        let sink = Sink::default();
        let mut telemetry = Telemetry::new(
            Box::new(sink.clone()),
            LevelFilter::at_least(LogLevel::Info),
            10,
        );
        assert_eq!(
            telemetry.record(LogLevel::Debug, "watcher", "noisy"),
            RecordOutcome::Filtered
        );
        assert_eq!(
            telemetry.record(LogLevel::Info, "watcher", "started"),
            RecordOutcome::Recorded
        );
        assert_eq!(sink.lines().len(), 1);
        assert!(LevelFilter::at_least(LogLevel::Warn).allows(LogLevel::Error));
        assert!(!LevelFilter::at_least(LogLevel::Warn).allows(LogLevel::Info));
    }

    #[test]
    fn repeated_errors_are_rate_limited_with_one_notice() {
        let (mut telemetry, sink) = telemetry(3);
        let now = Instant::now();
        for index in 0..3 {
            assert_eq!(
                telemetry.record_at(now, LogLevel::Error, "queue", "same failure"),
                RecordOutcome::Recorded,
                "record {index} is inside the limit"
            );
        }
        assert_eq!(
            telemetry.record_at(now, LogLevel::Error, "queue", "same failure"),
            RecordOutcome::SuppressionNotice
        );
        assert_eq!(
            telemetry.record_at(now, LogLevel::Error, "queue", "same failure"),
            RecordOutcome::Suppressed
        );
        // A different target has its own budget.
        assert_eq!(
            telemetry.record_at(now, LogLevel::Error, "publish", "same failure"),
            RecordOutcome::Recorded
        );
        let lines = sink.lines();
        assert_eq!(lines.len(), 5);
        assert!(lines[3].contains("suppressed"));
        assert_eq!(telemetry.recorded_for("queue"), 3);
        assert!(RecordOutcome::Recorded.was_written());
        assert!(!RecordOutcome::Suppressed.was_written());
    }

    #[test]
    fn the_rate_limit_window_resets_after_one_minute() {
        let (mut telemetry, sink) = telemetry(1);
        let start = Instant::now();
        assert_eq!(
            telemetry.record_at(start, LogLevel::Error, "queue", "first"),
            RecordOutcome::Recorded
        );
        assert_eq!(
            telemetry.record_at(start, LogLevel::Error, "queue", "second"),
            RecordOutcome::SuppressionNotice
        );
        let later = start + RATE_WINDOW + Duration::from_millis(1);
        assert_eq!(
            telemetry.record_at(later, LogLevel::Error, "queue", "third"),
            RecordOutcome::Recorded
        );
        let lines = sink.lines();
        assert_eq!(lines.len(), 3);
        assert!(lines[2].contains("third"));
    }

    #[test]
    fn a_zero_limit_suppresses_everything_but_still_reports_once() {
        let (mut telemetry, sink) = telemetry(0);
        let now = Instant::now();
        assert_eq!(
            telemetry.record_at(now, LogLevel::Warn, "queue", "x"),
            RecordOutcome::SuppressionNotice
        );
        assert_eq!(
            telemetry.record_at(now, LogLevel::Warn, "queue", "x"),
            RecordOutcome::Suppressed
        );
        assert_eq!(sink.lines().len(), 1);
    }

    #[test]
    fn error_records_carry_the_stable_code() {
        let (mut telemetry, sink) = telemetry(10);
        let error = AxiomError::new(
            ErrorCode::WriterAlreadyRunning,
            "another daemon owns the lock",
        );
        assert_eq!(
            telemetry.record_error("instance_lock", &error),
            RecordOutcome::Recorded
        );
        assert!(sink.text().contains("WRITER_ALREADY_RUNNING"));
        assert_eq!(telemetry.filter().level(), LogLevel::Trace);
    }
}
