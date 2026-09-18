//! Hard worker, batch and input-byte caps (task B-038).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 6 fixes the defaults and
//! requires the memory and in-flight budget to stay bounded:
//!
//! * CPU workers = `max(1, min(4, logical_cpu_count - 1))`;
//! * a parser batch is at most 64 files or 16 MiB of input;
//! * an oversized file is handled by a per-file limit and an explicit report.
//!
//! A configured value is a request, not a promise. Every constructor here clamps
//! to the hard cap, so a configuration file cannot lift the limit. An input that
//! is larger than one whole batch is never silently dropped or truncated: it gets
//! an explicit [`Admission::RejectedOversized`] result that the caller records.

use graph_core::config::{RuntimeConfig, MAX_PARSER_BATCH_BYTES, MAX_PARSER_BATCH_FILES};

/// Fewest workers this build will run.
pub const MIN_WORKERS: usize = 1;
/// Most workers this build will run.
pub const MAX_WORKERS: usize = 4;
/// Hard cap on files in one parser batch.
pub const HARD_MAX_BATCH_FILES: usize = MAX_PARSER_BATCH_FILES;
/// Hard cap on bytes in one parser batch.
pub const HARD_MAX_BATCH_BYTES: u64 = MAX_PARSER_BATCH_BYTES;
/// Hard cap on batches a single instance may hold in flight at once.
pub const MAX_IN_FLIGHT_BATCHES: usize = 4;

/// Worker count for a host with `logical_cpus` processors.
///
/// One processor is always left for the watcher, the writer and the SQLite
/// background work, but the count never drops below one worker.
#[must_use]
pub const fn worker_count(logical_cpus: usize) -> usize {
    let available = logical_cpus.saturating_sub(1);
    if available < MIN_WORKERS {
        MIN_WORKERS
    } else if available > MAX_WORKERS {
        MAX_WORKERS
    } else {
        available
    }
}

/// Clamp a configured worker count into the supported range.
#[must_use]
pub const fn configured_worker_count(requested: usize) -> usize {
    if requested < MIN_WORKERS {
        MIN_WORKERS
    } else if requested > MAX_WORKERS {
        MAX_WORKERS
    } else {
        requested
    }
}

/// Batch limits that can never exceed the hard caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchLimits {
    max_files: usize,
    max_bytes: u64,
}

impl BatchLimits {
    /// Clamp requested limits into the supported range.
    #[must_use]
    pub const fn new(max_files: usize, max_bytes: u64) -> Self {
        Self {
            max_files: if max_files < 1 {
                1
            } else if max_files > HARD_MAX_BATCH_FILES {
                HARD_MAX_BATCH_FILES
            } else {
                max_files
            },
            max_bytes: if max_bytes < 1 {
                1
            } else if max_bytes > HARD_MAX_BATCH_BYTES {
                HARD_MAX_BATCH_BYTES
            } else {
                max_bytes
            },
        }
    }

    /// Limits taken from the runtime configuration, then clamped.
    #[must_use]
    pub const fn from_runtime(runtime: &RuntimeConfig) -> Self {
        Self::new(runtime.parser_batch_files(), runtime.parser_batch_bytes())
    }

    /// Maximum files admitted to one batch.
    #[must_use]
    pub const fn max_files(&self) -> usize {
        self.max_files
    }

    /// Maximum input bytes admitted to one batch.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

impl Default for BatchLimits {
    fn default() -> Self {
        Self::new(HARD_MAX_BATCH_FILES, HARD_MAX_BATCH_BYTES)
    }
}

/// One candidate input for a parser batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchItem {
    portable_path: String,
    bytes: u64,
}

impl BatchItem {
    /// Describe one input file.
    #[must_use]
    pub fn new(portable_path: impl Into<String>, bytes: u64) -> Self {
        Self {
            portable_path: portable_path.into(),
            bytes,
        }
    }

    /// Canonical portable relative path.
    #[must_use]
    pub fn portable_path(&self) -> &str {
        &self.portable_path
    }

    /// Input size in bytes.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// How an input was classified against a single-file limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClass {
    /// The input fits in a batch.
    Accepted,
    /// The input is larger than a whole batch and must be reported per-file.
    Oversized {
        /// The limit that was exceeded.
        limit: u64,
    },
}

impl InputClass {
    /// Whether the input may enter a batch.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Classify one input against the batch byte limit.
#[must_use]
pub const fn classify_input(bytes: u64, limits: &BatchLimits) -> InputClass {
    if bytes > limits.max_bytes() {
        InputClass::Oversized {
            limit: limits.max_bytes(),
        }
    } else {
        InputClass::Accepted
    }
}

/// The result of offering an input to a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The input joined the batch.
    Admitted,
    /// The input is larger than one whole batch; report it per file.
    RejectedOversized {
        /// Canonical portable relative path of the input.
        portable_path: String,
        /// Observed size in bytes.
        observed: u64,
        /// The limit that was exceeded.
        limit: u64,
    },
    /// The batch is already at a hard cap; the caller opens a new batch.
    RejectedFull {
        /// Which cap was reached.
        cap: BatchCap,
    },
}

/// A hard cap that a batch reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchCap {
    /// The file-count cap.
    Files,
    /// The input-byte cap.
    Bytes,
}

/// A bounded parser batch.
#[derive(Debug, Clone)]
pub struct ParserBatch {
    limits: BatchLimits,
    items: Vec<BatchItem>,
    total_bytes: u64,
}

impl ParserBatch {
    /// An empty batch with `limits`.
    #[must_use]
    pub fn new(limits: BatchLimits) -> Self {
        Self {
            limits,
            items: Vec::new(),
            total_bytes: 0,
        }
    }

    /// The limits this batch enforces.
    #[must_use]
    pub const fn limits(&self) -> BatchLimits {
        self.limits
    }

    /// Files currently admitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether no file is admitted yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Input bytes currently admitted.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Files that still fit before the file-count cap.
    #[must_use]
    pub fn remaining_files(&self) -> usize {
        self.limits.max_files().saturating_sub(self.items.len())
    }

    /// Input bytes that still fit before the byte cap.
    #[must_use]
    pub const fn remaining_bytes(&self) -> u64 {
        self.limits.max_bytes().saturating_sub(self.total_bytes)
    }

    /// Whether the batch has reached a hard cap.
    #[must_use]
    pub fn cap_reached(&self) -> Option<BatchCap> {
        if self.items.len() >= self.limits.max_files() {
            return Some(BatchCap::Files);
        }
        if self.total_bytes >= self.limits.max_bytes() {
            return Some(BatchCap::Bytes);
        }
        None
    }

    /// Offer one input to the batch.
    ///
    /// An oversized input is rejected with its observed size, never truncated and
    /// never silently skipped.
    pub fn admit(&mut self, item: BatchItem) -> Admission {
        if let InputClass::Oversized { limit } = classify_input(item.bytes, &self.limits) {
            return Admission::RejectedOversized {
                portable_path: item.portable_path,
                observed: item.bytes,
                limit,
            };
        }
        if let Some(cap) = self.cap_reached() {
            return Admission::RejectedFull { cap };
        }
        self.total_bytes = self.total_bytes.saturating_add(item.bytes);
        self.items.push(item);
        Admission::Admitted
    }

    /// Take the admitted inputs, leaving the batch empty.
    pub fn drain(&mut self) -> Vec<BatchItem> {
        self.total_bytes = 0;
        core::mem::take(&mut self.items)
    }
}

/// Tracks how many batches one instance holds in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InFlightBatches {
    limit: usize,
    active: usize,
}

impl InFlightBatches {
    /// A tracker bounded by the worker-derived limit, itself hard-capped.
    #[must_use]
    pub const fn new(workers: usize) -> Self {
        let bounded = configured_worker_count(workers);
        Self {
            limit: if bounded > MAX_IN_FLIGHT_BATCHES {
                MAX_IN_FLIGHT_BATCHES
            } else {
                bounded
            },
            active: 0,
        }
    }

    /// The hard cap in force.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Batches currently in flight.
    #[must_use]
    pub const fn active(&self) -> usize {
        self.active
    }

    /// Try to start one batch.
    pub fn acquire(&mut self) -> bool {
        if self.active >= self.limit {
            return false;
        }
        self.active += 1;
        true
    }

    /// Release one batch; a spurious release is ignored.
    pub fn release(&mut self) {
        self.active = self.active.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_input, configured_worker_count, worker_count, Admission, BatchCap, BatchItem,
        BatchLimits, InFlightBatches, InputClass, HARD_MAX_BATCH_BYTES, HARD_MAX_BATCH_FILES,
        MAX_IN_FLIGHT_BATCHES, MAX_WORKERS,
    };

    #[test]
    fn worker_count_leaves_one_cpu_and_stays_within_the_hard_cap() {
        assert_eq!(worker_count(0), 1);
        assert_eq!(worker_count(1), 1);
        assert_eq!(worker_count(2), 1);
        assert_eq!(worker_count(3), 2);
        assert_eq!(worker_count(8), 4);
        assert_eq!(worker_count(256), MAX_WORKERS);
    }

    #[test]
    fn a_configured_worker_count_cannot_exceed_the_hard_cap() {
        assert_eq!(configured_worker_count(0), 1);
        assert_eq!(configured_worker_count(2), 2);
        assert_eq!(configured_worker_count(99), MAX_WORKERS);
    }

    #[test]
    fn a_configured_batch_limit_cannot_exceed_the_hard_cap() {
        let limits = BatchLimits::new(usize::MAX, u64::MAX);
        assert_eq!(limits.max_files(), HARD_MAX_BATCH_FILES);
        assert_eq!(limits.max_bytes(), HARD_MAX_BATCH_BYTES);
        let tiny = BatchLimits::new(0, 0);
        assert_eq!(tiny.max_files(), 1);
        assert_eq!(tiny.max_bytes(), 1);
    }

    #[test]
    fn a_single_oversized_input_returns_an_explicit_result() {
        let limits = BatchLimits::default();
        assert_eq!(
            classify_input(HARD_MAX_BATCH_BYTES + 1, &limits),
            InputClass::Oversized {
                limit: HARD_MAX_BATCH_BYTES
            }
        );
        assert!(classify_input(HARD_MAX_BATCH_BYTES, &limits).is_accepted());

        let mut batch = super::ParserBatch::new(limits);
        let admission = batch.admit(BatchItem::new("src/huge.sql", HARD_MAX_BATCH_BYTES + 1));
        assert_eq!(
            admission,
            Admission::RejectedOversized {
                portable_path: "src/huge.sql".to_string(),
                observed: HARD_MAX_BATCH_BYTES + 1,
                limit: HARD_MAX_BATCH_BYTES,
            }
        );
        assert!(
            batch.is_empty(),
            "a rejected input must not be half-admitted"
        );
        assert_eq!(batch.bytes(), 0);
    }

    #[test]
    fn the_file_cap_stops_a_batch_and_asks_for_a_new_one() {
        let mut batch = super::ParserBatch::new(BatchLimits::new(2, HARD_MAX_BATCH_BYTES));
        assert_eq!(batch.admit(BatchItem::new("a.cs", 1)), Admission::Admitted);
        assert_eq!(batch.admit(BatchItem::new("b.cs", 1)), Admission::Admitted);
        assert_eq!(
            batch.admit(BatchItem::new("c.cs", 1)),
            Admission::RejectedFull {
                cap: BatchCap::Files
            }
        );
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn the_byte_cap_stops_a_batch_and_reports_the_cap() {
        let mut batch = super::ParserBatch::new(BatchLimits::new(64, 10));
        assert_eq!(batch.admit(BatchItem::new("a.cs", 10)), Admission::Admitted);
        assert_eq!(
            batch.admit(BatchItem::new("b.cs", 1)),
            Admission::RejectedFull {
                cap: BatchCap::Bytes
            }
        );
    }

    #[test]
    fn draining_a_batch_resets_its_budget() {
        let mut batch = super::ParserBatch::new(BatchLimits::default());
        batch.admit(BatchItem::new("a.cs", 7));
        let drained = batch.drain();
        assert_eq!(drained.len(), 1);
        assert!(batch.is_empty());
        assert_eq!(batch.bytes(), 0);
        assert_eq!(batch.remaining_bytes(), HARD_MAX_BATCH_BYTES);
    }

    #[test]
    fn in_flight_batches_are_bounded_by_workers_and_the_hard_cap() {
        let mut in_flight = InFlightBatches::new(99);
        assert_eq!(in_flight.limit(), MAX_IN_FLIGHT_BATCHES);
        for _ in 0..MAX_IN_FLIGHT_BATCHES {
            assert!(in_flight.acquire());
        }
        assert!(!in_flight.acquire(), "the cap must refuse a further batch");
        in_flight.release();
        assert!(in_flight.acquire());
        in_flight.release();
        in_flight.release();
        assert_eq!(in_flight.active(), 2, "two releases after a re-acquire");
    }
}
