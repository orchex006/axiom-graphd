//! Post-update doctor: health, handshake and schema probes (task E-044).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 puts a smoke check and an
//! MCP health plus fixture query between the version swap and the resume step, and
//! section 7 says what a failure there must do: stop the new process, repoint the
//! old versions, restore a compatible database backup and clear the new
//! unpublished outbox. This module is that decision.
//!
//! ## A transport success is not a functional success
//!
//! The failure mode this module is built against is the one an upgrade actually
//! produces: the new daemon answers, so the socket is up and the status line is
//! `200`, while the process is *not* serving the contract the upgrade promised. A
//! schema-frozen client, an incompatible graph schema, a downgraded build and a
//! fixture query that indexes nothing all look perfectly healthy to a probe that
//! checks the status code. So no probe here reports success from a status code:
//! every probe must return a body this build can parse *and* whose values match the
//! expectation being checked, and the decisive negative test in this module feeds
//! a `200` with a refused body and requires a rollback.
//!
//! ## Bounded rollback
//!
//! [`RollbackScope`] is drawn from a closed set of four steps and is never empty,
//! so "roll back" can never mean "remove state this module did not create". The
//! steps named by a failure are exactly the ones section 7 assigns to it: a schema
//! divergence additionally restores the compatible backup, a fixture-query
//! divergence additionally clears the new unpublished outbox.
//!
//! Nothing here opens a socket, spawns a process or writes a file: probes arrive
//! through the [`ProbeRunner`] abstraction, so the same decision runs over a live
//! daemon, a fixture and the in-memory doubles in the tests.

use std::collections::BTreeSet;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::redact;

/// Probes the doctor runs, in the order it runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProbeKind {
    /// Liveness and identity of the new process.
    Health,
    /// Protocol handshake of the new MCP server.
    Handshake,
    /// Schema versions the new build actually speaks.
    Schema,
    /// A real fixture query over the migrated state.
    FixtureQuery,
}

impl ProbeKind {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Handshake => "handshake",
            Self::Schema => "schema",
            Self::FixtureQuery => "fixture_query",
        }
    }

    /// Every probe, in run order.
    #[must_use]
    pub const fn all() -> &'static [ProbeKind] {
        &[
            Self::Health,
            Self::Handshake,
            Self::Schema,
            Self::FixtureQuery,
        ]
    }
}

/// Steps a bounded rollback may take, in the order section 7 applies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RollbackStep {
    /// Stop the process the update started.
    StopNewProcess,
    /// Repoint the active install manifest at the previous versions.
    RepointPrevious,
    /// Restore the compatible database backup taken before the migration.
    RestoreCompatibleBackup,
    /// Discard the new, unpublished outbox and cache state.
    ClearUnpublishedOutbox,
}

impl RollbackStep {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewProcess => "stop_new_process",
            Self::RepointPrevious => "repoint_previous",
            Self::RestoreCompatibleBackup => "restore_compatible_backup",
            Self::ClearUnpublishedOutbox => "clear_unpublished_outbox",
        }
    }

    /// Every step, in application order.
    #[must_use]
    pub const fn all() -> &'static [RollbackStep] {
        &[
            Self::StopNewProcess,
            Self::RepointPrevious,
            Self::RestoreCompatibleBackup,
            Self::ClearUnpublishedOutbox,
        ]
    }
}

/// The bounded set of steps one rollback will take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackScope {
    steps: BTreeSet<RollbackStep>,
}

impl RollbackScope {
    /// The scope one failure of `kind` requires.
    ///
    /// Every scope contains the two steps that stop the new build and restore the
    /// previous one; a schema divergence additionally restores the compatible
    /// backup, and a fixture-query divergence additionally clears the unpublished
    /// outbox.
    #[must_use]
    pub fn for_failure(kind: ProbeKind) -> Self {
        let mut steps = BTreeSet::new();
        steps.insert(RollbackStep::StopNewProcess);
        steps.insert(RollbackStep::RepointPrevious);
        if kind == ProbeKind::Schema {
            steps.insert(RollbackStep::RestoreCompatibleBackup);
        }
        if kind == ProbeKind::FixtureQuery {
            steps.insert(RollbackStep::ClearUnpublishedOutbox);
        }
        Self { steps }
    }

    /// The union of the scopes of every failure, which is what a multi-failure
    /// rollback must actually do.
    #[must_use]
    pub fn union(scopes: &[Self]) -> Option<Self> {
        let mut steps = BTreeSet::new();
        for scope in scopes {
            steps.extend(scope.steps.iter().copied());
        }
        if steps.is_empty() {
            None
        } else {
            Some(Self { steps })
        }
    }

    /// The steps, in application order.
    #[must_use]
    pub fn steps(&self) -> Vec<RollbackStep> {
        self.steps.iter().copied().collect()
    }

    /// Whether this scope takes a step.
    #[must_use]
    pub fn contains(&self, step: RollbackStep) -> bool {
        self.steps.contains(&step)
    }

    /// True when every step is one of the four declared steps and none is missing
    /// the two that always apply. A scope is never allowed to be unbounded.
    #[must_use]
    pub fn is_bounded(&self) -> bool {
        !self.steps.is_empty()
            && self
                .steps
                .iter()
                .all(|step| RollbackStep::all().contains(step))
            && self.steps.contains(&RollbackStep::StopNewProcess)
            && self.steps.contains(&RollbackStep::RepointPrevious)
    }
}

/// Upper bound on one probe body this module will parse.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Host bound on one probe, which a runner must respect.
pub const PROBE_TIMEOUT_MS: u64 = 10_000;

/// Protocol this build's MCP handshake expects.
pub const MCP_PROTOCOL: &str = "mcp";

/// One probe's raw answer, as the runner observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResponse {
    /// HTTP status code the process returned.
    pub status_code: u16,
    /// Body the process returned.
    pub body: String,
    /// Whether the transport itself failed.
    pub transport_error: Option<String>,
}

impl ProbeResponse {
    /// A response with a body, as the doubles and a real runner both produce.
    #[must_use]
    pub fn new(status_code: u16, body: &str) -> Self {
        Self {
            status_code,
            body: body.to_string(),
            transport_error: None,
        }
    }

    /// A response for a transport that never answered.
    #[must_use]
    pub fn transport_failure(reason: &str) -> Self {
        Self {
            status_code: 0,
            body: String::new(),
            transport_error: Some(reason.to_string()),
        }
    }

    /// True when the status code is a success status.
    ///
    /// This is a precondition check, never the verdict: [`doctor`] refuses to treat
    /// a success status as health by itself.
    #[must_use]
    pub const fn status_is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }
}

/// What a probe may be run against.
pub trait ProbeRunner {
    /// Run one probe and return its raw answer.
    fn run(&self, kind: ProbeKind) -> ProbeResponse;
}

/// What the upgraded build must be serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectations {
    /// Component the health probe must report.
    pub component: String,
    /// Version the health probe must report.
    pub version: String,
    /// Graph payload schema the schema probe must report.
    pub graph_schema: u32,
    /// Control API version the control probe must report.
    pub control_api: u32,
    /// MCP protocol version the handshake must report.
    pub protocol_version: u32,
    /// Minimum fixture records the fixture query must return.
    pub min_fixture_records: u64,
}

impl Expectations {
    /// The expectations of one core-release upgrade.
    #[must_use]
    pub fn core(version: &str, protocol_version: u32) -> Self {
        Self {
            component: "axiom-graphd".to_string(),
            version: version.to_string(),
            graph_schema: 1,
            control_api: 1,
            protocol_version,
            min_fixture_records: 1,
        }
    }
}

/// One refused probe, with the rule it violated and the redacted observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFailure {
    /// Probe that failed.
    pub kind: ProbeKind,
    /// Stable name of the violated rule.
    pub rule: &'static str,
    /// Redacted observation that made the rule fail.
    pub observed: String,
}

impl ProbeFailure {
    /// The failure as an error, using only allowed and redacted details.
    #[must_use]
    pub fn to_error(&self) -> AxiomError {
        AxiomError::new(
            ErrorCode::NotReady,
            "the post-update doctor refused the new build",
        )
        .with_detail("component", self.kind.as_str())
        .with_detail("rule", self.rule)
        .with_detail("observed", &self.observed)
    }
}

/// The verdict of one post-update doctor run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorVerdict {
    /// Every probe served the expected contract.
    Healthy,
    /// At least one probe diverged; the new build must be rolled back.
    Rollback {
        /// Every failure, in probe order.
        failures: Vec<ProbeFailure>,
        /// The bounded set of steps the rollback must take.
        scope: RollbackScope,
    },
}

/// One probe's result, kept so a report can say what was actually checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// Probe that ran.
    pub kind: ProbeKind,
    /// Status code observed, for the report.
    pub status_code: u16,
    /// Whether the probe passed.
    pub passed: bool,
}

/// The whole doctor report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// Probes that ran, in order.
    pub outcomes: Vec<ProbeOutcome>,
    /// The verdict.
    pub verdict: DoctorVerdict,
}

impl DoctorReport {
    /// Whether the new build is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.verdict == DoctorVerdict::Healthy
    }

    /// The refusal, when the new build is not healthy.
    ///
    /// # Errors
    ///
    /// Fails when the report is healthy, so a caller cannot report a rollback that
    /// the doctor never asked for.
    pub fn refusal(&self) -> Result<AxiomError, AxiomError> {
        match &self.verdict {
            DoctorVerdict::Healthy => Err(AxiomError::new(
                ErrorCode::Internal,
                "a healthy report is not a refusal",
            )),
            DoctorVerdict::Rollback { failures, .. } => Ok(failures[0].to_error()),
        }
    }
}

/// Run every probe and decide whether the new build may stay.
///
/// The decision is fail-closed in three ways: a transport that never answered is a
/// failure, a non-success status is a failure, and a success status whose body is
/// not the expected document or does not carry the expected values is a failure.
///
/// # Errors
///
/// Refuses an expectation that cannot be checked (an empty component or version, or
/// a zero protocol version), because a probe run against no expectation would pass
/// vacuously.
pub fn doctor(
    runner: &dyn ProbeRunner,
    expectations: &Expectations,
) -> Result<DoctorReport, AxiomError> {
    validate_expectations(expectations)?;
    let mut outcomes = Vec::new();
    let mut failures = Vec::new();
    for kind in ProbeKind::all() {
        let response = runner.run(*kind);
        let outcome = check(*kind, &response, expectations);
        if let Err(failure) = outcome {
            failures.push(failure);
            outcomes.push(ProbeOutcome {
                kind: *kind,
                status_code: response.status_code,
                passed: false,
            });
        } else {
            outcomes.push(ProbeOutcome {
                kind: *kind,
                status_code: response.status_code,
                passed: true,
            });
        }
    }
    let verdict = if failures.is_empty() {
        DoctorVerdict::Healthy
    } else {
        let scopes: Vec<RollbackScope> = failures
            .iter()
            .map(|failure| RollbackScope::for_failure(failure.kind))
            .collect();
        let scope = RollbackScope::union(&scopes).expect("at least one failure");
        DoctorVerdict::Rollback { failures, scope }
    };
    Ok(DoctorReport { outcomes, verdict })
}

/// Check one response against the probe's contract.
fn check(
    kind: ProbeKind,
    response: &ProbeResponse,
    expectations: &Expectations,
) -> Result<(), ProbeFailure> {
    let fail = |rule: &'static str, observed: String| ProbeFailure {
        kind,
        rule,
        observed: redact::scrub(&observed),
    };
    if let Some(reason) = &response.transport_error {
        return Err(fail("transport_error", reason.clone()));
    }
    if response.body.len() > MAX_BODY_BYTES {
        return Err(fail(
            "body_too_large",
            format!("bytes={} limit={MAX_BODY_BYTES}", response.body.len()),
        ));
    }
    if !response.status_is_success() {
        return Err(fail(
            "status_not_success",
            format!("status={}", response.status_code),
        ));
    }
    let document: serde_json::Value = serde_json::from_str(&response.body).map_err(|_| {
        fail(
            "body_not_the_expected_document",
            format!("bytes={} is not a JSON document", response.body.len()),
        )
    })?;
    let object = document.as_object().ok_or_else(|| {
        fail(
            "body_not_the_expected_document",
            "the body is not a JSON object".to_string(),
        )
    })?;
    match kind {
        ProbeKind::Health => {
            let status = object.get("status").and_then(|value| value.as_str());
            if status != Some("ok") {
                return Err(fail(
                    "status_field_not_ok",
                    format!("status={}", status.unwrap_or("absent")),
                ));
            }
            let component = object.get("component").and_then(|value| value.as_str());
            if component != Some(expectations.component.as_str()) {
                return Err(fail(
                    "component_mismatch",
                    format!(
                        "expected={} actual={}",
                        expectations.component,
                        component.unwrap_or("absent")
                    ),
                ));
            }
            let version = object.get("version").and_then(|value| value.as_str());
            if version != Some(expectations.version.as_str()) {
                return Err(fail(
                    "version_mismatch",
                    format!(
                        "expected={} actual={}",
                        expectations.version,
                        version.unwrap_or("absent")
                    ),
                ));
            }
        }
        ProbeKind::Handshake => {
            let protocol = object.get("protocol").and_then(|value| value.as_str());
            if protocol != Some(MCP_PROTOCOL) {
                return Err(fail(
                    "handshake_protocol_mismatch",
                    format!("expected={MCP_PROTOCOL} actual={}", protocol.unwrap_or("absent")),
                ));
            }
            let version = object
                .get("protocol_version")
                .and_then(serde_json::Value::as_u64);
            if version != Some(u64::from(expectations.protocol_version)) {
                return Err(fail(
                    "handshake_version_mismatch",
                    format!(
                        "expected={} actual={}",
                        expectations.protocol_version,
                        version.map_or_else(|| "absent".to_string(), |v| v.to_string())
                    ),
                ));
            }
            let capabilities = object.get("capabilities").and_then(|value| value.as_array());
            match capabilities {
                Some(list) if !list.is_empty() => {}
                _ => {
                    return Err(fail(
                        "handshake_capabilities_missing",
                        "capabilities=absent-or-empty".to_string(),
                    ))
                }
            }
        }
        ProbeKind::Schema => {
            let graph = object
                .get("graph_schema")
                .and_then(serde_json::Value::as_u64);
            if graph != Some(u64::from(expectations.graph_schema)) {
                return Err(fail(
                    "graph_schema_mismatch",
                    format!(
                        "expected={} actual={}",
                        expectations.graph_schema,
                        graph.map_or_else(|| "absent".to_string(), |v| v.to_string())
                    ),
                ));
            }
            let control = object
                .get("control_api")
                .and_then(serde_json::Value::as_u64);
            if control != Some(u64::from(expectations.control_api)) {
                return Err(fail(
                    "control_api_mismatch",
                    format!(
                        "expected={} actual={}",
                        expectations.control_api,
                        control.map_or_else(|| "absent".to_string(), |v| v.to_string())
                    ),
                ));
            }
            let queue = object
                .get("queue_schema")
                .and_then(serde_json::Value::as_u64);
            if queue != Some(u64::from(crate::version::QUEUE_SCHEMA_VERSION)) {
                return Err(fail(
                    "queue_schema_mismatch",
                    format!(
                        "expected={} actual={}",
                        crate::version::QUEUE_SCHEMA_VERSION,
                        queue.map_or_else(|| "absent".to_string(), |v| v.to_string())
                    ),
                ));
            }
        }
        ProbeKind::FixtureQuery => {
            let ok = object.get("ok").and_then(serde_json::Value::as_bool);
            if ok != Some(true) {
                return Err(fail(
                    "fixture_query_not_ok",
                    format!("ok={}", ok.map_or_else(|| "absent".to_string(), |v| v.to_string())),
                ));
            }
            let records = object
                .get("records")
                .and_then(serde_json::Value::as_u64);
            match records {
                Some(count) if count >= expectations.min_fixture_records => {}
                other => {
                    return Err(fail(
                        "fixture_query_returned_too_few_records",
                        format!(
                            "expected>={} actual={}",
                            expectations.min_fixture_records,
                            other.map_or_else(|| "absent".to_string(), |v| v.to_string())
                        ),
                    ))
                }
            }
        }
    }
    Ok(())
}

/// Refuse an expectation that could only produce a vacuous pass.
fn validate_expectations(expectations: &Expectations) -> Result<(), AxiomError> {
    if expectations.component.is_empty() || expectations.version.is_empty() {
        return Err(refuse("expectations_incomplete", &expectations.component));
    }
    if expectations.protocol_version == 0 {
        return Err(refuse("expectations_protocol_version_absent", "0"));
    }
    Ok(())
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the post-update doctor request is not checkable",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const VERSION: &str = "0.1.0";
    const PROTOCOL_VERSION: u32 = 1;

    struct Fixture {
        responses: BTreeMap<ProbeKind, ProbeResponse>,
    }

    impl Fixture {
        fn healthy(expectations: &Expectations) -> Self {
            let mut responses = BTreeMap::new();
            responses.insert(
                ProbeKind::Health,
                ProbeResponse::new(
                    200,
                    &format!(
                        "{{\"status\":\"ok\",\"component\":\"{}\",\"version\":\"{}\"}}",
                        expectations.component, expectations.version
                    ),
                ),
            );
            responses.insert(
                ProbeKind::Handshake,
                ProbeResponse::new(
                    200,
                    &format!(
                        "{{\"protocol\":\"{MCP_PROTOCOL}\",\"protocol_version\":{},\"capabilities\":[\"query\"]}}",
                        expectations.protocol_version
                    ),
                ),
            );
            responses.insert(
                ProbeKind::Schema,
                ProbeResponse::new(
                    200,
                    &format!(
                        "{{\"graph_schema\":{},\"control_api\":{},\"queue_schema\":{}}}",
                        expectations.graph_schema,
                        expectations.control_api,
                        crate::version::QUEUE_SCHEMA_VERSION
                    ),
                ),
            );
            responses.insert(
                ProbeKind::FixtureQuery,
                ProbeResponse::new(200, "{\"ok\":true,\"records\":3}"),
            );
            Self { responses }
        }

        fn with(mut self, kind: ProbeKind, response: ProbeResponse) -> Self {
            self.responses.insert(kind, response);
            self
        }
    }

    impl ProbeRunner for Fixture {
        fn run(&self, kind: ProbeKind) -> ProbeResponse {
            self.responses
                .get(&kind)
                .cloned()
                .unwrap_or_else(|| ProbeResponse::transport_failure("the fixture has no answer"))
        }
    }

    fn expectations() -> Expectations {
        Expectations::core(VERSION, PROTOCOL_VERSION)
    }

    fn failures(report: &DoctorReport) -> Vec<ProbeFailure> {
        match &report.verdict {
            DoctorVerdict::Healthy => Vec::new(),
            DoctorVerdict::Rollback { failures, .. } => failures.clone(),
        }
    }

    fn scope(report: &DoctorReport) -> RollbackScope {
        match &report.verdict {
            DoctorVerdict::Healthy => panic!("a healthy report has no rollback scope"),
            DoctorVerdict::Rollback { scope, .. } => scope.clone(),
        }
    }

    #[test]
    fn every_probe_matching_its_contract_is_healthy() {
        let expectations = expectations();
        let report = doctor(&Fixture::healthy(&expectations), &expectations)
            .expect("the expectations are checkable");
        assert!(report.is_healthy());
        assert_eq!(report.outcomes.len(), ProbeKind::all().len());
        assert!(report.outcomes.iter().all(|outcome| outcome.passed));
        assert!(report.refusal().is_err());
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.kind)
                .collect::<Vec<_>>(),
            ProbeKind::all().to_vec()
        );
    }

    #[test]
    fn a_success_status_with_a_refused_body_is_not_healthy() {
        let expectations = expectations();
        let cases = [
            (
                ProbeKind::Health,
                "{\"status\":\"degraded\",\"component\":\"axiom-graphd\",\"version\":\"0.1.0\"}",
                "status_field_not_ok",
            ),
            (
                ProbeKind::Health,
                "<html><body>ok</body></html>",
                "body_not_the_expected_document",
            ),
            (
                ProbeKind::Handshake,
                "{\"protocol\":\"other\",\"protocol_version\":1,\"capabilities\":[\"query\"]}",
                "handshake_protocol_mismatch",
            ),
            (
                ProbeKind::Handshake,
                "{\"protocol\":\"mcp\",\"protocol_version\":0,\"capabilities\":[\"query\"]}",
                "handshake_version_mismatch",
            ),
            (
                ProbeKind::Handshake,
                "{\"protocol\":\"mcp\",\"protocol_version\":1,\"capabilities\":[]}",
                "handshake_capabilities_missing",
            ),
            (
                ProbeKind::Schema,
                "{\"graph_schema\":2,\"control_api\":1,\"queue_schema\":1}",
                "graph_schema_mismatch",
            ),
            (
                ProbeKind::FixtureQuery,
                "{\"ok\":false,\"records\":3}",
                "fixture_query_not_ok",
            ),
        ];
        for (kind, body, expected) in cases {
            let fixture = Fixture::healthy(&expectations).with(kind, ProbeResponse::new(200, body));
            let report = doctor(&fixture, &expectations).expect("checkable");
            assert!(!report.is_healthy(), "{kind:?} accepted {body}");
            let failures = failures(&report);
            assert_eq!(failures.len(), 1, "{kind:?} produced {failures:?}");
            assert_eq!(failures[0].kind, kind);
            assert_eq!(failures[0].rule, expected, "for {body}");
            assert_eq!(report.refusal().expect("a refusal").code(), ErrorCode::NotReady);
        }
    }

    #[test]
    fn a_transport_failure_or_a_non_success_status_is_a_failure() {
        let expectations = expectations();
        let fixture = Fixture::healthy(&expectations).with(
            ProbeKind::Health,
            ProbeResponse::transport_failure("connection refused to the new process"),
        );
        let report = doctor(&fixture, &expectations).expect("checkable");
        assert_eq!(failures(&report)[0].rule, "transport_error");

        let fixture = Fixture::healthy(&expectations).with(
            ProbeKind::FixtureQuery,
            ProbeResponse::new(500, "{\"ok\":true,\"records\":3}"),
        );
        let report = doctor(&fixture, &expectations).expect("checkable");
        let failures = failures(&report);
        assert_eq!(failures[0].rule, "status_not_success");
        assert_eq!(review_scope(&report), vec![
            RollbackStep::StopNewProcess,
            RollbackStep::RepointPrevious,
            RollbackStep::ClearUnpublishedOutbox,
        ]);
    }

    fn review_scope(report: &DoctorReport) -> Vec<RollbackStep> {
        scope(report).steps()
    }

    #[test]
    fn a_schema_divergence_adds_the_compatible_backup_restore() {
        let expectations = expectations();
        let fixture = Fixture::healthy(&expectations).with(
            ProbeKind::Schema,
            ProbeResponse::new(
                200,
                "{\"graph_schema\":1,\"control_api\":1,\"queue_schema\":9}",
            ),
        );
        let report = doctor(&fixture, &expectations).expect("checkable");
        assert_eq!(failures(&report)[0].rule, "queue_schema_mismatch");
        let scope = scope(&report);
        assert!(scope.contains(RollbackStep::StopNewProcess));
        assert!(scope.contains(RollbackStep::RepointPrevious));
        assert!(
            scope.contains(RollbackStep::RestoreCompatibleBackup),
            "a schema divergence must restore the compatible backup"
        );
        assert!(!scope.contains(RollbackStep::ClearUnpublishedOutbox));
        assert!(scope.is_bounded());
    }

    #[test]
    fn a_fixture_query_divergence_adds_the_outbox_clear() {
        let expectations = expectations();
        let fixture = Fixture::healthy(&expectations)
            .with(ProbeKind::FixtureQuery, ProbeResponse::new(200, "{\"ok\":true,\"records\":0}"));
        let report = doctor(&fixture, &expectations).expect("checkable");
        assert_eq!(
            failures(&report)[0].rule,
            "fixture_query_returned_too_few_records"
        );
        let scope = scope(&report);
        assert!(scope.contains(RollbackStep::ClearUnpublishedOutbox));
        assert!(!scope.contains(RollbackStep::RestoreCompatibleBackup));
        assert!(scope.is_bounded());
    }

    #[test]
    fn every_scope_is_bounded_and_no_failure_ever_produces_an_empty_or_wide_one() {
        let expectations = expectations();
        for kind in ProbeKind::all() {
            let scope = RollbackScope::for_failure(*kind);
            assert!(scope.is_bounded(), "{kind:?} produced an unbounded scope");
            assert!(scope.contains(RollbackStep::StopNewProcess));
            assert!(scope.contains(RollbackStep::RepointPrevious));
            for step in scope.steps() {
                assert!(RollbackStep::all().contains(&step));
            }
            assert!(!scope.steps().is_empty());
        }
        assert!(RollbackScope::union(&[]).is_none());
    }

    #[test]
    fn several_failures_produce_the_union_of_their_scopes() {
        let expectations = expectations();
        let fixture = Fixture::healthy(&expectations)
            .with(
                ProbeKind::Schema,
                ProbeResponse::new(
                    200,
                    "{\"graph_schema\":1,\"control_api\":1,\"queue_schema\":9}",
                ),
            )
            .with(
                ProbeKind::FixtureQuery,
                ProbeResponse::new(200, "{\"ok\":true,\"records\":0}"),
            )
            .with(
                ProbeKind::Health,
                ProbeResponse::new(503, "{\"status\":\"starting\"}"),
            );
        let report = doctor(&fixture, &expectations).expect("checkable");
        assert_eq!(failures(&report).len(), 3);
        let scope = scope(&report);
        assert_eq!(
            scope.steps(),
            RollbackStep::all().to_vec(),
            "the union covers every step the failures named"
        );
        assert!(scope.is_bounded());
        let error = report.refusal().expect("a refusal");
        assert_eq!(error.code(), ErrorCode::NotReady);
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("health"),
            "the first failure in probe order is reported"
        );
    }

    #[test]
    fn an_observation_is_redacted_before_it_is_recorded() {
        let expectations = expectations();
        let fixture = Fixture::healthy(&expectations).with(
            ProbeKind::Health,
            ProbeResponse::transport_failure("connection to 10.0.0.7 with token=abc123 refused"),
        );
        let report = doctor(&fixture, &expectations).expect("checkable");
        let observed = &failures(&report)[0].observed;
        assert!(
            !observed.contains("abc123"),
            "a credential must not survive into the report: {observed}"
        );
    }

    #[test]
    fn a_body_at_the_bound_is_accepted_and_one_byte_over_is_refused() {
        let expectations = expectations();
        let base = "{\"ok\":true,\"records\":1}";
        let padded = format!(
            "{base}{}",
            " ".repeat(MAX_BODY_BYTES - base.len())
        );
        assert_eq!(padded.len(), MAX_BODY_BYTES);
        let fixture =
            Fixture::healthy(&expectations).with(ProbeKind::FixtureQuery, ProbeResponse::new(200, &padded));
        let report = doctor(&fixture, &expectations).expect("checkable");
        assert!(report.is_healthy(), "a body at the bound is accepted");

        let over = format!("{padded} ");
        let fixture =
            Fixture::healthy(&expectations).with(ProbeKind::FixtureQuery, ProbeResponse::new(200, &over));
        let report = doctor(&fixture, &expectations).expect("checkable");
        assert_eq!(failures(&report)[0].rule, "body_too_large");
    }

    #[test]
    fn an_uncheckable_expectation_is_refused() {
        let fixture = Fixture::healthy(&expectations());
        let mut empty_component = expectations();
        empty_component.component = String::new();
        assert_eq!(
            doctor(&fixture, &empty_component)
                .expect_err("an empty component is not checkable")
                .details()
                .get("rule")
                .map(String::as_str),
            Some("expectations_incomplete")
        );
        let mut empty_version = expectations();
        empty_version.version = String::new();
        assert!(doctor(&fixture, &empty_version).is_err());
        let mut no_protocol = expectations();
        no_protocol.protocol_version = 0;
        assert_eq!(
            doctor(&fixture, &no_protocol)
                .expect_err("protocol version 0 is not checkable")
                .details()
                .get("rule")
                .map(String::as_str),
            Some("expectations_protocol_version_absent")
        );
    }
}
