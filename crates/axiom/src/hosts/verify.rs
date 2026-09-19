//! Post-apply host verification: the host really speaks MCP (task E-031).
//!
//! `25-HOST-ADAPTERS-AND-HOOKS.md` section 4 puts a verification step after the
//! host configuration is written, and task E-031 fixes what that step must prove:
//! **a real `tools/list` and a bounded test query must succeed**. A server that is
//! configured, or a process that merely starts, is not an integration.
//!
//! ## Starting is not integrating
//!
//! The failure this module is built against is exactly the one an installer
//! produces: the endpoint answers, `initialize` returns a well-formed
//! `serverInfo`, the process is alive and the launcher reports success - and the
//! host still has no usable tool surface, because `tools/list` is empty, missing,
//! or refused. So the sequence here is three real MCP JSON-RPC requests:
//!
//! 1. `initialize` - must return a body this build parses whose `serverInfo`
//!    names the expected server. A status code is never the verdict.
//! 2. `tools/list` - must return at least one named tool. An `initialize` that
//!    succeeded but a `tools/list` that did not is reported as
//!    [`RULE_START_ONLY`], because that is precisely "the process started".
//! 3. `tools/call` on the expected read tool with a **bounded** test query - must
//!    return parseable content carrying at least the expected number of records.
//!    An answering tool that returns nothing is [`RULE_TEST_QUERY_EMPTY`], not a
//!    pass.
//!
//! ## Nothing here opens a socket
//!
//! Requirements arrive through the [`HostTransport`] abstraction, so the same
//! decision runs over a live host and over the in-memory doubles in the tests.
//! This module never spawns a process, never reads a real host configuration and
//! never writes a file: it decides whether an already-applied configuration is
//! integrated, from answers the caller supplies.
//!
//! ## Recorded, unrun on this machine
//!
//! No Codex, Claude, Gemini or AGY host is installed in the build environment, so
//! the live effect of this verification is recorded `not_run` with the
//! reproducible command `axiom host verify --host <host> --json` on a machine that
//! has the host installed. The decision logic itself is covered by the tests
//! below through the transport double.

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::Value;

/// Schema revision of the verification report this module emits.
pub const VERIFY_SCHEMA_VERSION: u32 = 1;
/// Upper bound on one JSON-RPC body this module will parse.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Largest accepted number of tools a `tools/list` answer may carry.
pub const MAX_TOOLS: usize = 512;
/// Largest accepted tool name.
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Largest accepted bounded test query.
pub const MAX_TEST_QUERY_BYTES: usize = 1024;
/// Host bound on one request, which a transport must respect.
pub const REQUEST_TIMEOUT_MS: u64 = 10_000;
/// Protocol marker this build's handshake expects, as `update::verify` uses it.
pub const MCP_PROTOCOL: &str = "mcp";
/// Rows the bounded test query asks for: one is enough to prove indexing.
pub const TEST_QUERY_LIMIT: u64 = 1;

/// Managed server name every host adapter installs.
pub const MANAGED_SERVER: &str = "axiom-graphd";
/// Read tool the bounded test query is sent to.
pub const TEST_QUERY_TOOL: &str = "graph_query";

/// Refusal: the transport itself never answered.
pub const RULE_TRANSPORT_FAILED: &str = "transport-failed";
/// Refusal: the transport answered with a non-success status.
pub const RULE_STATUS_NOT_SUCCESS: &str = "status-not-success";
/// Refusal: an answer body larger than this module will parse.
pub const RULE_BODY_TOO_LARGE: &str = "body-too-large";
/// Refusal: the `initialize` body is not the expected document.
pub const RULE_INITIALIZE_UNPARSED: &str = "initialize-unparsed";
/// Refusal: `initialize` answered, but for a different server.
pub const RULE_INITIALIZE_NOT_SERVING: &str = "initialize-not-serving";
/// Refusal: the host answered `initialize` but served no tool surface.
pub const RULE_START_ONLY: &str = "process-started-is-not-integration";
/// Refusal: the expected tool is absent from `tools/list`.
pub const RULE_TOOL_NOT_FOUND: &str = "tool-not-found";
/// Refusal: the bounded test query did not answer with a parseable result.
pub const RULE_TEST_QUERY_UNPARSED: &str = "test-query-unparsed";
/// Refusal: the bounded test query answered, but indexed nothing.
pub const RULE_TEST_QUERY_EMPTY: &str = "test-query-empty";

fn refuse(rule: &str, message: impl AsRef<str>) -> AxiomError {
    AxiomError::new(ErrorCode::NotReady, message).with_detail("rule", rule)
}

/// The MCP requests this verification performs, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifyStep {
    /// `initialize`: the process answers as an MCP server.
    Initialize,
    /// `tools/list`: the host has a usable tool surface.
    ToolsList,
    /// `tools/call`: a bounded read query actually returns records.
    TestQuery,
}

impl VerifyStep {
    /// The JSON-RPC method this step sends.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::ToolsList => "tools/list",
            Self::TestQuery => "tools/call",
        }
    }

    /// The stable wire spelling of this step.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::ToolsList => "tools_list",
            Self::TestQuery => "test_query",
        }
    }

    /// Every step, in run order.
    #[must_use]
    pub const fn all() -> &'static [VerifyStep] {
        &[Self::Initialize, Self::ToolsList, Self::TestQuery]
    }
}

/// One request's raw answer, as the transport observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcResponse {
    /// Status code the transport returned.
    pub status_code: u16,
    /// Body the transport returned.
    pub body: String,
    /// Whether the transport itself failed.
    pub transport_error: Option<String>,
}

impl RpcResponse {
    /// A response with a body, as a double and a real transport both produce.
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
    /// A precondition only: [`verify_mcp`] never treats a status as the verdict.
    #[must_use]
    pub const fn status_is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }
}

/// What the verification may be run against.
///
/// A live host implements this over its MCP endpoint; the tests implement it over
/// scripted answers. The trait is deliberately request-shaped rather than
/// step-shaped, so the verification really sends `tools/list` and `tools/call`.
pub trait HostTransport {
    /// Send one JSON-RPC request and return the raw answer.
    fn request(&self, method: &str, params_json: &str) -> RpcResponse;
}
/// What the applied host configuration must be serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyExpectations {
    /// Server name `initialize` must report.
    pub server_name: String,
    /// Tool `tools/list` must expose and the test query is sent to.
    pub tool: String,
    /// Bounded test query sent to that tool.
    pub test_query: String,
    /// Minimum records the test query must return.
    pub min_records: u64,
}

impl VerifyExpectations {
    /// The expectations of one managed host install.
    #[must_use]
    pub fn managed(test_query: &str) -> Self {
        Self {
            server_name: MANAGED_SERVER.to_owned(),
            tool: TEST_QUERY_TOOL.to_owned(),
            test_query: test_query.to_owned(),
            min_records: 1,
        }
    }
}

/// One refused step, with the rule it violated and the redacted observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFailure {
    /// Step that failed.
    pub step: VerifyStep,
    /// Stable name of the violated rule.
    pub rule: &'static str,
    /// Redacted observation that made the rule fail.
    pub observed: String,
}

impl VerifyFailure {
    /// The failure as an error, using only allowed and redacted details.
    #[must_use]
    pub fn to_error(&self) -> AxiomError {
        refuse(
            self.rule,
            "the host verification refused the applied configuration",
        )
        .with_detail("component", self.step.as_str())
        .with_detail("observed", &self.observed)
    }
}

/// The verdict of one host verification run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyVerdict {
    /// `initialize`, `tools/list` and the bounded test query all succeeded.
    Integrated,
    /// At least one step diverged; the host is not integrated.
    NotIntegrated {
        /// Every failure, in step order.
        failures: Vec<VerifyFailure>,
    },
}

/// One step's result, kept so a report can say what was actually checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcome {
    /// Step that ran.
    pub step: VerifyStep,
    /// Status code observed, for the report.
    pub status_code: u16,
    /// Whether the step passed.
    pub passed: bool,
}

/// The whole verification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Report schema revision.
    pub schema_version: u32,
    /// Model Context Protocol marker this build expects.
    pub protocol: String,
    /// Steps that ran, in order.
    pub steps: Vec<StepOutcome>,
    /// The verdict.
    pub verdict: VerifyVerdict,
}

impl VerifyReport {
    /// Whether the applied configuration is integrated.
    #[must_use]
    pub fn is_integrated(&self) -> bool {
        self.verdict == VerifyVerdict::Integrated
    }

    /// True when the host answered `initialize` but never served a tool surface.
    ///
    /// This is the "a running process is not an integration" state the card names:
    /// a caller that only checked that the process started reports this as the
    /// reason no integration can be claimed.
    #[must_use]
    pub fn started_without_tools(&self) -> bool {
        match &self.verdict {
            VerifyVerdict::Integrated => false,
            VerifyVerdict::NotIntegrated { failures } => failures
                .iter()
                .any(|failure| failure.rule == RULE_START_ONLY),
        }
    }

    /// The refusal, when the host is not integrated.
    ///
    /// # Errors
    /// Fails when the report is integrated, so a caller cannot report a refusal
    /// the verification never made.
    pub fn refusal(&self) -> Result<AxiomError, AxiomError> {
        match &self.verdict {
            VerifyVerdict::Integrated => Err(AxiomError::new(
                ErrorCode::Internal,
                "an integrated report is not a refusal",
            )),
            VerifyVerdict::NotIntegrated { failures } => Ok(failures[0].to_error()),
        }
    }

    /// The report as the JSON object `axiom host verify --json` emits.
    #[must_use]
    pub fn render_json(&self) -> Value {
        let integrated = self.is_integrated();
        serde_json::json!({
            "schema_version": self.schema_version,
            "protocol": self.protocol,
            "integrated": integrated,
            "started_without_tools": self.started_without_tools(),
            "steps": self
                .steps
                .iter()
                .map(|step| serde_json::json!({
                    "step": step.step.as_str(),
                    "method": step.step.method(),
                    "status_code": step.status_code,
                    "passed": step.passed,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// Run the three-step MCP verification and decide whether the host is integrated.
///
/// The decision is fail-closed: a transport that never answered, a non-success
/// status, and a success status whose body is not the expected document are all
/// failures, and an answering `initialize` with no tool surface is
/// [`RULE_START_ONLY`] rather than a pass.
///
/// # Errors
/// Refuses an expectation that cannot be checked (an empty server name, an empty
/// tool, an empty or oversized test query, or a zero record floor), because a
/// verification run against no expectation would pass vacuously.
pub fn verify_mcp(
    transport: &dyn HostTransport,
    expectations: &VerifyExpectations,
) -> Result<VerifyReport, AxiomError> {
    validate_expectations(expectations)?;
    let mut steps = Vec::new();
    let mut failures = Vec::new();
    let mut listed = Vec::new();
    let mut initialized = false;

    for step in VerifyStep::all() {
        let params = match step {
            VerifyStep::Initialize => serde_json::json!({
                "clientInfo": { "name": "axiom" },
                "protocol": MCP_PROTOCOL,
            })
            .to_string(),
            VerifyStep::ToolsList => "{}".to_owned(),
            VerifyStep::TestQuery => serde_json::json!({
                "name": expectations.tool,
                "arguments": {
                    "query": expectations.test_query,
                    "limit": TEST_QUERY_LIMIT,
                },
            })
            .to_string(),
        };
        let response = transport.request(step.method(), &params);
        let outcome = check(*step, &response, expectations, initialized, &mut listed);
        match outcome {
            Ok(()) => {
                if *step == VerifyStep::Initialize {
                    initialized = true;
                }
                steps.push(StepOutcome {
                    step: *step,
                    status_code: response.status_code,
                    passed: true,
                });
            }
            Err(failure) => {
                steps.push(StepOutcome {
                    step: *step,
                    status_code: response.status_code,
                    passed: false,
                });
                failures.push(failure);
                break;
            }
        }
    }

    let verdict = if failures.is_empty() {
        VerifyVerdict::Integrated
    } else {
        VerifyVerdict::NotIntegrated { failures }
    };
    Ok(VerifyReport {
        schema_version: VERIFY_SCHEMA_VERSION,
        protocol: MCP_PROTOCOL.to_owned(),
        steps,
        verdict,
    })
}

fn validate_expectations(expectations: &VerifyExpectations) -> Result<(), AxiomError> {
    if expectations.server_name.trim().is_empty() {
        return Err(refuse(
            RULE_INITIALIZE_NOT_SERVING,
            "the expected server name is empty, so a handshake cannot be checked",
        ));
    }
    if expectations.tool.trim().is_empty() {
        return Err(refuse(
            RULE_TOOL_NOT_FOUND,
            "the expected tool is empty, so a tool surface cannot be checked",
        ));
    }
    if expectations.test_query.trim().is_empty() {
        return Err(refuse(
            RULE_TEST_QUERY_EMPTY,
            "the bounded test query is empty, so a test query cannot be checked",
        ));
    }
    if expectations.test_query.len() > MAX_TEST_QUERY_BYTES {
        return Err(refuse(
            RULE_BODY_TOO_LARGE,
            "the bounded test query is larger than this module will send",
        )
        .with_detail("observed", expectations.test_query.len().to_string()));
    }
    if expectations.min_records == 0 {
        return Err(refuse(
            RULE_TEST_QUERY_EMPTY,
            "a zero record floor would pass vacuously",
        ));
    }
    Ok(())
}
fn rule_for_no_result(step: VerifyStep) -> &'static str {
    match step {
        VerifyStep::Initialize => RULE_INITIALIZE_UNPARSED,
        VerifyStep::ToolsList => RULE_START_ONLY,
        VerifyStep::TestQuery => RULE_TEST_QUERY_UNPARSED,
    }
}

/// A failed `tools/list` after a successful `initialize` is the "the process
/// started, nothing more" case, whatever the underlying transport reported: the
/// host answered as an MCP server and still served no tool surface.
fn escalation(step: VerifyStep, initialized: bool, base: &'static str) -> &'static str {
    if initialized && step == VerifyStep::ToolsList {
        RULE_START_ONLY
    } else {
        base
    }
}

fn check(
    step: VerifyStep,
    response: &RpcResponse,
    expectations: &VerifyExpectations,
    initialized: bool,
    listed: &mut Vec<String>,
) -> Result<(), VerifyFailure> {
    let fail = |rule: &'static str, observed: String| VerifyFailure {
        step,
        rule,
        observed,
    };
    if let Some(reason) = &response.transport_error {
        return Err(fail(
            escalation(step, initialized, RULE_TRANSPORT_FAILED),
            format!("transport: {reason}"),
        ));
    }
    if !response.status_is_success() {
        return Err(fail(
            escalation(step, initialized, RULE_STATUS_NOT_SUCCESS),
            format!("status: {}", response.status_code),
        ));
    }
    if response.body.len() > MAX_BODY_BYTES {
        return Err(fail(
            escalation(step, initialized, RULE_BODY_TOO_LARGE),
            format!("body: {} bytes", response.body.len()),
        ));
    }
    let parsed = serde_json::from_str::<Value>(&response.body);
    let Ok(value) = parsed else {
        return Err(fail(
            escalation(step, initialized, rule_for_no_result(step)),
            format!("body: not json ({} bytes)", response.body.len()),
        ));
    };
    let Some(result) = value.get("result") else {
        let code = value
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64);
        let observed = match code {
            Some(code) => format!("rpc error code {code}"),
            None => "no result member".to_owned(),
        };
        return Err(fail(
            escalation(step, initialized, rule_for_no_result(step)),
            observed,
        ));
    };
    match step {
        VerifyStep::Initialize => {
            let name = result
                .get("serverInfo")
                .and_then(|info| info.get("name"))
                .and_then(Value::as_str);
            match name {
                Some(name) if name == expectations.server_name => Ok(()),
                Some(name) => Err(fail(
                    RULE_INITIALIZE_NOT_SERVING,
                    format!("serverInfo.name: {name}"),
                )),
                None => Err(fail(
                    RULE_INITIALIZE_UNPARSED,
                    "serverInfo.name: absent".to_owned(),
                )),
            }
        }
        VerifyStep::ToolsList => {
            let Some(tools) = result.get("tools").and_then(Value::as_array) else {
                return Err(fail(
                    RULE_START_ONLY,
                    "tools/list: no tools array".to_owned(),
                ));
            };
            if tools.len() > MAX_TOOLS {
                return Err(fail(RULE_BODY_TOO_LARGE, format!("tools: {}", tools.len())));
            }
            for tool in tools {
                let Some(name) = tool.get("name").and_then(Value::as_str) else {
                    return Err(fail(RULE_START_ONLY, "tools/list: unnamed tool".to_owned()));
                };
                if name.is_empty() || name.len() > MAX_TOOL_NAME_BYTES {
                    return Err(fail(
                        RULE_START_ONLY,
                        format!("tools/list: unusable tool name ({} bytes)", name.len()),
                    ));
                }
                listed.push(name.to_owned());
            }
            if listed.is_empty() {
                return Err(fail(RULE_START_ONLY, "tools/list: 0 tools".to_owned()));
            }
            if !listed.iter().any(|name| name == &expectations.tool) {
                return Err(fail(
                    RULE_TOOL_NOT_FOUND,
                    format!("tools: {}", listed.join(",")),
                ));
            }
            Ok(())
        }
        VerifyStep::TestQuery => {
            let records = count_records(result);
            if records < expectations.min_records {
                return Err(fail(
                    RULE_TEST_QUERY_EMPTY,
                    format!("tools/call: {records} records"),
                ));
            }
            Ok(())
        }
    }
}

/// Count the records one `tools/call` result carries.
///
/// A result may carry a flat `rows`/`records` array, or MCP content blocks whose
/// text is itself a JSON document with a row array. A content block that carries
/// non-empty text but no row array still counts as one answered record, so the
/// refusal it can produce is the empty answer, not a parsing quirk.
fn count_records(result: &Value) -> u64 {
    for key in ["rows", "records"] {
        if let Some(rows) = result.get(key).and_then(Value::as_array) {
            return rows.len() as u64;
        }
    }
    let Some(content) = result.get("content").and_then(Value::as_array) else {
        return 0;
    };
    let mut total = 0_u64;
    for block in content {
        let Some(text) = block.get("text").and_then(Value::as_str) else {
            total += 1;
            continue;
        };
        if let Ok(inner) = serde_json::from_str::<Value>(text) {
            if let Some(rows) = inner.get("rows").and_then(Value::as_array) {
                total += rows.len() as u64;
                continue;
            }
            if let Some(records) = inner.get("records").and_then(Value::as_array) {
                total += records.len() as u64;
                continue;
            }
            if let Some(items) = inner.as_array() {
                total += items.len() as u64;
                continue;
            }
        }
        if !text.trim().is_empty() {
            total += 1;
        }
    }
    total
}
#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    fn rule(error: &AxiomError) -> String {
        error
            .details()
            .get("rule")
            .cloned()
            .unwrap_or_else(|| "<none>".to_owned())
    }

    fn expected() -> VerifyExpectations {
        VerifyExpectations::managed("MATCH (n) RETURN n LIMIT 1")
    }

    fn initialize_ok() -> RpcResponse {
        RpcResponse::new(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocol":"mcp","serverInfo":{"name":"axiom-graphd","version":"2.0.0"}}}"#,
        )
    }

    fn tools_ok() -> RpcResponse {
        RpcResponse::new(
            200,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"graph_query"},{"name":"graph_status"}]}}"#,
        )
    }

    fn query_ok() -> RpcResponse {
        RpcResponse::new(
            200,
            r#"{"jsonrpc":"2.0","id":3,"result":{"rows":[{"n":{"id":"node-1"}}]}}"#,
        )
    }

    /// A transport double that answers each method from a script and records the
    /// requests it actually received.
    struct Scripted {
        answers: BTreeMap<String, RpcResponse>,
        calls: RefCell<Vec<(String, String)>>,
    }

    impl Scripted {
        fn new(answers: Vec<(&str, RpcResponse)>) -> Self {
            Self {
                answers: answers
                    .into_iter()
                    .map(|(method, response)| (method.to_owned(), response))
                    .collect(),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn methods(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .map(|(method, _)| method.clone())
                .collect()
        }

        fn params_for(&self, method: &str) -> String {
            self.calls
                .borrow()
                .iter()
                .find(|(called, _)| called == method)
                .map(|(_, params)| params.clone())
                .unwrap_or_default()
        }
    }

    impl HostTransport for Scripted {
        fn request(&self, method: &str, params_json: &str) -> RpcResponse {
            self.calls
                .borrow_mut()
                .push((method.to_owned(), params_json.to_owned()));
            self.answers
                .get(method)
                .cloned()
                .unwrap_or_else(|| RpcResponse::new(404, "not found"))
        }
    }

    fn failures(report: &VerifyReport) -> &[VerifyFailure] {
        match &report.verdict {
            VerifyVerdict::Integrated => panic!("expected a refusal, got an integrated verdict"),
            VerifyVerdict::NotIntegrated { failures } => failures.as_slice(),
        }
    }

    #[test]
    fn a_real_tools_list_and_bounded_query_are_required_to_integrate() {
        let transport = Scripted::new(vec![
            ("initialize", initialize_ok()),
            ("tools/list", tools_ok()),
            ("tools/call", query_ok()),
        ]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        assert!(report.is_integrated());
        assert!(!report.started_without_tools());
        assert_eq!(report.schema_version, VERIFY_SCHEMA_VERSION);
        assert_eq!(report.protocol, MCP_PROTOCOL);
        assert_eq!(report.steps.len(), 3);
        assert!(report.steps.iter().all(|step| step.passed));
        assert_eq!(
            report
                .steps
                .iter()
                .map(|step| step.step)
                .collect::<Vec<_>>(),
            vec![
                VerifyStep::Initialize,
                VerifyStep::ToolsList,
                VerifyStep::TestQuery
            ]
        );

        // The tool surface was really listed and really queried, with a bounded
        // test query and the expected tool name.
        assert_eq!(
            transport.methods(),
            vec!["initialize", "tools/list", "tools/call"]
        );
        let params = transport.params_for("tools/call");
        assert!(params.contains(TEST_QUERY_TOOL));
        assert!(params.contains("MATCH (n) RETURN n LIMIT 1"));
        assert!(params.contains(&format!("\"limit\":{TEST_QUERY_LIMIT}")));
        assert!(report.refusal().is_err());
    }

    #[test]
    fn a_process_that_starts_without_a_tool_surface_is_not_integrated() {
        // An initialize that succeeds with an empty tool list, and one whose
        // tools/list never answers, are the same verdict: started, not integrated.
        let cases = [
            RpcResponse::new(200, r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#),
            RpcResponse::new(404, ""),
            RpcResponse::transport_failure("connection reset"),
        ];
        for tools_list in cases {
            let transport = Scripted::new(vec![
                ("initialize", initialize_ok()),
                ("tools/list", tools_list),
            ]);
            let report = verify_mcp(&transport, &expected()).expect("a verification run");
            assert!(!report.is_integrated());
            assert!(
                report.started_without_tools(),
                "an initialize-only answer must be reported as started, not integrated"
            );
            let failure = &failures(&report)[0];
            assert_eq!(failure.step, VerifyStep::ToolsList);
            assert_eq!(failure.rule, RULE_START_ONLY);
            assert_eq!(rule(&report.refusal().expect("a refusal")), RULE_START_ONLY);
        }
    }

    #[test]
    fn a_two_hundred_with_a_refused_body_is_not_a_handshake() {
        let transport = Scripted::new(vec![(
            "initialize",
            RpcResponse::new(200, r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}"#),
        )]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let failure = &failures(&report)[0];
        assert_eq!(failure.step, VerifyStep::Initialize);
        assert_eq!(failure.rule, RULE_INITIALIZE_UNPARSED);
        assert!(failure.observed.contains("-32601"));
    }

    #[test]
    fn a_different_server_name_is_refused() {
        let transport = Scripted::new(vec![(
            "initialize",
            RpcResponse::new(
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"some-other-server"}}}"#,
            ),
        )]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let failure = &failures(&report)[0];
        assert_eq!(failure.rule, RULE_INITIALIZE_NOT_SERVING);
    }

    #[test]
    fn a_tool_surface_without_the_expected_tool_is_refused() {
        let transport = Scripted::new(vec![
            ("initialize", initialize_ok()),
            (
                "tools/list",
                RpcResponse::new(
                    200,
                    r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"graph_status"}]}}"#,
                ),
            ),
        ]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let failure = &failures(&report)[0];
        assert_eq!(failure.step, VerifyStep::ToolsList);
        assert_eq!(failure.rule, RULE_TOOL_NOT_FOUND);
    }

    #[test]
    fn a_test_query_that_indexes_nothing_is_refused() {
        let transport = Scripted::new(vec![
            ("initialize", initialize_ok()),
            ("tools/list", tools_ok()),
            (
                "tools/call",
                RpcResponse::new(200, r#"{"jsonrpc":"2.0","id":3,"result":{"content":[]}}"#),
            ),
        ]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let failure = &failures(&report)[0];
        assert_eq!(failure.step, VerifyStep::TestQuery);
        assert_eq!(failure.rule, RULE_TEST_QUERY_EMPTY);
    }

    #[test]
    fn a_content_block_carrying_rows_counts_as_an_answer() {
        let transport = Scripted::new(vec![
            ("initialize", initialize_ok()),
            ("tools/list", tools_ok()),
            (
                "tools/call",
                RpcResponse::new(
                    200,
                    r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"rows\":[{\"id\":1}]}"}]}}"#,
                ),
            ),
        ]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        assert!(report.is_integrated());
    }

    #[test]
    fn a_transport_failure_is_a_failure() {
        let transport = Scripted::new(vec![(
            "initialize",
            RpcResponse::transport_failure("connection refused"),
        )]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let failure = &failures(&report)[0];
        assert_eq!(failure.rule, RULE_TRANSPORT_FAILED);
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let oversized = format!(r#"{{"result":"{}"}}"#, "x".repeat(MAX_BODY_BYTES));
        let transport = Scripted::new(vec![("initialize", RpcResponse::new(200, &oversized))]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let failure = &failures(&report)[0];
        assert_eq!(failure.rule, RULE_BODY_TOO_LARGE);
    }

    #[test]
    fn an_expectation_that_cannot_be_checked_is_refused() {
        let transport = Scripted::new(vec![("initialize", initialize_ok())]);
        let mut empty_tool = expected();
        empty_tool.tool = String::new();
        let error = verify_mcp(&transport, &empty_tool).expect_err("an empty tool is refused");
        assert_eq!(rule(&error), RULE_TOOL_NOT_FOUND);

        let empty_query = VerifyExpectations::managed("");
        let error =
            verify_mcp(&transport, &empty_query).expect_err("an empty test query is refused");
        assert_eq!(rule(&error), RULE_TEST_QUERY_EMPTY);

        let mut huge_query = expected();
        huge_query.test_query = "q".repeat(MAX_TEST_QUERY_BYTES + 1);
        let error =
            verify_mcp(&transport, &huge_query).expect_err("an oversized test query is refused");
        assert_eq!(rule(&error), RULE_BODY_TOO_LARGE);

        let mut no_records = expected();
        no_records.min_records = 0;
        let error = verify_mcp(&transport, &no_records).expect_err("a zero floor is refused");
        assert_eq!(rule(&error), RULE_TEST_QUERY_EMPTY);
    }

    #[test]
    fn the_report_renders_the_checked_steps_as_json() {
        let transport = Scripted::new(vec![
            ("initialize", initialize_ok()),
            ("tools/list", tools_ok()),
            ("tools/call", query_ok()),
        ]);
        let report = verify_mcp(&transport, &expected()).expect("a verification run");
        let rendered = report.render_json();
        assert_eq!(rendered["integrated"], Value::from(true));
        assert_eq!(rendered["started_without_tools"], Value::from(false));
        assert_eq!(rendered["protocol"], Value::from(MCP_PROTOCOL));
        assert_eq!(
            rendered["schema_version"],
            Value::from(VERIFY_SCHEMA_VERSION)
        );
        assert_eq!(rendered["steps"].as_array().map(Vec::len), Some(3));
        assert_eq!(rendered["steps"][1]["method"], Value::from("tools/list"));
    }
}
