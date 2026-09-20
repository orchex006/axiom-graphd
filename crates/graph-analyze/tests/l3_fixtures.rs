//! F-006 conformance vectors for the Level-3 HTTP, SQL and messaging adapters.
//!
//! Every vector is static text under `fixtures/l3/`: source text for the
//! language adapters and declarative join text for the HTTP join. Nothing here
//! executes user source, replays a runtime log or captures traffic.
//!
//! Each rule is asserted in both directions. A supported literal form must
//! produce the documented fact, and a non-literal or boundary form must produce
//! exactly the documented `PATTERN_*` / `REASON_*` refusal, or no fact at all.
//! The refusal assertions are the negative half of task F-006 AC2.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use graph_analyze::l3::angular_http;
use graph_analyze::l3::dotnet_routes::{self, HttpVerb};
use graph_analyze::l3::http_join::{self, HttpClientFact, HttpEndpointFact, SolutionMapping};
use graph_analyze::l3::messaging::{self, ConfiguredTopic, MessagingConfig, MessagingRole};
use graph_analyze::l3::minimal_api;
use graph_analyze::l3::sql_literals::{self, SqlOperation};
use graph_analyze::l3::FactQuality;
use graph_analyze::Span;

/// Directory holding the F-006 vectors, resolved from the crate manifest.
fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("l3")
}

/// Read one vector relative to `fixtures/l3/`.
fn load(relative: &str) -> String {
    let path = fixtures_root().join(relative);
    match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            let shown = path.display();
            panic!("cannot read fixture {shown}: {error}")
        }
    }
}

#[test]
fn aspnet_literal_routes_compose_and_a_computed_prefix_refuses() {
    let analysis = dotnet_routes::analyze(
        "positive_controller_routes.cs",
        &load("http/aspnet_routes/positive_controller_routes.cs"),
    );
    assert!(analysis.unresolved.is_empty());
    let facts: Vec<(String, String, Vec<HttpVerb>)> = analysis
        .endpoints
        .iter()
        .map(|endpoint| {
            (
                endpoint.action.clone(),
                endpoint.template.clone(),
                endpoint.verbs.clone(),
            )
        })
        .collect();
    assert_eq!(
        facts,
        vec![
            (
                "GetItem".to_string(),
                "api/Items/{id}".to_string(),
                vec![HttpVerb::Get],
            ),
            (
                "Create".to_string(),
                "api/Items/Create".to_string(),
                vec![HttpVerb::Post],
            ),
        ]
    );
    assert!(analysis
        .endpoints
        .iter()
        .all(|endpoint| endpoint.quality == FactQuality::ExactStatic));

    // Boundary: a computed controller prefix must produce no endpoint at all and
    // must record the refusal for the controller and for its action.
    let refused = dotnet_routes::analyze(
        "negative_dynamic_controller_route.cs",
        &load("http/aspnet_routes/negative_dynamic_controller_route.cs"),
    );
    assert!(refused.endpoints.is_empty());
    assert_eq!(refused.unresolved.len(), 2);
    assert!(refused
        .unresolved
        .iter()
        .all(|entry| entry.reason == dotnet_routes::REASON_DYNAMIC_ROUTE));
    assert_eq!(refused.unresolved[0].action, None);
    assert_eq!(refused.unresolved[1].action.as_deref(), Some("List"));
    assert!(refused
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == dotnet_routes::CODE_DYNAMIC_ROUTE));
}

#[test]
fn minimal_api_literal_mappings_compose_without_refusal() {
    let positive = minimal_api::analyze(
        "positive_literal_map.cs",
        &load("http/minimal_api/positive_literal_map.cs"),
    );
    assert!(positive.unsupported.is_empty());
    let facts: Vec<(String, HttpVerb)> = positive
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.template.clone(), endpoint.verb))
        .collect();
    assert_eq!(
        facts,
        vec![
            ("items".to_string(), HttpVerb::Get),
            ("api/v1/items".to_string(), HttpVerb::Post),
        ]
    );

    let verbs = minimal_api::analyze(
        "positive_verb_mappers.cs",
        &load("http/minimal_api/positive_verb_mappers.cs"),
    );
    assert!(verbs.unsupported.is_empty());
    let facts: Vec<(String, HttpVerb)> = verbs
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.template.clone(), endpoint.verb))
        .collect();
    assert_eq!(
        facts,
        vec![
            ("items/{id}".to_string(), HttpVerb::Put),
            ("items/{id}".to_string(), HttpVerb::Delete),
            ("items/{id}".to_string(), HttpVerb::Patch),
        ]
    );
}

#[test]
fn minimal_api_convention_mappers_refuse_with_their_own_pattern() {
    let conventions = minimal_api::analyze(
        "negative_convention_mappers.cs",
        &load("http/minimal_api/negative_convention_mappers.cs"),
    );
    assert!(conventions.endpoints.is_empty());
    let patterns: Vec<&str> = conventions
        .unsupported
        .iter()
        .map(|entry| entry.pattern.as_str())
        .collect();
    assert_eq!(
        patterns,
        vec![
            minimal_api::PATTERN_MAP_RAZOR_PAGES,
            minimal_api::PATTERN_MAP_HUB,
            minimal_api::PATTERN_MAP_HEALTH_CHECKS,
            minimal_api::PATTERN_MAP_FALLBACK,
            minimal_api::PATTERN_MAP_METHODS,
        ]
    );
    assert!(conventions
        .unsupported
        .iter()
        .all(|entry| entry.reason == minimal_api::REASON_CONVENTION_PATTERN));
}

#[test]
fn minimal_api_unresolved_boundaries_name_the_exact_pattern() {
    let cases: [(&str, &str, &str); 4] = [
        (
            "http/minimal_api/negative_unknown_receiver.cs",
            minimal_api::PATTERN_UNKNOWN_RECEIVER,
            minimal_api::REASON_UNKNOWN_RECEIVER,
        ),
        (
            "http/minimal_api/negative_app_not_built.cs",
            minimal_api::PATTERN_APP_NOT_BUILT,
            minimal_api::REASON_UNKNOWN_RECEIVER,
        ),
        (
            "http/minimal_api/negative_missing_handler.cs",
            minimal_api::PATTERN_MISSING_HANDLER,
            minimal_api::REASON_MISSING_HANDLER,
        ),
        (
            "http/minimal_api/negative_convention_map.cs",
            minimal_api::PATTERN_MAP_CONTROLLERS,
            minimal_api::REASON_CONVENTION_PATTERN,
        ),
    ];
    for (relative, pattern, reason) in cases {
        let analysis = minimal_api::analyze(relative, &load(relative));
        assert!(
            analysis.endpoints.is_empty(),
            "{relative} produced an endpoint"
        );
        assert_eq!(
            analysis.unsupported.len(),
            1,
            "{relative} unsupported count"
        );
        assert_eq!(
            analysis.unsupported[0].pattern, pattern,
            "{relative} pattern"
        );
        assert_eq!(analysis.unsupported[0].reason, reason, "{relative} reason");
    }

    // A computed route keeps the mapper spelling as its pattern id.
    let dynamic = minimal_api::analyze(
        "http/minimal_api/negative_dynamic_route.cs",
        &load("http/minimal_api/negative_dynamic_route.cs"),
    );
    assert!(dynamic.endpoints.is_empty());
    assert_eq!(dynamic.unsupported.len(), 1);
    assert_eq!(dynamic.unsupported[0].pattern, "MapGet");
    assert_eq!(
        dynamic.unsupported[0].reason,
        minimal_api::REASON_DYNAMIC_ROUTE
    );

    // A computed MapGroup prefix refuses every group mapping.
    let group = minimal_api::analyze(
        "http/minimal_api/negative_dynamic_group.cs",
        &load("http/minimal_api/negative_dynamic_group.cs"),
    );
    assert!(group.endpoints.is_empty());
    assert_eq!(group.unsupported.len(), 1);
    assert_eq!(
        group.unsupported[0].pattern,
        minimal_api::PATTERN_DYNAMIC_MAP_GROUP
    );
    assert_eq!(
        group.unsupported[0].reason,
        minimal_api::REASON_DYNAMIC_ROUTE
    );

    // Boundary: the generic `MapHub<T>(...)` spelling is not recognised at all,
    // so it must be silently absent rather than parsed into a wrong endpoint.
    let generic = minimal_api::analyze(
        "http/minimal_api/negative_generic_map_hub_boundary.cs",
        &load("http/minimal_api/negative_generic_map_hub_boundary.cs"),
    );
    assert!(generic.endpoints.is_empty());
    assert!(generic.unsupported.is_empty());
}

#[test]
fn angular_literal_calls_are_recorded_and_computed_routes_refuse() {
    let analysis = angular_http::analyze(
        "positive_literal_calls.ts",
        &load("http/angular_http/positive_literal_calls.ts"),
    );
    assert!(analysis.unresolved.is_empty());
    assert_eq!(analysis.declared_base_urls.len(), 1);
    assert_eq!(analysis.declared_base_urls[0].value, None);
    assert_eq!(analysis.calls.len(), 4);
    let relative_get = analysis
        .calls
        .iter()
        .find(|call| call.method == HttpVerb::Get && call.route == "api/items")
        .expect("literal GET call");
    assert_eq!(relative_get.client, "this.http");
    assert!(relative_get.base_url_is_runtime());
    assert!(!analysis.calls.iter().any(|call| call.route.contains('$')));
    let absolute = analysis
        .calls
        .iter()
        .find(|call| call.absolute_url.is_some())
        .expect("absolute call");
    // Recorded behaviour: the stored spelling is slash-normalised, so the
    // scheme separator collapses. It is still flagged as an absolute URL.
    assert_eq!(
        absolute.absolute_url.as_deref(),
        Some("https:/cdn.example.com/health")
    );
    assert!(!absolute.base_url_is_runtime());

    let literal_base = angular_http::analyze(
        "positive_literal_base_url.ts",
        &load("http/angular_http/positive_literal_base_url.ts"),
    );
    assert_eq!(literal_base.declared_base_urls.len(), 1);
    assert_eq!(
        literal_base.declared_base_urls[0].value.as_deref(),
        Some("/api")
    );
    assert_eq!(literal_base.calls.len(), 1);
    assert!(literal_base.calls[0].base_url_is_runtime());
}

#[test]
fn angular_refusal_vectors_never_produce_a_call() {
    let cases: [(&str, &str, &str); 4] = [
        (
            "http/angular_http/negative_template_literal.ts",
            angular_http::PATTERN_TEMPLATE_LITERAL,
            angular_http::REASON_DYNAMIC_ROUTE,
        ),
        (
            "http/angular_http/negative_dynamic_route.ts",
            angular_http::PATTERN_DYNAMIC_ROUTE,
            angular_http::REASON_DYNAMIC_ROUTE,
        ),
        (
            "http/angular_http/negative_non_client_receiver.ts",
            angular_http::PATTERN_NON_CLIENT_RECEIVER,
            angular_http::REASON_NON_CLIENT_RECEIVER,
        ),
        (
            "http/angular_http/negative_request_verb.ts",
            angular_http::PATTERN_REQUEST_VERB,
            angular_http::REASON_NON_LITERAL_VERB,
        ),
    ];
    for (relative, pattern, reason) in cases {
        let refused = angular_http::analyze(relative, &load(relative));
        assert!(refused.calls.is_empty(), "{relative} produced a call");
        assert!(
            refused
                .unresolved
                .iter()
                .any(|entry| entry.pattern == pattern && entry.reason == reason),
            "{relative} missing {pattern}"
        );
    }

    // The request-verb vector also carries a literal verb with a computed route.
    let mixed = angular_http::analyze(
        "http/angular_http/negative_request_verb.ts",
        &load("http/angular_http/negative_request_verb.ts"),
    );
    assert_eq!(mixed.unresolved.len(), 2);
    assert!(mixed.unresolved.iter().any(|entry| {
        entry.pattern == angular_http::PATTERN_DYNAMIC_ROUTE
            && entry.reason == angular_http::REASON_DYNAMIC_ROUTE
    }));
}

#[test]
fn sql_literal_statements_are_classified_and_dynamic_text_refuses() {
    let positive = sql_literals::analyze(
        "positive_literal_statements.cs",
        &load("sql/positive_literal_statements.cs"),
    );
    let facts: Vec<(SqlOperation, Option<String>, Option<String>)> = positive
        .accesses
        .iter()
        .map(|access| {
            (
                access.operation,
                access.schema.clone(),
                access.object.clone(),
            )
        })
        .collect();
    assert_eq!(
        facts,
        vec![
            (
                SqlOperation::Select,
                Some("dbo".to_string()),
                Some("Items".to_string()),
            ),
            (SqlOperation::Insert, None, Some("Customers".to_string())),
            (SqlOperation::Update, None, Some("Orders".to_string())),
            (SqlOperation::Delete, None, Some("Sessions".to_string())),
            (
                SqlOperation::StoredProcedure,
                Some("dbo".to_string()),
                Some("RebuildIndexes".to_string()),
            ),
        ]
    );
    assert!(positive.unresolved.is_empty());
    assert!(positive
        .accesses
        .iter()
        .all(|access| access.quality == FactQuality::ExactStatic));
    assert_eq!(
        positive.accesses[0].qualified_object().as_deref(),
        Some("dbo.Items")
    );

    // Negative: interpolated and concatenated SQL never becomes a fact.
    let dynamic = sql_literals::analyze(
        "negative_dynamic_statement.cs",
        &load("sql/negative_dynamic_statement.cs"),
    );
    assert!(dynamic.accesses.is_empty());
    assert_eq!(dynamic.unresolved.len(), 2);
    assert!(dynamic.unresolved.iter().all(|entry| {
        entry.pattern == sql_literals::PATTERN_DYNAMIC_SQL
            && entry.reason == sql_literals::REASON_DYNAMIC_SQL
    }));

    // Negative: a literal statement whose target cannot be narrowed.
    let unnarrowed = sql_literals::analyze(
        "negative_unnarrowed_object.cs",
        &load("sql/negative_unnarrowed_object.cs"),
    );
    assert!(unnarrowed.accesses.is_empty());
    assert_eq!(unnarrowed.unresolved.len(), 2);
    assert!(unnarrowed.unresolved.iter().all(|entry| {
        entry.pattern == sql_literals::PATTERN_UNNARROWED_OBJECT
            && entry.reason == sql_literals::REASON_UNNARROWED_OBJECT
    }));
    assert!(unnarrowed.unresolved[0].text.contains("SELECT"));
    assert!(unnarrowed.unresolved[1].text.contains("EXEC"));

    // Boundary: text that is not SQL produces nothing, and refuses explicitly
    // only when the caller asks this adapter to refuse it.
    let ignored = sql_literals::analyze(
        "negative_not_a_statement.cs",
        &load("sql/negative_not_a_statement.cs"),
    );
    assert!(ignored.accesses.is_empty());
    assert!(ignored.unresolved.is_empty());
    let refused_text = sql_literals::refuse_non_literal(
        "negative_not_a_statement.cs",
        "hello world",
        Span::new(0, 11),
    );
    assert_eq!(refused_text.pattern, sql_literals::PATTERN_NOT_SQL);
    assert_eq!(refused_text.reason, graph_analyze::l3::REASON_NOT_A_LITERAL);
    let refused_expression = sql_literals::refuse_non_literal(
        "negative_not_a_statement.cs",
        "\"SELECT 1\"",
        Span::new(0, 10),
    );
    assert_eq!(refused_expression.pattern, sql_literals::PATTERN_NOT_SQL);
    assert_eq!(
        refused_expression.reason,
        graph_analyze::l3::REASON_DYNAMIC_EXPRESSION
    );
}

#[test]
fn messaging_literal_topics_link_and_computed_topics_refuse() {
    let producer = messaging::analyze(
        "Orders",
        "publisher_orders.cs",
        &load("messaging/publisher_orders.cs"),
    );
    assert!(producer.unresolved.is_empty());
    assert_eq!(producer.bindings.len(), 1);
    assert_eq!(producer.bindings[0].role, MessagingRole::Producer);
    assert_eq!(producer.bindings[0].topic, "orders.created");
    assert_eq!(producer.bindings[0].quality, FactQuality::ExactStatic);

    let consumer = messaging::analyze(
        "Billing",
        "subscriber_billing.cs",
        &load("messaging/subscriber_billing.cs"),
    );
    assert!(consumer.unresolved.is_empty());
    assert_eq!(consumer.bindings_for(MessagingRole::Consumer).len(), 2);

    let shipping = messaging::analyze(
        "Shipping",
        "publisher_shipping.cs",
        &load("messaging/publisher_shipping.cs"),
    );
    assert_eq!(shipping.bindings.len(), 1);
    assert_eq!(shipping.bindings[0].topic, "shipments.queued");

    let config = MessagingConfig {
        topics: vec![
            ConfiguredTopic {
                topic: "orders.created".to_string(),
                project: "Orders".to_string(),
            },
            ConfiguredTopic {
                topic: "shipments.queued".to_string(),
                project: "Shipping".to_string(),
            },
        ],
    };
    let bindings: Vec<messaging::TopicBinding> = producer
        .bindings
        .iter()
        .chain(consumer.bindings.iter())
        .chain(shipping.bindings.iter())
        .cloned()
        .collect();
    let report = messaging::link(&bindings, &config);
    assert_eq!(report.links.len(), 2);
    assert!(report
        .links
        .iter()
        .all(|link| link.quality == FactQuality::ExactStatic));
    assert!(report.unlinked.is_empty());
    assert!(report.unmatched_topics.is_empty());
    assert_eq!(report.links[0].topic, "orders.created");
    assert_eq!(report.links[0].topic_project, "Orders");
    assert_eq!(report.links[0].producer_project, "Orders");
    assert_eq!(report.links[0].consumer_project, "Billing");
    assert_eq!(report.links[1].topic, "shipments.queued");
    assert_eq!(report.links[1].topic_project, "Shipping");
    assert_eq!(report.links[1].producer_project, "Shipping");
    assert_eq!(report.links[1].consumer_project, "Billing");

    // Negative: a topic that only exists at runtime never becomes a binding.
    let dynamic = messaging::analyze(
        "Orders",
        "negative_dynamic_topic.cs",
        &load("messaging/negative_dynamic_topic.cs"),
    );
    assert!(dynamic.bindings.is_empty());
    assert_eq!(dynamic.unresolved.len(), 3);
    assert!(dynamic
        .unresolved
        .iter()
        .all(|entry| entry.reason == messaging::REASON_DYNAMIC_TOPIC));
    let patterns: Vec<&str> = dynamic
        .unresolved
        .iter()
        .map(|entry| entry.pattern.as_str())
        .collect();
    assert_eq!(
        patterns,
        vec![
            messaging::PATTERN_PUBLISH,
            messaging::PATTERN_PUBLISH,
            messaging::PATTERN_TOPIC_ATTRIBUTE,
        ]
    );
    assert_eq!(dynamic.unresolved[2].role, MessagingRole::Consumer);

    // Boundary: a literal topic nobody configured is refused by the link.
    let untracked = messaging::analyze(
        "Orders",
        "negative_unconfigured_topic.cs",
        &load("messaging/negative_unconfigured_topic.cs"),
    );
    assert_eq!(untracked.bindings.len(), 1);
    let refused = messaging::link(&untracked.bindings, &config);
    assert!(refused.links.is_empty());
    assert_eq!(refused.unlinked.len(), 1);
    assert_eq!(
        refused.unlinked[0].reason,
        messaging::REASON_TOPIC_NOT_CONFIGURED
    );
}

/// One declarative HTTP-join vector read from `fixtures/l3/http_join/`.
#[derive(Default)]
struct JoinVector {
    name: String,
    mapping: SolutionMapping,
    /// Declared `link <source> <target> <protocol> <route-prefix>` directives.
    links: Vec<[String; 4]>,
    endpoints: Vec<HttpEndpointFact>,
    clients: Vec<HttpClientFact>,
    expectations: Vec<Expectation>,
}

/// One expected outcome of a join vector.
enum Expectation {
    Relation {
        client_project: String,
        server_project: String,
        method: HttpVerb,
        request_path: String,
    },
    Unresolved {
        client_project: String,
        pattern: String,
        reason: String,
    },
    Ambiguous {
        client_project: String,
        candidates: usize,
    },
}

fn verb(spelling: &str) -> HttpVerb {
    match spelling {
        "GET" => HttpVerb::Get,
        "POST" => HttpVerb::Post,
        "PUT" => HttpVerb::Put,
        "DELETE" => HttpVerb::Delete,
        "PATCH" => HttpVerb::Patch,
        "HEAD" => HttpVerb::Head,
        "OPTIONS" => HttpVerb::Options,
        other => panic!("unknown verb {other}"),
    }
}

fn maybe(text: &str) -> Option<String> {
    if text == "-" {
        None
    } else {
        Some(text.to_string())
    }
}

fn parse_join_vector(relative: &str) -> JoinVector {
    let mut vector = JoinVector::default();
    for (index, raw) in load(relative).lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens[0] {
            "vector" => vector.name = tokens[1].to_string(),
            "link" => vector.links.push([
                tokens[1].to_string(),
                tokens[2].to_string(),
                tokens[3].to_string(),
                tokens[4].to_string(),
            ]),
            "endpoint" => vector.endpoints.push(HttpEndpointFact {
                project: tokens[1].to_string(),
                file: tokens[2].to_string(),
                method: verb(tokens[3]),
                template: tokens[4].to_string(),
                span: Span::new(index, index),
            }),
            "client" => vector.clients.push(HttpClientFact {
                project: tokens[1].to_string(),
                file: tokens[2].to_string(),
                method: verb(tokens[3]),
                absolute_url: maybe(tokens[4]),
                path: maybe(tokens[5]),
                span: Span::new(index, index),
            }),
            "expect-relation" => vector.expectations.push(Expectation::Relation {
                client_project: tokens[1].to_string(),
                server_project: tokens[2].to_string(),
                method: verb(tokens[3]),
                request_path: tokens[4].to_string(),
            }),
            "expect-unresolved" => vector.expectations.push(Expectation::Unresolved {
                client_project: tokens[1].to_string(),
                pattern: tokens[2].to_string(),
                reason: tokens[3].to_string(),
            }),
            "expect-ambiguous" => vector.expectations.push(Expectation::Ambiguous {
                client_project: tokens[1].to_string(),
                candidates: tokens[2].parse().expect("candidate count"),
            }),
            other => panic!("{relative}: unknown directive {other}"),
        }
    }

    // The alias table is not written here. The vector's `link` directives are
    // projected into a real solution document and read back through the same
    // reader operator registration uses, so a host can only resolve when the
    // document declares it.
    let mut projects: BTreeSet<String> = BTreeSet::new();
    for endpoint in &vector.endpoints {
        projects.insert(endpoint.project.clone());
    }
    for client in &vector.clients {
        projects.insert(client.project.clone());
    }
    for link in &vector.links {
        projects.insert(link[0].clone());
        projects.insert(link[1].clone());
    }
    let document = serde_json::json!({
        "schema_version": 2,
        "solution_id": "l3-vector",
        "repositories": projects
            .iter()
            .map(|project| serde_json::json!({"repo_id": project, "binding_key": project}))
            .collect::<Vec<_>>(),
        "projects": projects
            .iter()
            .map(|project| serde_json::json!({
                "project_id": project,
                "repo_id": project,
                "path": "src",
            }))
            .collect::<Vec<_>>(),
        "semantic_links": vector
            .links
            .iter()
            .map(|link| serde_json::json!({
                "source_project": link[0],
                "target_project": link[1],
                "protocol": link[2],
                "route_prefix": link[3],
            }))
            .collect::<Vec<_>>(),
    });
    let registered = axiom_config::solution::read_registered_solution(&document, None)
        .unwrap_or_else(|error| panic!("{relative}: the vector document is refused: {error}"));
    vector.mapping = SolutionMapping::from_registered_aliases(registered.l3_aliases());
    vector
}

fn check_join_vector(relative: &str) {
    let vector = parse_join_vector(relative);
    assert!(
        !vector.name.is_empty(),
        "{relative} declares no vector name"
    );
    let report = http_join::join(&vector.endpoints, &vector.clients, &vector.mapping);
    for expectation in &vector.expectations {
        match expectation {
            Expectation::Relation {
                client_project,
                server_project,
                method,
                request_path,
            } => {
                let found = report.relations.iter().any(|relation| {
                    relation.client_project == *client_project
                        && relation.server_project == *server_project
                        && relation.method == *method
                        && relation.request_path == *request_path
                        && relation.quality == FactQuality::ExactStatic
                });
                assert!(
                    found,
                    "{relative} missing exact relation {server_project} <- {client_project}"
                );
            }
            Expectation::Unresolved {
                client_project,
                pattern,
                reason,
            } => {
                let found = report.unresolved.iter().any(|entry| {
                    entry.client_project == *client_project
                        && entry.pattern == *pattern
                        && entry.reason == *reason
                });
                assert!(found, "{relative} missing refusal {pattern}");
            }
            Expectation::Ambiguous {
                client_project,
                candidates,
            } => {
                let found = report.ambiguous.iter().any(|entry| {
                    entry.client_project == *client_project && entry.candidates.len() == *candidates
                });
                assert!(
                    found,
                    "{relative} missing ambiguous relation with {candidates} candidates"
                );
            }
        }
    }
    assert_eq!(
        report.relations.len() + report.ambiguous.len() + report.unresolved.len(),
        vector.clients.len(),
        "{relative} client accounting"
    );
}

#[test]
fn http_join_vectors_join_only_through_configured_aliases() {
    check_join_vector("http_join/positive_alias_join.vector");
    check_join_vector("http_join/negative_unconfigured_host.vector");
    check_join_vector("http_join/negative_relative_client.vector");
    check_join_vector("http_join/negative_no_route_candidate.vector");
    check_join_vector("http_join/negative_ambiguous_route.vector");

    // Boundary: the legitimate request must produce no refusal at all, and no
    // refusal pattern may fire for it.
    let positive = parse_join_vector("http_join/positive_alias_join.vector");
    let report = http_join::join(&positive.endpoints, &positive.clients, &positive.mapping);
    assert!(report.unresolved.is_empty());
    assert!(report.ambiguous.is_empty());
    assert_eq!(report.relations.len(), 1);
    for pattern in [
        http_join::PATTERN_UNCONFIGURED_HOST,
        http_join::PATTERN_RELATIVE_CLIENT,
        http_join::PATTERN_NO_ROUTE_CANDIDATE,
    ] {
        assert!(
            !report
                .unresolved
                .iter()
                .any(|entry| entry.pattern == pattern),
            "positive vector fired {pattern}"
        );
    }

    // Boundary: two equally good routes stay ambiguous and never become a
    // single joined relation.
    let ambiguous = parse_join_vector("http_join/negative_ambiguous_route.vector");
    let report = http_join::join(&ambiguous.endpoints, &ambiguous.clients, &ambiguous.mapping);
    assert_eq!(report.ambiguous.len(), 1);
    assert_eq!(
        report.ambiguous[0].reason(),
        http_join::REASON_AMBIGUOUS_ROUTE
    );
    assert!(report.relations.is_empty());
}
