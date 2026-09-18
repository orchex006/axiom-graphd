# L3 conformance fixture vectors (task F-006)

Owner: `axiom-graphd`. Task: F-006. Pinned specification revision:
`1bf754298ba1bb266a77f13cded4bfe69484906f`.

## What this corpus is

Static conformance **test vectors** for the Level-3 adapters of
`crates/graph-analyze/src/l3/`. Every vector is static source text, or static
declarative join text, committed to the repository. No vector contains a runtime
log, a captured request or trace, or a recording of executed user source. The
adapters that consume them parse text only and execute nothing.

This corpus is **not** a registered shared contract fixture. It adds no row to
`conformance/fixture-index.json` in `axiom-specs`, it does not change
`fixture_index_digest`, and it does not touch `conformance/ownership.json`.
Promoting any vector here to a shared contract fixture requires an approved
specification change and must then live under `examples/` in `axiom-specs` and
be indexed there.

## How the vectors are exercised

`crates/graph-analyze/tests/l3_fixtures.rs` loads every vector from disk and
runs the real adapter, then asserts the positive fact set and the exact
`PATTERN_*` / `REASON_*` of every refusal. That test is the targeted regression
test for F-006 and the negative/boundary evidence for F-006 AC2.

The supported rule set below was read from the implementation, not from the
coverage document alone: a rule counts as **observable** only when the constant
actually reaches an output field (a refusal `pattern`, a `reason`, or a
diagnostic `code`). Constants that exist in the registry but never reach an
output are listed at the end and are not part of the vector matrix.

## Rule provenance

### HTTP: ASP.NET attribute routes

Implementation: `crates/graph-analyze/src/l3/dotnet_routes.rs`, `pub fn analyze`.
Serves the `aspnet-routes` supported subset of `docs/15-STATIC-ANALYSIS-COVERAGE.md`
section 2 ("Controller Route/Http* attributes, literal prefixes") and the
section 3 invariant that only a literal composition may be published as
`exact_static`.

| Rule | Direction | Vector | Expected outcome |
|---|---|---|---|
| literal `[Route]` prefix composed with a literal `[Http*]` action template | positive | `http/aspnet_routes/positive_controller_routes.cs` | two `RouteEndpoint`s (`api/Items/{id}` GET, `api/Items/Create` POST), both `exact_static` |
| a computed route prefix or action template | negative | `http/aspnet_routes/negative_dynamic_controller_route.cs` | zero endpoints; two refusals with `REASON_DYNAMIC_ROUTE`, plus diagnostic `CODE_DYNAMIC_ROUTE` |

### HTTP: minimal API mappings

Implementation: `crates/graph-analyze/src/l3/minimal_api.rs`, `pub fn analyze`.
Serves the `aspnet-routes` subset phrase "basic literal MapGet/MapPost/MapGroup"
and the section 3 rule that a computed route stays unresolved. Refusals carry
the invariant that convention discovery, an unknown receiver, an unbuilt app
builder, a computed group prefix and a missing handler are reported instead of
being guessed into an endpoint.

| Rule | Direction | Vector | Expected outcome |
|---|---|---|---|
| literal `MapGet`/`MapPost` route, group prefix composition | positive | `http/minimal_api/positive_literal_map.cs` | endpoints `items` (GET) and `api/v1/items` (POST) |
| literal `MapPut`/`MapDelete`/`MapPatch` routes | positive | `http/minimal_api/positive_verb_mappers.cs` | three endpoints `items/{id}` for PUT, DELETE, PATCH |
| convention mappers `MapRazorPages`/`MapHub`/`MapHealthChecks`/`MapFallback`/`MapMethods` | negative | `http/minimal_api/negative_convention_mappers.cs` | five refusals with `REASON_CONVENTION_PATTERN` and patterns `PATTERN_MAP_RAZOR_PAGES`, `PATTERN_MAP_HUB`, `PATTERN_MAP_HEALTH_CHECKS`, `PATTERN_MAP_FALLBACK`, `PATTERN_MAP_METHODS` |
| `MapControllers` convention discovery | negative | `http/minimal_api/negative_convention_map.cs` | one refusal `PATTERN_MAP_CONTROLLERS`, `REASON_CONVENTION_PATTERN` |
| mapping on a receiver declared nowhere | negative | `http/minimal_api/negative_unknown_receiver.cs` | one refusal `PATTERN_UNKNOWN_RECEIVER`, `REASON_UNKNOWN_RECEIVER` |
| mapping on a builder that was never built | negative | `http/minimal_api/negative_app_not_built.cs` | one refusal `PATTERN_APP_NOT_BUILT`, `REASON_UNKNOWN_RECEIVER` |
| mapping without a request delegate | negative | `http/minimal_api/negative_missing_handler.cs` | one refusal `PATTERN_MISSING_HANDLER`, `REASON_MISSING_HANDLER` |
| computed route pattern | negative | `http/minimal_api/negative_dynamic_route.cs` | one refusal, pattern is the mapper spelling `MapGet`, `REASON_DYNAMIC_ROUTE` |
| computed `MapGroup` prefix | negative | `http/minimal_api/negative_dynamic_group.cs` | one refusal `PATTERN_DYNAMIC_MAP_GROUP`, `REASON_DYNAMIC_ROUTE` |
| generic `MapHub<T>(...)` spelling (recorded boundary) | negative | `http/minimal_api/negative_generic_map_hub_boundary.cs` | zero endpoints and zero refusals: the adapter matches only `MapHub(` with the parenthesis directly after the name, so the generic spelling is not recognised |

### HTTP: Angular `HttpClient`

Implementation: `crates/graph-analyze/src/l3/angular_http.rs`, `pub fn analyze`.
Serves the `angular-http` subset ("HttpClient.get/post/put/delete/patch with a
literal or allowlisted constant service base and routes") and requires arbitrary
template expressions, interceptors and runtime environment values to be reported
as unsupported.

| Rule | Direction | Vector | Expected outcome |
|---|---|---|---|
| literal relative route on an HTTP client receiver | positive | `http/angular_http/positive_literal_calls.ts` | four `HttpCall`s; the relative GET is `exact_static` and its base URL is a runtime value |
| literal `baseUrl` declaration | positive | `http/angular_http/positive_literal_base_url.ts` | one declared base URL with literal value `/api`, plus one relative call |
| template-literal route | negative | `http/angular_http/negative_template_literal.ts` | zero calls; one refusal `PATTERN_TEMPLATE_LITERAL`, `REASON_DYNAMIC_ROUTE` |
| computed route expression | negative | `http/angular_http/negative_dynamic_route.ts` | zero calls; one refusal `PATTERN_DYNAMIC_ROUTE`, `REASON_DYNAMIC_ROUTE` |
| method call on a non-client receiver | negative | `http/angular_http/negative_non_client_receiver.ts` | zero calls; one refusal `PATTERN_NON_CLIENT_RECEIVER`, `REASON_NON_CLIENT_RECEIVER` |
| `request(` without a literal verb, and a literal verb with a computed route | negative | `http/angular_http/negative_request_verb.ts` | zero calls; refusals `PATTERN_REQUEST_VERB`/`REASON_NON_LITERAL_VERB` and `PATTERN_DYNAMIC_ROUTE`/`REASON_DYNAMIC_ROUTE` |

Recorded current behaviour: the stored spelling of an absolute literal URL is
slash-normalised, so `https://cdn.example.com/health` is recorded as
`https:/cdn.example.com/health`. The call is still flagged with `absolute_url`
and is not a runtime base binding. The test pins this so a future change to
`normalize_route` is noticed.

### SQL literals

Implementation: `crates/graph-analyze/src/l3/sql_literals.rs`, `pub fn analyze`
and `pub fn refuse_non_literal`. Serves the `sql-literals` subset ("literal SQL
select/insert/update/delete table/SP name") and the section 2 rule that dynamic
SQL and arbitrary concatenation must be reported instead of guessed.

| Rule | Direction | Vector | Expected outcome |
|---|---|---|---|
| literal `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`EXEC` statements | positive | `sql/positive_literal_statements.cs` | five `SqlAccess` facts, all `exact_static`, with schema/object narrowed where the text names one (`dbo.Items`, `Customers`, `Orders`, `Sessions`, `dbo.RebuildIndexes`) |
| interpolated or concatenated SQL | negative | `sql/negative_dynamic_statement.cs` | zero facts; two refusals `PATTERN_DYNAMIC_SQL`, `REASON_DYNAMIC_SQL` |
| literal statement whose target cannot be narrowed (derived table, parameterised object) | negative | `sql/negative_unnarrowed_object.cs` | zero facts; two refusals `PATTERN_UNNARROWED_OBJECT`, `REASON_UNNARROWED_OBJECT` |
| text that is not SQL, and a `SELECT` that is not a literal | negative | `sql/negative_not_a_statement.cs` | `analyze` yields nothing at all; `refuse_non_literal` yields `PATTERN_NOT_SQL` with `REASON_NOT_A_LITERAL` for non-literal text and `REASON_DYNAMIC_EXPRESSION` for a string that is exactly one literal |

### Messaging topics

Implementation: `crates/graph-analyze/src/l3/messaging.rs`, `pub fn analyze` and
`pub fn link`. Serves the `messaging-config` subset ("literal publish/subscribe/
topic names with explicit annotations") and requires a runtime-computed topic to
be reported as unsupported.

| Rule | Direction | Vector | Expected outcome |
|---|---|---|---|
| literal publish call | positive | `messaging/publisher_orders.cs` | one `Producer` binding `orders.created`, `exact_static` |
| literal subscribe call and literal topic attribute | positive | `messaging/subscriber_billing.cs` | two `Consumer` bindings (`orders.created`, `shipments.queued`) |
| literal producer for a second configured topic | positive | `messaging/publisher_shipping.cs` | one `Producer` binding `shipments.queued` |
| producer/consumer link through explicit configuration | positive | the three vectors above | two `exact_static` links (`orders.created`: Orders -> Billing, `shipments.queued`: Shipping -> Billing), no unlinked or unmatched topics |
| computed topic in a call or an attribute | negative | `messaging/negative_dynamic_topic.cs` | zero bindings; three refusals (`PATTERN_PUBLISH` twice, `PATTERN_TOPIC_ATTRIBUTE` once), all `REASON_DYNAMIC_TOPIC` |
| literal topic that no configuration names | negative | `messaging/negative_unconfigured_topic.cs` | one binding, zero links, one `unlinked` entry with `REASON_TOPIC_NOT_CONFIGURED` |

### HTTP join

Implementation: `crates/graph-analyze/src/l3/http_join.rs`, `pub fn join`. Serves
the `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 3 rule that an API client and
server are linked only through a configured service alias, and that an ambiguous
route raises a diagnostic instead of a guessed link. `join` consumes extracted
facts rather than source text, so these vectors are declarative text in
`http_join/*.vector`; the grammar is documented at the top of each file.

| Rule | Direction | Vector | Expected outcome |
|---|---|---|---|
| absolute request whose host is one configured alias, one matching route | positive | `http_join/positive_alias_join.vector` | one `exact_static` relation `OrdersApi <- Web`, path `api/items/7`, and no refusal at all |
| host with no configured alias | negative | `http_join/negative_unconfigured_host.vector` | one refusal `PATTERN_UNCONFIGURED_HOST`, `REASON_NO_CONFIGURED_ALIAS` |
| relative client address | negative | `http_join/negative_relative_client.vector` | one refusal `PATTERN_RELATIVE_CLIENT`, `REASON_RUNTIME_BASE_URL` |
| configured host with no verb/path match | negative | `http_join/negative_no_route_candidate.vector` | one refusal `PATTERN_NO_ROUTE_CANDIDATE`, `REASON_NO_ROUTE_CANDIDATE` |
| two equally good routes | negative | `http_join/negative_ambiguous_route.vector` | one ambiguous relation with two candidates, `REASON_AMBIGUOUS_ROUTE`, zero joined relations |

## Registry constants that never reach an output

An emission audit over `crates/graph-analyze/src/l3/` shows the following
`PATTERN_*` constants are declared but never assigned to a refusal `pattern`,
`reason` or diagnostic `code`. They name intent, not observable behaviour, so
they are deliberately excluded from the vector matrix:

- `PATTERN_LITERAL_ROUTE` (`angular-http-literal-route`)
- `PATTERN_ABSOLUTE_URL` (`angular-http-absolute-url`)
- `PATTERN_LITERAL_STATEMENT` (`sql-literal-statement`)
- `PATTERN_ALIAS_JOIN` (`http-join-configured-alias`)

This is recorded as a finding, not repaired here: changing those outputs is a
behaviour change outside the F-006 bounded deliverable.

## Adding a vector

1. Add static source text under the matching adapter directory.
2. Add a positive and a negative case to
   `crates/graph-analyze/tests/l3_fixtures.rs`, naming the exact expected fact
   set and the exact `PATTERN_*`/`REASON_*` of the refusal.
3. Extend the table above with the source file and function that implements the
   rule and the invariant it serves.
