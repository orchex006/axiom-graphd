//! Solution membership and cross-service aliases read from a registered solution
//! document (task H-004).
//!
//! [`crate::bindings`] (V2-007) already keeps the *logical* identity of a bound
//! repository separate from its machine-local root, and
//! `graph_core::solution::validate_membership` (B-013) validates membership
//! claims that a caller had to build by hand. This module is the missing reader:
//! it turns one accepted `schema_version` 2 solution document plus its
//! owner-only bindings document into
//!
//! 1. the **membership claim set** - exactly one claim per `projects[]` entry, and
//! 2. the **cross-service alias set** - one alias per `semantic_links[]` entry
//!    that carries a `route_prefix`,
//!
//! exactly as `contracts/solution-alias-mapping.md` (H-003) defines them. The
//! document a registration validates is therefore the only source of the L3
//! cross-service join, so no alias table may be built by hand and a host that
//! matches no alias, an alias set that resolves one service address to two
//! projects, and a `semantic_links` endpoint that is not a member are all
//! explicit refusals rather than a guessed project.
//!
//! Two properties are deliberate:
//!
//! * Every refusal reuses the contract's frozen identifier verbatim; this module
//!   invents no new spelling and keeps the evaluator names it was told not to
//!   re-spell.
//! * The *whole* claim set is validated before the reader returns, and the reader
//!   writes no row and no file, so a refused registration writes nothing (M1).
//!
//! `semantic_links[].route_prefix` is the schema's field and is read here; the
//! resolver in [`RegisteredSolution::resolve`] walks the contract's section 4
//! order and never breaks a tie by list position.

use std::collections::{BTreeMap, BTreeSet};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, is_portable_id};
use graph_core::solution::{validate_membership, ProjectMembership, SolutionMembership};
use serde_json::Value;

/// Stable refusal: one `binding_key` is declared by more than one repository (M3).
pub const ERR_BINDING_KEY_DUPLICATE: &str = "binding-key-duplicate";
/// Stable refusal: a declared `binding_key` has no root, or the bindings document
/// carries an undeclared key (M4).
pub const ERR_BINDING_KEY_UNRESOLVED: &str = "binding-key-unresolved";
/// Stable refusal: `projects[].path` is not a repository-relative path (M5).
pub const ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE: &str = "project-path-not-repository-relative";
/// Stable refusal: the derived absolute root leaves its bound local root (M6).
pub const ERR_PROJECT_ROOT_ESCAPES_BINDING: &str = "project-root-escapes-binding";
/// Stable refusal: a `semantic_links` endpoint is not a member of the solution (M7).
pub const ERR_LINK_ENDPOINT_NOT_MEMBER: &str = "link-endpoint-not-member";
/// Stable refusal: an `http`/`sql`/`message` link carries no route prefix.
pub const ERR_ROUTE_PREFIX_REQUIRED: &str = "route-prefix-required";
/// Stable refusal: a route prefix is machine-local or credential-shaped.
pub const ERR_ROUTE_PREFIX_NOT_PORTABLE_FREE_TEXT: &str = "route-prefix-not-portable-free-text";
/// Stable resolution refusal: one service address resolves to two projects.
pub const ERR_ALIAS_AMBIGUOUS_HOST: &str = "alias-ambiguous-host";
/// Stable explicit-unresolved result: no declared alias matches the address.
pub const ERR_ALIAS_UNRESOLVED_HOST: &str = "alias-unresolved-host";

/// Rule frozen by the evaluator for a duplicate `project_id`; not re-spelled here.
pub const ERR_DUPLICATE_PROJECT_ID: &str = "duplicate-project-id";
/// Rule frozen by the evaluator for a route prefix that is not slash-led.
pub const ERR_ROUTE_PREFIX_NOT_ABSOLUTE: &str = "semantic link route prefix is not absolute";
/// Rule frozen by the evaluator for a non-portable id.
pub const ERR_NOT_PORTABLE_ID: &str = "is not a portable id";
/// Rule frozen by the evaluator for a non-portable binding alias.
pub const ERR_NOT_PORTABLE_ALIAS: &str = "is not a portable alias";
/// Local rule name for a document whose shape is not the accepted shape.
pub const ERR_DOCUMENT_SHAPE: &str = "document-shape-invalid";

/// The link protocols the schema's enum allows.
pub const LINK_PROTOCOLS: [&str; 4] = ["http", "sql", "message", "explicit"];

/// One validated membership claim, one per `projects[]` entry.
///
/// The claim is a logical identity plus the machine-local root derived from the
/// bound local root joined with the repository-relative path. [`absolute_root`]
/// is `None` only when no bindings document was supplied with the solution, which
/// is the alias-only reading the reference evaluator also allows; a registration
/// always supplies the bindings document.
///
/// [`absolute_root`]: MembershipClaim::absolute_root
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipClaim {
    project_id: String,
    repo_id: String,
    binding_key: String,
    path: String,
    absolute_root: Option<String>,
    language_profile: Option<String>,
}

impl MembershipClaim {
    /// The task project id.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// The repository the project belongs to.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// The binding key of the `repositories[]` entry that names `repo_id`.
    #[must_use]
    pub fn binding_key(&self) -> &str {
        &self.binding_key
    }

    /// The repository-relative path, normalized to `/` form.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The derived absolute root, when a bindings document was supplied.
    #[must_use]
    pub fn absolute_root(&self) -> Option<&str> {
        self.absolute_root.as_deref()
    }

    /// The declared language profile, when present.
    #[must_use]
    pub fn language_profile(&self) -> Option<&str> {
        self.language_profile.as_deref()
    }
}

/// One cross-service alias derived from a `semantic_links[]` entry.
///
/// [`alias_key`] is `normalize_service_key(route_prefix)`; [`project`] is always
/// the link's *target* project. [`l3_host_key`] projects an authority-bearing key
/// onto the authority-only spelling the L3 HTTP join matches on.
///
/// [`alias_key`]: ServiceAlias::alias_key
/// [`project`]: ServiceAlias::project
/// [`l3_host_key`]: ServiceAlias::l3_host_key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceAlias {
    alias_key: String,
    project: String,
    protocol: String,
}

impl ServiceAlias {
    /// The normalized service address key this alias matches.
    #[must_use]
    pub fn alias_key(&self) -> &str {
        &self.alias_key
    }

    /// The project the alias resolves to.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The one protocol this alias covers.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// The authority-only spelling of this alias, when it has an authority.
    ///
    /// A route-only key (`/api/auth`) names no host and returns `None`, so the
    /// host-based L3 join never invents an authority for it.
    #[must_use]
    pub fn l3_host_key(&self) -> Option<String> {
        let rest = self.alias_key.strip_prefix("//")?;
        let end = rest.find('/').unwrap_or(rest.len());
        let host = &rest[..end];
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    }
}

/// The contract's section 4 outcome for one observed service address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasResolution<'a> {
    /// Exactly one project claims the address.
    Resolved(&'a str),
    /// No declared alias matches the address.
    Unresolved,
    /// Two or more distinct projects claim the address.
    Ambiguous,
}

impl AliasResolution<'_> {
    /// The stable refusal identifier for this outcome, if any.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Resolved(_) => None,
            Self::Unresolved => Some(ERR_ALIAS_UNRESOLVED_HOST),
            Self::Ambiguous => Some(ERR_ALIAS_AMBIGUOUS_HOST),
        }
    }
}

/// The membership and cross-service alias tables of one accepted solution.
///
/// The tables are produced only by [`read_registered_solution`], so the same
/// document a registration validated is the only source of the L3 join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredSolution {
    solution_id: String,
    claims: Vec<MembershipClaim>,
    aliases: Vec<ServiceAlias>,
}

impl RegisteredSolution {
    /// The accepted solution id.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// The membership claim set, in `projects[]` order.
    #[must_use]
    pub fn claims(&self) -> &[MembershipClaim] {
        &self.claims
    }

    /// The cross-service alias set, in `semantic_links[]` order.
    #[must_use]
    pub fn aliases(&self) -> &[ServiceAlias] {
        &self.aliases
    }

    /// The claim of `project_id`, when that project is a member.
    #[must_use]
    pub fn claim_for(&self, project_id: &str) -> Option<&MembershipClaim> {
        self.claims
            .iter()
            .find(|claim| claim.project_id == project_id)
    }

    /// True when `project_id` is a member of this solution.
    #[must_use]
    pub fn is_member(&self, project_id: &str) -> bool {
        self.claim_for(project_id).is_some()
    }

    /// Resolve one observed service address through the alias set.
    ///
    /// The order is the contract's: keep the aliases whose protocol covers
    /// `protocol`, normalize `address` with [`normalize_service_key`], then
    /// accept an alias that equals the address key or is a prefix of it ending at
    /// a `/` boundary. Zero candidates is [`AliasResolution::Unresolved`]; two or
    /// more candidates naming distinct projects is [`AliasResolution::Ambiguous`];
    /// several aliases naming the same project resolve. The tie is never broken
    /// by list position, specificity or file order.
    #[must_use]
    pub fn resolve(&self, protocol: &str, address: &str) -> AliasResolution<'_> {
        let address_key = normalize_service_key(address);
        let mut resolved: Option<&str> = None;
        for alias in &self.aliases {
            if alias.protocol != protocol || !alias_key_matches(&alias.alias_key, &address_key) {
                continue;
            }
            match resolved {
                Some(previous) if previous != alias.project.as_str() => {
                    return AliasResolution::Ambiguous;
                }
                Some(_) => {}
                None => resolved = Some(alias.project.as_str()),
            }
        }
        match resolved {
            Some(project) => AliasResolution::Resolved(project),
            None => AliasResolution::Unresolved,
        }
    }

    /// Resolve an address, or refuse with the contract's identifier in `rule`.
    ///
    /// # Errors
    /// - [`ErrorCode::NotFound`] with `rule` [`ERR_ALIAS_UNRESOLVED_HOST`] when no
    ///   alias matches.
    /// - [`ErrorCode::Conflict`] with `rule` [`ERR_ALIAS_AMBIGUOUS_HOST`] when two
    ///   distinct projects claim the address.
    pub fn resolve_or_refuse(&self, protocol: &str, address: &str) -> Result<&str, AxiomError> {
        match self.resolve(protocol, address) {
            AliasResolution::Resolved(project) => Ok(project),
            AliasResolution::Unresolved => Err(AxiomError::new(
                ErrorCode::NotFound,
                "no declared solution alias matches this service address",
            )
            .with_detail("rule", ERR_ALIAS_UNRESOLVED_HOST)
            .with_detail("solution_id", &self.solution_id)
            .with_detail("config_key", "route_prefix")
            .with_detail("observed", address)),
            AliasResolution::Ambiguous => Err(AxiomError::new(
                ErrorCode::Conflict,
                "two declared solution aliases resolve one service address to two projects",
            )
            .with_detail("rule", ERR_ALIAS_AMBIGUOUS_HOST)
            .with_detail("solution_id", &self.solution_id)
            .with_detail("config_key", "route_prefix")
            .with_detail("observed", address)),
        }
    }

    /// The `(host, project)` pairs the L3 HTTP join consumes.
    ///
    /// Only authority-bearing aliases produce a pair; a route-only alias names no
    /// host and is skipped instead of being guessed into one. The list is sorted
    /// and deduplicated so the mapping is stable across runs.
    #[must_use]
    pub fn l3_aliases(&self) -> Vec<(String, String)> {
        let mut pairs: BTreeSet<(String, String)> = BTreeSet::new();
        for alias in &self.aliases {
            if let Some(host) = alias.l3_host_key() {
                pairs.insert((host, alias.project.clone()));
            }
        }
        pairs.into_iter().collect()
    }
}

/// Read one accepted solution document plus its owner-only bindings document.
///
/// Every `projects[]` claim is validated with the frozen membership rules before
/// this function returns, and nothing is written. `bindings` is the machine-local
/// companion document (`{"bindings": {"<binding_key>": "<absolute local root>"}}`);
/// `None` means the bundle carries no bindings document, in which case the M4 and
/// M6 checks cannot run and the claims carry no `absolute_root` - the alias-only
/// reading the frozen reference evaluator also allows. A registration always
/// supplies the bindings document.
///
/// # Errors
/// Returns [`ErrorCode::ValidationError`] or [`ErrorCode::Conflict`] with the
/// contract's refusal identifier in the `rule` detail.
pub fn read_registered_solution(
    solution: &Value,
    bindings: Option<&Value>,
) -> Result<RegisteredSolution, AxiomError> {
    let solution_id = required_str(solution, "solution_id")?;
    if !is_portable_id(&solution_id) {
        return Err(observed_rule_error(
            ERR_NOT_PORTABLE_ID,
            "the solution id is not a portable id",
            &solution_id,
        ));
    }

    // M3 first: one binding_key names at most one repository. Producing this
    // refusal before the bindings coverage check is what makes a document that
    // shares one key between two repositories refused unconditionally.
    let mut binding_by_repo: BTreeMap<String, String> = BTreeMap::new();
    let mut declared_keys: BTreeSet<String> = BTreeSet::new();
    for entry in array_or_empty(solution, "repositories")? {
        let repo_id = required_str(entry, "repo_id")?;
        let binding_key = required_str(entry, "binding_key")?;
        if !is_portable_id(&repo_id) {
            return Err(observed_rule_error(
                ERR_NOT_PORTABLE_ID,
                "a repository id is not a portable id",
                &repo_id,
            ));
        }
        if !is_portable_id(&binding_key) {
            return Err(observed_rule_error(
                ERR_NOT_PORTABLE_ALIAS,
                "a binding key is not a portable alias",
                &binding_key,
            ));
        }
        if !declared_keys.insert(binding_key.clone()) {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "two repositories declare the same binding key",
            )
            .with_detail("rule", ERR_BINDING_KEY_DUPLICATE)
            .with_detail("solution_id", &solution_id)
            .with_detail("observed", &binding_key));
        }
        binding_by_repo.entry(repo_id).or_insert(binding_key);
    }

    // M4: the bindings document covers the declared key set exactly.
    let roots = match bindings {
        Some(document) => {
            if !document.is_object() {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "the machine-local bindings document must be a JSON object",
                )
                .with_detail("rule", ERR_BINDING_KEY_UNRESOLVED)
                .with_detail("solution_id", &solution_id));
            }
            let roots = binding_roots(document);
            let missing: Vec<&str> = declared_keys
                .iter()
                .filter(|key| !roots.contains_key(*key))
                .map(String::as_str)
                .collect();
            let undeclared: Vec<&str> = roots
                .keys()
                .filter(|key| !declared_keys.contains(*key))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() || !undeclared.is_empty() {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "the machine-local bindings document does not cover the declared binding keys exactly",
                )
                .with_detail("rule", ERR_BINDING_KEY_UNRESOLVED)
                .with_detail("solution_id", &solution_id)
                .with_detail("expected", missing.join(","))
                .with_detail("actual", undeclared.join(",")));
            }
            Some(roots)
        }
        None => None,
    };

    // M2/M5/M6: one claim per entry, validated before anything is returned.
    let mut claims = Vec::new();
    let mut membership_projects = Vec::new();
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    for project in array_or_empty(solution, "projects")? {
        let project_id = required_str(project, "project_id")?;
        let repo_id = required_str(project, "repo_id")?;
        let path = required_str(project, "path")?;
        if !is_portable_id(&project_id) {
            return Err(observed_rule_error(
                ERR_NOT_PORTABLE_ID,
                "a project id is not a portable id",
                &project_id,
            ));
        }
        if !is_portable_id(&repo_id) {
            return Err(observed_rule_error(
                ERR_NOT_PORTABLE_ID,
                "a project repository id is not a portable id",
                &repo_id,
            ));
        }
        if !is_repository_relative(&path) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a project path is not a repository-relative path",
            )
            .with_detail("rule", ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE)
            .with_detail("project_id", &project_id)
            .with_detail("solution_id", &solution_id)
            .with_detail("observed", &path));
        }
        if !seen_ids.insert(project_id.clone()) {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "project id is duplicated in this solution",
            )
            .with_detail("rule", ERR_DUPLICATE_PROJECT_ID)
            .with_detail("project_id", &project_id)
            .with_detail("solution_id", &solution_id));
        }
        let binding_key = binding_by_repo.get(&repo_id).cloned().ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "a project names a repository that no declared binding covers",
            )
            .with_detail("rule", ERR_BINDING_KEY_UNRESOLVED)
            .with_detail("project_id", &project_id)
            .with_detail("solution_id", &solution_id)
            .with_detail("observed", &repo_id)
        })?;
        let absolute_root = match roots.as_ref() {
            Some(roots) => {
                let root = roots.get(&binding_key).ok_or_else(|| {
                    AxiomError::new(
                        ErrorCode::ValidationError,
                        "a declared binding key has no machine-local root",
                    )
                    .with_detail("rule", ERR_BINDING_KEY_UNRESOLVED)
                    .with_detail("project_id", &project_id)
                    .with_detail("solution_id", &solution_id)
                    .with_detail("observed", &binding_key)
                })?;
                Some(contained_absolute_root(root, &path).ok_or_else(|| {
                    AxiomError::new(
                        ErrorCode::ValidationError,
                        "the derived project root leaves its bound local root",
                    )
                    .with_detail("rule", ERR_PROJECT_ROOT_ESCAPES_BINDING)
                    .with_detail("project_id", &project_id)
                    .with_detail("solution_id", &solution_id)
                    .with_detail("observed", root)
                })?)
            }
            None => None,
        };
        let language_profile = project
            .get("language_profile")
            .and_then(Value::as_str)
            .map(str::to_owned);
        claims.push(MembershipClaim {
            project_id: project_id.clone(),
            repo_id: repo_id.clone(),
            binding_key,
            path: path.clone(),
            absolute_root,
            language_profile,
        });
        membership_projects.push(ProjectMembership::new(project_id, repo_id, path));
    }

    // Shared id and root-overlap rules (B-013): the same frozen check the
    // membership validator already owns, run over the claims read above.
    let membership = SolutionMembership::new(solution_id.clone(), membership_projects);
    validate_membership(&membership)?;

    // M7 plus section 3 alias derivation.
    let mut aliases = Vec::new();
    for link in array_or_empty(solution, "semantic_links")? {
        let source = required_str(link, "source_project")?;
        let target = required_str(link, "target_project")?;
        if !seen_ids.contains(&source) || !seen_ids.contains(&target) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a semantic link endpoint is not a member of the solution",
            )
            .with_detail("rule", ERR_LINK_ENDPOINT_NOT_MEMBER)
            .with_detail("solution_id", &solution_id)
            .with_detail("project_id", &target)
            .with_detail("observed", &source));
        }
        let protocol = required_str(link, "protocol")?;
        if !LINK_PROTOCOLS.contains(&protocol.as_str()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a semantic link protocol is not a supported value",
            )
            .with_detail("rule", ERR_DOCUMENT_SHAPE)
            .with_detail("solution_id", &solution_id)
            .with_detail("config_key", "protocol")
            .with_detail("observed", &protocol));
        }
        // Section 3 coverage: `http`, `sql` and `message` require a route
        // prefix, while `explicit` may omit it. A *present* value is never
        // silently ignored. JSON `null` is the absent form, because the frozen
        // evaluator reads the field with `.get()` and cannot tell an explicit
        // null from an omitted key.
        let declared_route = match link.get("route_prefix") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value),
        };
        let route_prefix = declared_route
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        match route_prefix {
            Some(route) => {
                if !is_portable_free_text(route) {
                    return Err(AxiomError::new(
                        ErrorCode::ValidationError,
                        "a route prefix must be portable free text",
                    )
                    .with_detail("rule", ERR_ROUTE_PREFIX_NOT_PORTABLE_FREE_TEXT)
                    .with_detail("solution_id", &solution_id)
                    .with_detail("config_key", "route_prefix"));
                }
                if !route.starts_with('/') {
                    return Err(AxiomError::new(
                        ErrorCode::ValidationError,
                        "a route prefix must be an absolute, slash-led service spelling",
                    )
                    .with_detail("rule", ERR_ROUTE_PREFIX_NOT_ABSOLUTE)
                    .with_detail("solution_id", &solution_id)
                    .with_detail("observed", route));
                }
                aliases.push(ServiceAlias {
                    alias_key: normalize_service_key(route),
                    project: target,
                    protocol,
                });
            }
            None => {
                if requires_route_prefix(&protocol) {
                    return Err(AxiomError::new(
                        ErrorCode::ValidationError,
                        "an http, sql or message link requires an absolute route prefix",
                    )
                    .with_detail("rule", ERR_ROUTE_PREFIX_REQUIRED)
                    .with_detail("solution_id", &solution_id)
                    .with_detail("project_id", &target)
                    .with_detail("observed", &source));
                }
                if declared_route.is_some() {
                    // A protocol that may omit the field carried a present but
                    // unusable value: the frozen evaluator reports it with the
                    // not-absolute rule rather than dropping the declaration.
                    let observed = match declared_route {
                        Some(Value::String(text)) => text.clone(),
                        Some(value) => value.to_string(),
                        None => String::new(),
                    };
                    return Err(AxiomError::new(
                        ErrorCode::ValidationError,
                        "a declared route prefix must be an absolute, slash-led service spelling",
                    )
                    .with_detail("rule", ERR_ROUTE_PREFIX_NOT_ABSOLUTE)
                    .with_detail("solution_id", &solution_id)
                    .with_detail("observed", observed));
                }
            }
        }
    }

    Ok(RegisteredSolution {
        solution_id,
        claims,
        aliases,
    })
}

/// True when `protocol` needs a route prefix to produce an alias.
fn requires_route_prefix(protocol: &str) -> bool {
    matches!(protocol, "http" | "sql" | "message")
}

/// Section 4 rule 3: equality, or a prefix that ends at a `/` boundary.
///
/// `alias_key` = `/api` matches `/api/auth` and does not match `/apix`.
fn alias_key_matches(alias_key: &str, address_key: &str) -> bool {
    if alias_key == address_key {
        return true;
    }
    address_key
        .strip_prefix(alias_key)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Section 2 M5: relative, forward-slash, no empty/`.`/`..` segment, no trailing
/// separator and no drive prefix.
fn is_repository_relative(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') || path.contains('\\') {
        return false;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    !path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

/// Section 2 M6: join a bound root with a normalized relative path and re-verify
/// that the result stays inside the bound root.
///
/// The containment check is a second net after M5. A bound root whose own trail
/// carries a `..` segment is refused here, because a root reached through a `..`
/// segment is never a claim even when the lexical join still looks contained.
fn contained_absolute_root(root: &str, path: &str) -> Option<String> {
    if root.split('/').any(|segment| segment == "..") {
        return None;
    }
    if root == "/" {
        return Some(format!("/{path}"));
    }
    let joined = format!("{root}/{path}");
    if joined.starts_with(&format!("{root}/")) {
        Some(joined)
    } else {
        None
    }
}

/// The absolute local roots carried by a bindings document, keyed by binding key.
///
/// Values that are not an absolute local root are not a root at all, so they stay
/// absent and M4 reports the declared key as unresolved instead of inventing one.
fn binding_roots(bindings: &Value) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    let table = bindings.get("bindings").and_then(Value::as_object);
    let Some(table) = table else {
        return roots;
    };
    for (key, value) in table {
        let Some(root) = value.as_str().filter(|root| is_absolute_host_path(root)) else {
            continue;
        };
        let normalized = root.replace('\\', "/");
        let trimmed = normalized.trim_end_matches('/');
        let root = if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        };
        roots.insert(key.clone(), root);
    }
    roots
}

fn required_str(document: &Value, key: &str) -> Result<String, AxiomError> {
    document
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ValidationError,
                format!("a registered solution document requires a non-empty {key}"),
            )
            .with_detail("rule", ERR_DOCUMENT_SHAPE)
            .with_detail("config_key", key)
        })
}

fn array_or_empty<'a>(document: &'a Value, key: &str) -> Result<Vec<&'a Value>, AxiomError> {
    match document.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(entries)) => Ok(entries.iter().collect()),
        Some(_) => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("{key} must be a JSON array"),
        )
        .with_detail("rule", ERR_DOCUMENT_SHAPE)
        .with_detail("config_key", key)),
    }
}

fn observed_rule_error(rule: &str, message: &str, observed: &str) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// The contract's deterministic, pure, filesystem-free service-key normalizer.
///
/// The steps, in order: trim and lowercase; drop a `<scheme>://` prefix and, for
/// `http`/`https`, a default `:80`/`:443` port; collapse each run of `/` into one
/// while keeping a leading `//` authority marker intact; drop one trailing `/`
/// unless the value is exactly `/`.
///
/// So `//Orders.Contoso.Example/` normalizes to `//orders.contoso.example`,
/// `//host//api` to `//host/api` and `/api/auth/` to `/api/auth`. This function
/// refuses nothing: the reader checks portability and the slash-led rule before
/// calling it.
#[must_use]
pub fn normalize_service_key(value: &str) -> String {
    let mut text = value.trim().to_lowercase();
    if let Some(scheme_end) = scheme_prefix_end(&text) {
        let scheme = text[..scheme_end].to_string();
        text = format!("//{}", &text[scheme_end + 3..]);
        if scheme == "http" {
            text = strip_default_port(&text, ":80");
        } else if scheme == "https" {
            text = strip_default_port(&text, ":443");
        }
    }
    let (prefix, rest) = match text.strip_prefix("//") {
        Some(rest) => ("//", rest),
        None => ("", text.as_str()),
    };
    let mut normalized = String::with_capacity(text.len());
    normalized.push_str(prefix);
    normalized.push_str(&collapse_slashes(rest));
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

/// The byte length of a leading `scheme` in `scheme://`, when there is one.
fn scheme_prefix_end(text: &str) -> Option<usize> {
    let end = text.find("://")?;
    if end == 0 {
        return None;
    }
    let scheme = &text[..end];
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
    {
        return None;
    }
    Some(end)
}

/// Drop a default port when it terminates the authority and nothing else follows.
fn strip_default_port(text: &str, default_port: &str) -> String {
    let Some(rest) = text.strip_prefix("//") else {
        return text.to_string();
    };
    let end = rest.find(['/', ':']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return text.to_string();
    }
    let tail = &rest[end..];
    match tail.strip_prefix(default_port) {
        Some(after) if after.is_empty() || after.starts_with('/') => {
            format!("//{authority}{after}")
        }
        _ => text.to_string(),
    }
}

/// Collapse each run of `/` into one `/`.
fn collapse_slashes(text: &str) -> String {
    let mut collapsed = String::with_capacity(text.len());
    let mut previous_slash = false;
    for ch in text.chars() {
        if ch == '/' {
            if previous_slash {
                continue;
            }
            previous_slash = true;
        } else {
            previous_slash = false;
        }
        collapsed.push(ch);
    }
    collapsed
}

/// Section 3 step 1: portable free text carries no machine-local reference and no
/// credential-shaped value.
#[must_use]
pub fn is_portable_free_text(value: &str) -> bool {
    !looks_machine_local(value) && !looks_like_secret(value)
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// True when `value` carries `%VAR%`, `$env:VAR`, `$VAR` or `${VAR}` in a
/// machine-local position.
fn looks_machine_local(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    has_percent_reference(&lower)
        || has_dollar_env_reference(&lower)
        || has_dollar_reference(&lower)
}

/// `%[A-Za-z_][A-Za-z0-9_]*%`.
fn has_percent_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (start, byte) in bytes.iter().enumerate() {
        if *byte != b'%' {
            continue;
        }
        let index = start + 1;
        match bytes.get(index).copied() {
            Some(next) if is_identifier_start(next) => {}
            _ => continue,
        }
        let mut index = index + 1;
        while matches!(bytes.get(index), Some(next) if is_word_byte(*next)) {
            index += 1;
        }
        if bytes.get(index).copied() == Some(b'%') {
            return true;
        }
    }
    false
}

/// `$env:[A-Za-z_][A-Za-z0-9_]*`.
fn has_dollar_env_reference(value: &str) -> bool {
    let mut rest = value;
    while let Some(offset) = rest.find("$env:") {
        if rest.as_bytes()[offset + 5..]
            .first()
            .copied()
            .is_some_and(is_identifier_start)
        {
            return true;
        }
        rest = &rest[offset + 1..];
    }
    false
}

/// `$` optionally braced identifier followed by a path separator or the end.
fn has_dollar_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (start, byte) in bytes.iter().enumerate() {
        if *byte != b'$' {
            continue;
        }
        let mut index = start + 1;
        if bytes.get(index).copied() == Some(b'{') {
            index += 1;
        }
        match bytes.get(index).copied() {
            Some(next) if is_identifier_start(next) => {}
            _ => continue,
        }
        index += 1;
        while matches!(bytes.get(index), Some(next) if is_word_byte(*next)) {
            index += 1;
        }
        if bytes.get(index).copied() == Some(b'}') {
            index += 1;
        }
        match bytes.get(index).copied() {
            None | Some(b'/' | b'\\') => return true,
            _ => {}
        }
    }
    false
}

/// True when `value` carries a credential-shaped value.
fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    has_bearer(&lower)
        || has_github_token(&lower)
        || has_github_pat(&lower)
        || has_sk_token(value)
        || has_aws_access_key(value)
        || has_private_key_marker(value)
        || has_jwt(value)
        || has_credentialed_authority(&lower)
}

/// `\bbearer\s+\S+`.
fn has_bearer(value: &str) -> bool {
    const MARKER: &str = "bearer";
    let mut rest = value;
    while let Some(at) = rest.find(MARKER) {
        let bytes = rest.as_bytes();
        let before_is_boundary = at == 0 || !is_word_byte(bytes[at - 1]);
        let mut index = at + MARKER.len();
        let whitespace = |byte: &u8| byte.is_ascii_whitespace();
        if before_is_boundary && bytes.get(index).is_some_and(whitespace) {
            while bytes.get(index).is_some_and(whitespace) {
                index += 1;
            }
            if index < bytes.len() {
                return true;
            }
        }
        rest = &rest[at + 1..];
    }
    false
}

/// `\bgh[pousr]_[A-Za-z0-9]{16,}`.
fn has_github_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (start, byte) in bytes.iter().enumerate() {
        if *byte != b'g' || bytes.get(start + 1).copied() != Some(b'h') {
            continue;
        }
        if !matches!(
            bytes.get(start + 2).copied(),
            Some(b'p' | b'o' | b'u' | b's' | b'r')
        ) {
            continue;
        }
        if bytes.get(start + 3).copied() != Some(b'_') {
            continue;
        }
        if start > 0 && is_word_byte(bytes[start - 1]) {
            continue;
        }
        let mut index = start + 4;
        let run_start = index;
        while matches!(bytes.get(index), Some(next) if next.is_ascii_alphanumeric()) {
            index += 1;
        }
        if index - run_start >= 16 {
            return true;
        }
    }
    false
}

/// `\bgithub_pat_[A-Za-z0-9_]{20,}`.
fn has_github_pat(value: &str) -> bool {
    prefixed_run(
        value,
        "github_pat_",
        |byte| byte.is_ascii_alphanumeric() || byte == b'_',
        20,
    )
}

/// `\bsk-[A-Za-z0-9_-]{16,}`.
fn has_sk_token(value: &str) -> bool {
    prefixed_run(
        value,
        "sk-",
        |byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-',
        16,
    )
}

fn prefixed_run(value: &str, prefix: &str, accept: fn(u8) -> bool, minimum: usize) -> bool {
    let mut rest = value;
    while let Some(offset) = rest.find(prefix) {
        if offset == 0 || !is_word_byte(rest.as_bytes()[offset - 1]) {
            let after = &rest[offset + prefix.len()..];
            let run = after.bytes().take_while(|byte| accept(*byte)).count();
            if run >= minimum {
                return true;
            }
        }
        rest = &rest[offset + 1..];
    }
    false
}

/// `\bAKIA[0-9A-Z]{16}\b`.
fn has_aws_access_key(value: &str) -> bool {
    const PREFIX: &str = "AKIA";
    let mut rest = value;
    while let Some(offset) = rest.find(PREFIX) {
        if offset == 0 || !is_word_byte(rest.as_bytes()[offset - 1]) {
            let after = &rest[offset + PREFIX.len()..];
            let run = after
                .bytes()
                .take(16)
                .filter(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
                .count();
            let boundary = after.as_bytes().get(16).copied();
            if run == 16 && boundary.is_none_or(|byte| !is_word_byte(byte)) {
                return true;
            }
        }
        rest = &rest[offset + 1..];
    }
    false
}

/// `-----BEGIN [A-Z ]*PRIVATE KEY-----`.
fn has_private_key_marker(value: &str) -> bool {
    const MARKER: &str = "-----BEGIN ";
    const TAIL: &str = "PRIVATE KEY-----";
    let bytes = value.as_bytes();
    let mut rest = value;
    while let Some(offset) = rest.find(MARKER) {
        let mut index = offset + MARKER.len();
        while matches!(bytes.get(index), Some(byte) if byte.is_ascii_uppercase() || *byte == b' ') {
            index += 1;
        }
        if value[index..].starts_with(TAIL) {
            return true;
        }
        rest = &rest[offset + 1..];
    }
    false
}

/// `\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b`.
fn has_jwt(value: &str) -> bool {
    let mut rest = value;
    while let Some(offset) = rest.find("eyJ") {
        let at_a_word_boundary = offset == 0 || !is_word_byte(rest.as_bytes()[offset - 1]);
        if at_a_word_boundary && jwt_length(&rest[offset..]).is_some() {
            return true;
        }
        rest = &rest[offset + 1..];
    }
    false
}

fn jwt_length(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let segment = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-';
    let mut index = 0;
    for number in 0..3 {
        let run = bytes[index..]
            .iter()
            .take_while(|byte| segment(**byte))
            .count();
        if run < 6 {
            return None;
        }
        index += run;
        if number < 2 {
            if bytes.get(index).copied() != Some(b'.') {
                return None;
            }
            index += 1;
        }
    }
    match bytes.get(index).copied() {
        None => Some(index),
        Some(byte) if !is_word_byte(byte) => Some(index),
        _ => None,
    }
}

/// `[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`.
fn has_credentialed_authority(value: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = value[from..].find("://") {
        let at = from + offset;
        let mut scheme_start = at;
        while scheme_start > 0 && is_scheme_byte(value.as_bytes()[scheme_start - 1]) {
            scheme_start -= 1;
        }
        let scheme = &value[scheme_start..at];
        if scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
            && has_credentialed_tail(&value[at + 3..])
        {
            return true;
        }
        from = at + 1;
        if from >= value.len() {
            break;
        }
    }
    false
}

fn is_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-')
}

/// `[^/\s:@]+:[^/\s@]+@` at the start of `after`.
fn has_credentialed_tail(after: &str) -> bool {
    let bytes = after.as_bytes();
    let mut index = 0;
    let user_start = index;
    while index < bytes.len()
        && !matches!(bytes[index], b'/' | b':' | b'@')
        && !bytes[index].is_ascii_whitespace()
    {
        index += 1;
    }
    if index == user_start || bytes.get(index).copied() != Some(b':') {
        return false;
    }
    index += 1;
    let password_start = index;
    while index < bytes.len()
        && !matches!(bytes[index], b'/' | b'@')
        && !bytes[index].is_ascii_whitespace()
    {
        index += 1;
    }
    index > password_start && bytes.get(index).copied() == Some(b'@')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(alias_key: &str, project: &str, protocol: &str) -> ServiceAlias {
        ServiceAlias {
            alias_key: alias_key.to_string(),
            project: project.to_string(),
            protocol: protocol.to_string(),
        }
    }

    #[test]
    fn normalization_matches_the_contract_examples() {
        assert_eq!(
            normalize_service_key("//Orders.Contoso.Example/"),
            "//orders.contoso.example"
        );
        assert_eq!(normalize_service_key("//host//api"), "//host/api");
        assert_eq!(normalize_service_key("/api/auth/"), "/api/auth");
        assert_eq!(normalize_service_key("/"), "/");
        assert_eq!(normalize_service_key("  /API/Auth  "), "/api/auth");
        assert_eq!(
            normalize_service_key("HTTPS://Orders.Contoso.Example:443/x"),
            "//orders.contoso.example/x"
        );
        assert_eq!(
            normalize_service_key("http://billing.contoso.example:80"),
            "//billing.contoso.example"
        );
        assert_eq!(normalize_service_key("/api"), "/api");
    }

    #[test]
    fn prefix_matching_requires_a_slash_boundary() {
        assert!(alias_key_matches("/api", "/api"));
        assert!(alias_key_matches("/api", "/api/auth"));
        assert!(!alias_key_matches("/api", "/apix"));
        assert!(!alias_key_matches("/api/auth", "/api"));
    }

    #[test]
    fn machine_local_and_credential_shaped_values_are_not_portable_free_text() {
        for value in [
            "%USERPROFILE%/api",
            "$HOME/api",
            "${HOME}/api",
            "$env:HOME/api",
            "sk-aaaaaaaaaaaaaaaaaaaa",
            "ghp_aaaaaaaaaaaaaaaaaaaa",
            "github_pat_aaaaaaaaaaaaaaaaaaaaaaaa",
            "AKIAIOSFODNN7EXAMPLE",
            "Bearer abcdefghijklmnop",
            "https://user:password@example.invalid/api",
            "/api/v1/$metadata",
        ] {
            assert!(
                !is_portable_free_text(value),
                "{value} must not be portable free text"
            );
        }
        for value in ["/api/auth", "//orders.contoso.example", "/api/items/42"] {
            assert!(
                is_portable_free_text(value),
                "{value} must stay portable free text"
            );
        }
    }

    #[test]
    fn containment_refuses_a_bound_root_with_a_parent_segment() {
        assert_eq!(
            contained_absolute_root("/srv/checkout/web", "src"),
            Some("/srv/checkout/web/src".to_string())
        );
        assert_eq!(
            contained_absolute_root("/", "src"),
            Some("/src".to_string())
        );
        assert_eq!(contained_absolute_root("/srv/checkout/web/..", "src"), None);
    }

    #[test]
    fn the_l3_host_key_is_authority_only() {
        assert_eq!(
            alias("//orders.contoso.example", "orders-api", "http").l3_host_key(),
            Some("orders.contoso.example".to_string())
        );
        assert_eq!(
            alias("//host/api", "orders-api", "http").l3_host_key(),
            Some("host".to_string())
        );
        assert_eq!(alias("/api/auth", "auth-api", "http").l3_host_key(), None);
    }

    #[test]
    fn an_alias_resolution_reports_the_contract_reason() {
        assert_eq!(AliasResolution::Resolved("a").reason(), None);
        assert_eq!(
            AliasResolution::Unresolved.reason(),
            Some(ERR_ALIAS_UNRESOLVED_HOST)
        );
        assert_eq!(
            AliasResolution::Ambiguous.reason(),
            Some(ERR_ALIAS_AMBIGUOUS_HOST)
        );
    }

    /// One solution document carrying a single `explicit` link whose
    /// `route_prefix` is patched, so the absent/present branches are isolated.
    fn explicit_link_document(route_prefix: Value) -> Value {
        serde_json::json!({
            "schema_version": 2,
            "solution_id": "demo",
            "repositories": [
                {"repo_id": "a", "binding_key": "a"},
                {"repo_id": "b", "binding_key": "b"}
            ],
            "projects": [
                {"project_id": "a-api", "repo_id": "a", "path": "src"},
                {"project_id": "b-api", "repo_id": "b", "path": "src"}
            ],
            "semantic_links": [
                {
                    "source_project": "a-api",
                    "target_project": "b-api",
                    "protocol": "explicit",
                    "route_prefix": route_prefix
                }
            ]
        })
    }

    fn refusal_of(document: &Value) -> String {
        read_registered_solution(document, None)
            .expect_err("the document is refused")
            .details()
            .get("rule")
            .cloned()
            .expect("the reader reports a rule")
    }

    #[test]
    fn a_present_but_unusable_route_prefix_is_not_silently_ignored() {
        // A present value that is not an absolute spelling is reported rather
        // than dropped, exactly as the frozen evaluator reports it.
        for route_prefix in [serde_json::json!(""), serde_json::json!(7)] {
            assert_eq!(
                refusal_of(&explicit_link_document(route_prefix)),
                ERR_ROUTE_PREFIX_NOT_ABSOLUTE
            );
        }

        // `null` and an omitted key are the absent form; `explicit` may omit it.
        let mut omitted = explicit_link_document(Value::Null);
        omitted["semantic_links"][0]
            .as_object_mut()
            .expect("the link is an object")
            .remove("route_prefix");
        for document in [explicit_link_document(Value::Null), omitted] {
            let registered = read_registered_solution(&document, None).expect("accepted");
            assert!(registered.aliases().is_empty());
        }

        // A required protocol reports the missing-route rule in both forms.
        for route_prefix in [Value::Null, serde_json::json!("")] {
            let mut document = explicit_link_document(route_prefix);
            document["semantic_links"][0]["protocol"] = serde_json::json!("http");
            assert_eq!(refusal_of(&document), ERR_ROUTE_PREFIX_REQUIRED);
        }
    }
}
