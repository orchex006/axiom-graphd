//! Loopback control authentication (task B-083).
//!
//! `docs/23-SECURITY-AND-TRUST.md` requires a loopback-only control surface with
//! token audiences and scopes, and `docs/16-CLI-AND-CONTROL-API.md` section 7
//! requires that source-root authorization cannot be changed through an ordinary
//! read or reconcile token. The two requirements meet in one invariant: **a
//! token's audience, not its scope list, decides whether it can reach the
//! administration surface.** An MCP reader token is built with the
//! [`Audience::Mcp`] audience and can therefore never become a daemon
//! administration token, even if a configuration file tries to grant it the
//! [`Scope::Admin`] scope. Such a configuration is refused while the registry is
//! loaded, with [`REASON_ADMIN_NOT_DELEGABLE`], so the escalation cannot exist
//! rather than merely being rejected at call time.
//!
//! Secrets are never retained. A [`ControlToken`] keeps only the SHA-256 digest
//! of the presented secret, so the registry can authenticate without holding
//! anything that would let an attacker replay it, and a debug rendering never
//! prints a secret or a digest.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use graph_core::error::{AxiomError, ErrorCode};

/// Upper bound on a presented token, in bytes, before it is hashed.
pub const MAX_TOKEN_BYTES: usize = 512;
/// Reason recorded when no token was presented.
pub const REASON_TOKEN_MISSING: &str = "token-missing";
/// Reason recorded when a token is longer than [`MAX_TOKEN_BYTES`].
pub const REASON_TOKEN_MALFORMED: &str = "token-malformed";
/// Reason recorded when a presented token matches no registered entry.
pub const REASON_TOKEN_UNKNOWN: &str = "token-unknown";
/// Reason recorded when a token's audience cannot reach the requested surface.
pub const REASON_AUDIENCE_NOT_ACCEPTED: &str = "audience-not-accepted";
/// Reason recorded when a token does not carry the requested scope.
pub const REASON_SCOPE_MISSING: &str = "scope-missing";
/// Reason recorded when a non-administered audience is granted the admin scope.
pub const REASON_ADMIN_NOT_DELEGABLE: &str = "admin-not-delegable";
/// Reason recorded when a token id is registered twice with different secrets.
pub const REASON_DUPLICATE_TOKEN_ID: &str = "duplicate-token-id";
/// Reason recorded when a token is not authorized for a solution id.
pub const REASON_SOLUTION_NOT_AUTHORIZED: &str = "solution-not-authorized";

/// The surface a token was minted for.
///
/// The audience is the outermost gate. [`Scope::Admin`] is only reachable from
/// [`Audience::Administrator`], which no reader-side constructor produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Audience {
    /// The MCP read-only surface.
    Mcp,
    /// The loopback REST control API (`docs/16-CLI-AND-CONTROL-API.md` 5).
    ControlApi,
    /// The operator CLI running in the same user session.
    Cli,
    /// The administration surface: registry mutation and trust changes.
    Administrator,
}

impl Audience {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::ControlApi => "control-api",
            Self::Cli => "cli",
            Self::Administrator => "administrator",
        }
    }

    /// Parse a wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "mcp" => Some(Self::Mcp),
            "control-api" => Some(Self::ControlApi),
            "cli" => Some(Self::Cli),
            "administrator" => Some(Self::Administrator),
            _ => None,
        }
    }

    /// Whether this audience may reach the administration surface.
    #[must_use]
    pub const fn accepts_administration(self) -> bool {
        matches!(self, Self::Administrator)
    }

    /// Whether this audience is read-only by construction.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::Mcp)
    }
}
/// One capability a token may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Read scoped registry, status and snapshot data.
    Read,
    /// Submit verified change hints and queued reconcile requests.
    Reconcile,
    /// Create staged/worktree checkpoints.
    CheckpointWrite,
    /// Verify a source fingerprint.
    Verify,
    /// Mutate the solution registry and the trust configuration.
    Admin,
}

impl Scope {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Reconcile => "reconcile",
            Self::CheckpointWrite => "checkpoint-write",
            Self::Verify => "verify",
            Self::Admin => "admin",
        }
    }

    /// Parse a wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "read" => Some(Self::Read),
            "reconcile" => Some(Self::Reconcile),
            "checkpoint-write" => Some(Self::CheckpointWrite),
            "verify" => Some(Self::Verify),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Whether carrying this scope lets a caller mutate daemon state.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(self, Self::Read)
    }
}

/// Lowercase hex SHA-256 of a presented secret.
#[must_use]
pub fn digest(secret: &str) -> String {
    graph_export::sha256_hex(secret.as_bytes())
}

/// Compare two 64-character hex digests without an early exit on first byte.
///
/// The loop runs over the whole pair in both the equal and unequal case, so an
/// attacker cannot learn how many characters matched from the response time.
#[must_use]
pub fn digest_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// One registered token: an audience, a scope set and an optional solution scope.
///
/// The secret is reduced to a digest at construction and is never stored or
/// rendered.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlToken {
    id: String,
    secret_digest: String,
    audience: Audience,
    scopes: BTreeSet<Scope>,
    solutions: Option<Vec<String>>,
}

impl fmt::Debug for ControlToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlToken")
            .field("id", &self.id)
            .field("audience", &self.audience)
            .field("scopes", &self.scopes)
            .field("solutions", &self.solutions)
            .finish_non_exhaustive()
    }
}

impl ControlToken {
    /// Build a token with an explicit audience and scope set.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`REASON_ADMIN_NOT_DELEGABLE`] when a
    /// non-administrator audience is given [`Scope::Admin`]. This is the only
    /// way to construct a token, so the escalation cannot be represented.
    pub fn new(
        id: impl Into<String>,
        secret: &str,
        audience: Audience,
        scopes: impl IntoIterator<Item = Scope>,
    ) -> Result<Self, AxiomError> {
        let id = id.into();
        if id.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a control token id must not be empty",
            )
            .with_detail("rule", REASON_TOKEN_MALFORMED));
        }
        let scopes: BTreeSet<Scope> = scopes.into_iter().collect();
        if scopes.contains(&Scope::Admin) && !audience.accepts_administration() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the admin scope cannot be delegated to a read-side audience",
            )
            .with_detail("rule", REASON_ADMIN_NOT_DELEGABLE)
            .with_detail("token_id", id)
            .with_detail("audience", audience.wire()));
        }
        Ok(Self {
            id,
            secret_digest: digest(secret),
            audience,
            scopes,
            solutions: None,
        })
    }

    /// The daemon administration token: the only constructor that reaches the
    /// administration surface.
    #[must_use]
    pub fn administrator(id: impl Into<String>, secret: &str) -> Self {
        Self {
            id: id.into(),
            secret_digest: digest(secret),
            audience: Audience::Administrator,
            scopes: [
                Scope::Read,
                Scope::Reconcile,
                Scope::CheckpointWrite,
                Scope::Verify,
                Scope::Admin,
            ]
            .into_iter()
            .collect(),
            solutions: None,
        }
    }

    /// The MCP read-only token for a bounded set of solutions.
    #[must_use]
    pub fn mcp_reader(id: impl Into<String>, secret: &str, solutions: Vec<String>) -> Self {
        Self {
            id: id.into(),
            secret_digest: digest(secret),
            audience: Audience::Mcp,
            scopes: [Scope::Read].into_iter().collect(),
            solutions: Some(solutions),
        }
    }

    /// Narrow this token to the listed solutions.
    #[must_use]
    pub fn scoped_to(mut self, solutions: Option<Vec<String>>) -> Self {
        self.solutions = solutions;
        self
    }

    /// Token id, safe to log.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The audience this token was minted for.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// The scopes this token carries.
    #[must_use]
    pub fn scopes(&self) -> &BTreeSet<Scope> {
        &self.scopes
    }

    /// The solution allowlist, when the token is narrowed.
    #[must_use]
    pub fn solutions(&self) -> Option<&[String]> {
        self.solutions.as_deref()
    }

    /// The digest of this token's secret.
    #[must_use]
    pub fn secret_digest(&self) -> &str {
        &self.secret_digest
    }
}
/// An authenticated caller: what remains after a token is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    token_id: String,
    audience: Audience,
    scopes: BTreeSet<Scope>,
    solutions: Option<Vec<String>>,
}

impl Principal {
    /// Token id that authenticated this caller.
    #[must_use]
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// The audience of the authenticating token.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// Whether this caller may reach the administration surface.
    #[must_use]
    pub const fn is_administration(&self) -> bool {
        self.audience.accepts_administration()
    }

    /// Whether this caller carries `scope`.
    #[must_use]
    pub fn allows(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Whether this caller is authorized for `solution_id`.
    ///
    /// # Errors
    /// [`ErrorCode::Forbidden`] with [`REASON_SOLUTION_NOT_AUTHORIZED`] when the
    /// token is narrowed and does not list the solution.
    pub fn authorize_solution(&self, solution_id: &str) -> Result<(), AxiomError> {
        if let Some(solutions) = self.solutions.as_deref() {
            if !solutions.iter().any(|allowed| allowed == solution_id) {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "the caller is not authorized for this solution",
                )
                .with_detail("rule", REASON_SOLUTION_NOT_AUTHORIZED)
                .with_detail("solution_id", solution_id));
            }
        }
        Ok(())
    }
}

/// The set of tokens a loopback control surface accepts.
#[derive(Debug, Default, Clone)]
pub struct TokenRegistry {
    by_digest: BTreeMap<String, ControlToken>,
    ids: BTreeSet<String>,
}

impl TokenRegistry {
    /// An empty registry that authenticates nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a token.
    ///
    /// # Errors
    /// [`ErrorCode::Conflict`] with [`REASON_DUPLICATE_TOKEN_ID`] when the id is
    /// already registered under a different secret.
    pub fn insert(&mut self, token: ControlToken) -> Result<(), AxiomError> {
        if self.ids.contains(token.id()) && !self.by_digest.contains_key(token.secret_digest()) {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "a control token id is already registered",
            )
            .with_detail("rule", REASON_DUPLICATE_TOKEN_ID)
            .with_detail("token_id", token.id()));
        }
        self.ids.insert(token.id().to_owned());
        self.by_digest
            .insert(token.secret_digest().to_owned(), token);
        Ok(())
    }

    /// Number of registered tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    /// Whether no token is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }

    /// Look up a token by an already computed digest.
    #[must_use]
    pub fn lookup_digest(&self, presented_digest: &str) -> Option<&ControlToken> {
        let mut found: Option<&ControlToken> = None;
        for (registered, token) in &self.by_digest {
            if digest_eq(registered, presented_digest) {
                found = Some(token);
            }
        }
        found
    }

    /// Authenticate a presented secret.
    ///
    /// # Errors
    /// [`ErrorCode::Unauthenticated`] with [`REASON_TOKEN_MISSING`] or
    /// [`REASON_TOKEN_MALFORMED`], and with [`REASON_TOKEN_UNKNOWN`] when the
    /// digest matches no registered token.
    pub fn authenticate(&self, presented: &str) -> Result<Principal, AxiomError> {
        if presented.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::Unauthenticated,
                "no control token was presented",
            )
            .with_detail("rule", REASON_TOKEN_MISSING));
        }
        if presented.len() > MAX_TOKEN_BYTES {
            return Err(AxiomError::new(
                ErrorCode::Unauthenticated,
                "the presented control token exceeds the accepted length",
            )
            .with_detail("rule", REASON_TOKEN_MALFORMED)
            .with_detail("limit", MAX_TOKEN_BYTES.to_string()));
        }
        let presented_digest = digest(presented);
        let token = self.lookup_digest(&presented_digest).ok_or_else(|| {
            AxiomError::new(
                ErrorCode::Unauthenticated,
                "the presented control token is not registered",
            )
            .with_detail("rule", REASON_TOKEN_UNKNOWN)
        })?;
        Ok(Principal {
            token_id: token.id().to_owned(),
            audience: token.audience(),
            scopes: token.scopes().clone(),
            solutions: token.solutions().map(<[String]>::to_vec),
        })
    }

    /// Authenticate for a read of `solution_id` under `scope`.
    ///
    /// # Errors
    /// The authentication error, plus [`ErrorCode::Forbidden`] with
    /// [`REASON_SCOPE_MISSING`] and the solution authorization error.
    pub fn authorize(
        &self,
        presented: &str,
        scope: Scope,
        solution_id: &str,
    ) -> Result<Principal, AxiomError> {
        let principal = self.authenticate(presented)?;
        if !principal.allows(scope) {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "the presented control token does not carry the required scope",
            )
            .with_detail("rule", REASON_SCOPE_MISSING)
            .with_detail("scope", scope.wire()));
        }
        principal.authorize_solution(solution_id)?;
        Ok(principal)
    }

    /// Authenticate for a mutating call under `scope`.
    ///
    /// The audience gate runs before the scope gate, so a read-side token whose
    /// scope set somehow contained a mutation scope is still refused.
    ///
    /// # Errors
    /// The authentication error, plus [`ErrorCode::Forbidden`] with
    /// [`REASON_AUDIENCE_NOT_ACCEPTED`] for a non-administrator audience.
    pub fn authorize_mutation(
        &self,
        presented: &str,
        scope: Scope,
    ) -> Result<Principal, AxiomError> {
        let principal = self.authenticate(presented)?;
        if !principal.is_administration() {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "this audience cannot reach the administration surface",
            )
            .with_detail("rule", REASON_AUDIENCE_NOT_ACCEPTED)
            .with_detail("audience", principal.audience().wire())
            .with_detail("required_audience", Audience::Administrator.wire()));
        }
        if !principal.allows(scope) {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "the presented control token does not carry the required scope",
            )
            .with_detail("rule", REASON_SCOPE_MISSING)
            .with_detail("scope", scope.wire()));
        }
        Ok(principal)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> TokenRegistry {
        let mut registry = TokenRegistry::new();
        registry
            .insert(ControlToken::administrator(
                "admin-local",
                "admin-secret-value",
            ))
            .expect("admin token");
        registry
            .insert(ControlToken::mcp_reader(
                "mcp-reader",
                "reader-secret-value",
                vec!["demo-solution".to_owned()],
            ))
            .expect("reader token");
        registry
            .insert(
                ControlToken::new(
                    "cli-operator",
                    "cli-secret-value",
                    Audience::Cli,
                    [Scope::Read, Scope::Reconcile],
                )
                .expect("cli token"),
            )
            .expect("insert");
        registry
    }

    #[test]
    fn an_administrator_token_reaches_the_administration_surface() {
        let registry = registry();
        let principal = registry
            .authorize_mutation("admin-secret-value", Scope::Admin)
            .expect("admin mutation");
        assert!(principal.is_administration());
        assert_eq!(principal.token_id(), "admin-local");
        assert_eq!(principal.audience(), Audience::Administrator);
    }

    #[test]
    fn an_mcp_reader_token_cannot_become_a_daemon_administration_token() {
        let registry = registry();
        // The reader token can read its own solution.
        registry
            .authorize("reader-secret-value", Scope::Read, "demo-solution")
            .expect("scoped read");
        // The same secret is refused on the administration surface.
        let error = registry
            .authorize_mutation("reader-secret-value", Scope::Admin)
            .expect_err("reader token must not administer");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_AUDIENCE_NOT_ACCEPTED)
        );
        // A reader token cannot be re-labelled as an administrator.
        let error = ControlToken::new(
            "reader-promoted",
            "reader-secret-value",
            Audience::Mcp,
            [Scope::Admin],
        )
        .expect_err("admin scope is not delegable to mcp");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_ADMIN_NOT_DELEGABLE)
        );
    }

    #[test]
    fn boundary_unknown_empty_and_oversized_tokens_are_unauthenticated() {
        let registry = registry();
        assert_eq!(
            registry
                .authenticate("")
                .expect_err("empty")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(REASON_TOKEN_MISSING)
        );
        assert_eq!(
            registry
                .authenticate("not-a-registered-secret")
                .expect_err("unknown")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(REASON_TOKEN_UNKNOWN)
        );
        let oversized = "x".repeat(MAX_TOKEN_BYTES + 1);
        assert_eq!(
            registry
                .authenticate(&oversized)
                .expect_err("oversized")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(REASON_TOKEN_MALFORMED)
        );
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn a_narrowed_token_is_refused_for_another_solution() {
        let registry = registry();
        let error = registry
            .authorize("reader-secret-value", Scope::Read, "other-solution")
            .expect_err("out of scope solution");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_AUTHORIZED)
        );
        // A CLI token without the checkpoint scope is refused, not silently read-only.
        let error = registry
            .authorize("cli-secret-value", Scope::CheckpointWrite, "demo-solution")
            .expect_err("missing scope");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SCOPE_MISSING)
        );
    }

    #[test]
    fn digests_are_stable_and_comparison_never_short_circuits_on_length() {
        assert_eq!(digest("abc"), digest("abc"));
        assert_ne!(digest("abc"), digest("abd"));
        assert_eq!(digest("abc").len(), 64);
        assert!(digest_eq(&digest("abc"), &digest("abc")));
        assert!(!digest_eq(&digest("abc"), &digest("abd")));
        assert!(!digest_eq(&digest("abc"), "00"));
        // A token never renders its secret or its digest.
        let token = ControlToken::administrator("a", "top-secret-value");
        let text = format!("{token:?}");
        assert!(!text.contains("top-secret-value"));
        assert!(!text.contains(&digest("top-secret-value")));
    }

    #[test]
    fn a_duplicate_token_id_under_a_new_secret_is_a_conflict() {
        let mut registry = TokenRegistry::new();
        registry
            .insert(ControlToken::administrator("admin", "one"))
            .expect("first");
        let error = registry
            .insert(ControlToken::administrator("admin", "two"))
            .expect_err("duplicate id");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_DUPLICATE_TOKEN_ID)
        );
    }
}
