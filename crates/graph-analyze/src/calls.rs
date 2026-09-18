//! Conservative call-site evidence (task B-052).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 3 is the rule this module
//! implements: a call that resolves to exactly one explicitly declared symbol
//! becomes a `CALLS` edge with `exact_static` quality, while a call through an
//! interface keeps the interface call and the *possible* implementations as
//! separate `inferred_static` edges. Registration, dependency injection and
//! runtime type selection are never treated as proof of which implementation
//! runs, so a call site with several implementations never collapses onto one
//! of them.
//!
//! Everything the analyser cannot prove is left unresolved together with a
//! reason. A computed member name, a delegate invocation and a call whose
//! target is not declared in the project are all "not proven", and the graph
//! must say so instead of inventing a confident edge.

/// Reason recorded for a call whose member is computed at run time.
pub const REASON_DYNAMIC_DISPATCH: &str = "call-dynamic-dispatch";
/// Reason recorded when no declared symbol matches the callee.
pub const REASON_MISSING_TARGET: &str = "call-missing-target";
/// Reason recorded when several declared symbols match the callee.
pub const REASON_AMBIGUOUS_TARGET: &str = "call-ambiguous-target";
/// Reason recorded for a site that is not a literal member call.
pub const REASON_NOT_A_CALL: &str = "call-not-literal";

/// The syntactic shape of one call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallKind {
    /// `Widget.Run()` with a literal receiver and member name.
    Direct,
    /// `clock.Tick()` where the receiver is an explicitly declared interface.
    InterfaceMember,
    /// A delegate or first-class function invocation.
    Delegate,
    /// A member name or receiver that is computed at run time.
    Dynamic,
}

impl CallKind {
    /// Stable spelling used in coverage and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::InterfaceMember => "interface-member",
            Self::Delegate => "delegate",
            Self::Dynamic => "dynamic",
        }
    }
}

/// What a declared target is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    /// A free function.
    Function,
    /// A method on a concrete type.
    Method,
    /// A method declared on an interface.
    InterfaceMethod,
    /// A delegate declaration.
    Delegate,
}

impl TargetKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::InterfaceMethod => "interface-method",
            Self::Delegate => "delegate",
        }
    }

    /// Whether this target must be reached through an implementation.
    #[must_use]
    pub const fn is_interface_member(self) -> bool {
        matches!(self, Self::InterfaceMethod)
    }
}

/// One symbol the project declares, keyed by its stable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredTarget {
    /// Stable key from [`crate::identity::declaration_key`].
    pub key: String,
    /// Qualified semantic path, e.g. `["App", "Widget", "Run"]`.
    pub qualified: Vec<String>,
    /// Declaring container type, when the target is a member.
    pub container: Option<String>,
    /// What kind of target this is.
    pub kind: TargetKind,
}

impl DeclaredTarget {
    /// Build a declared target.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        qualified: impl IntoIterator<Item = impl Into<String>>,
        container: Option<String>,
        kind: TargetKind,
    ) -> Self {
        Self {
            key: key.into(),
            qualified: qualified.into_iter().map(Into::into).collect(),
            container,
            kind,
        }
    }

    /// The literal member name, i.e. the last qualified segment.
    #[must_use]
    pub fn member_name(&self) -> Option<&str> {
        self.qualified.last().map(String::as_str)
    }
}

/// One explicit `implements`/inheritance declaration, so possible
/// implementations come from source declarations and never from registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplementsFact {
    /// Concrete type's stable key.
    pub implementor: String,
    /// Interface's stable key.
    pub interface: String,
}

impl ImplementsFact {
    /// Build the fact.
    #[must_use]
    pub fn new(implementor: impl Into<String>, interface: impl Into<String>) -> Self {
        Self {
            implementor: implementor.into(),
            interface: interface.into(),
        }
    }
}

/// One call site found in a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// File the call appears in, portably relative.
    pub file: String,
    /// Stable key of the calling symbol.
    pub caller: String,
    /// Literal qualified callee path, when the source has one.
    pub callee: Option<Vec<String>>,
    /// Syntactic shape.
    pub kind: CallKind,
    /// One-based line of the call, for diagnostics.
    pub line: usize,
}

impl CallSite {
    /// A direct or interface call with a literal callee path.
    #[must_use]
    pub fn literal(
        file: impl Into<String>,
        caller: impl Into<String>,
        kind: CallKind,
        callee: impl IntoIterator<Item = impl Into<String>>,
        line: usize,
    ) -> Self {
        Self {
            file: file.into(),
            caller: caller.into(),
            callee: Some(callee.into_iter().map(Into::into).collect()),
            kind,
            line,
        }
    }

    /// A call without a literal callee path.
    #[must_use]
    pub fn unresolved_kind(
        file: impl Into<String>,
        caller: impl Into<String>,
        kind: CallKind,
        line: usize,
    ) -> Self {
        Self {
            file: file.into(),
            caller: caller.into(),
            callee: None,
            kind,
            line,
        }
    }
}

/// The kind of evidence edge produced for a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallEdgeKind {
    /// The caller provably calls this target or interface member.
    Calls,
    /// The target may be reached through this implementation.
    PossibleImplementation,
}

impl CallEdgeKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Calls => "CALLS",
            Self::PossibleImplementation => "POSSIBLE_IMPLEMENTATION",
        }
    }
}

/// Resolution quality, matching the coverage document vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallQuality {
    /// Exactly one explicitly declared target matched.
    ExactStatic,
    /// The edge is a possible relationship, not a proven one.
    InferredStatic,
}

impl CallQuality {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactStatic => "exact_static",
            Self::InferredStatic => "inferred_static",
        }
    }
}

/// One evidence edge produced from a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    /// Calling symbol.
    pub caller: String,
    /// Target symbol.
    pub target: String,
    /// Edge kind.
    pub kind: CallEdgeKind,
    /// Resolution quality.
    pub quality: CallQuality,
    /// Why the edge exists; always at least one evidence tag.
    pub evidence: Vec<String>,
}

impl CallEdge {
    fn calls(caller: &str, target: &str, quality: CallQuality, evidence: &str) -> Self {
        Self {
            caller: caller.to_string(),
            target: target.to_string(),
            kind: CallEdgeKind::Calls,
            quality,
            evidence: vec![evidence.to_string()],
        }
    }

    fn possible(caller: &str, target: &str, evidence: &str) -> Self {
        Self {
            caller: caller.to_string(),
            target: target.to_string(),
            kind: CallEdgeKind::PossibleImplementation,
            quality: CallQuality::InferredStatic,
            evidence: vec![evidence.to_string()],
        }
    }
}

/// A call that could not be turned into an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedCall {
    /// File of the site.
    pub file: String,
    /// One-based line of the site.
    pub line: usize,
    /// One of the `REASON_*` constants.
    pub reason: String,
    /// Candidate keys, when the resolution was ambiguous.
    pub candidates: Vec<String>,
}

/// The complete evidence for the call sites that were analysed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallGraph {
    /// Edges, in deterministic order.
    pub edges: Vec<CallEdge>,
    /// Unresolved sites, in input order.
    pub unresolved: Vec<UnresolvedCall>,
    /// Interface calls whose implementation set is only *possible*: the source
    /// declares implementations, but dependency injection and runtime type
    /// selection are not proven, so the set is never certified as unique.
    pub unproven_implementation_sets: usize,
    /// Interface calls whose implementation set has two or more candidates;
    /// the caller keeps the whole set and does not pick one.
    pub ambiguous_implementation_sets: usize,
}

impl CallGraph {
    /// Edges whose caller is `caller`.
    #[must_use]
    pub fn edges_for(&self, caller: &str) -> Vec<&CallEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.caller == caller)
            .collect()
    }

    /// The proven `CALLS` targets of `caller`.
    #[must_use]
    pub fn calls_of(&self, caller: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|edge| edge.caller == caller && edge.kind == CallEdgeKind::Calls)
            .map(|edge| edge.target.as_str())
            .collect()
    }
}

/// The analyser input: declared targets, explicit implements facts and sites.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallInput {
    /// Declared targets.
    pub targets: Vec<DeclaredTarget>,
    /// Explicit interface implementations.
    pub implements: Vec<ImplementsFact>,
    /// Call sites.
    pub sites: Vec<CallSite>,
}

impl CallInput {
    /// Resolve every site into evidence edges.
    #[must_use]
    pub fn resolve(&self) -> CallGraph {
        let mut graph = CallGraph::default();
        for site in &self.sites {
            self.resolve_site(site, &mut graph);
        }
        graph
    }

    fn resolve_site(&self, site: &CallSite, graph: &mut CallGraph) {
        let Some(callee) = site.callee.as_deref() else {
            graph.unresolved.push(UnresolvedCall {
                file: site.file.clone(),
                line: site.line,
                reason: match site.kind {
                    CallKind::Dynamic => REASON_DYNAMIC_DISPATCH.to_string(),
                    _ => REASON_NOT_A_CALL.to_string(),
                },
                candidates: Vec::new(),
            });
            return;
        };
        if site.kind == CallKind::Dynamic {
            graph.unresolved.push(UnresolvedCall {
                file: site.file.clone(),
                line: site.line,
                reason: REASON_DYNAMIC_DISPATCH.to_string(),
                candidates: Vec::new(),
            });
            return;
        }

        let matches: Vec<&DeclaredTarget> = self
            .targets
            .iter()
            .filter(|target| target.qualified == callee)
            .collect();
        match matches.as_slice() {
            [] => graph.unresolved.push(UnresolvedCall {
                file: site.file.clone(),
                line: site.line,
                reason: REASON_MISSING_TARGET.to_string(),
                candidates: Vec::new(),
            }),
            [only] => self.resolve_unique(site, only, graph),
            many => graph.unresolved.push(UnresolvedCall {
                file: site.file.clone(),
                line: site.line,
                reason: REASON_AMBIGUOUS_TARGET.to_string(),
                candidates: many.iter().map(|target| target.key.clone()).collect(),
            }),
        }
    }

    fn resolve_unique(&self, site: &CallSite, target: &DeclaredTarget, graph: &mut CallGraph) {
        if target.kind == TargetKind::Delegate {
            // A delegate declaration is a type, not a callable body; reaching
            // one proves the call goes through a run-time selection.
            graph.unresolved.push(UnresolvedCall {
                file: site.file.clone(),
                line: site.line,
                reason: REASON_DYNAMIC_DISPATCH.to_string(),
                candidates: vec![target.key.clone()],
            });
            return;
        }
        graph.edges.push(CallEdge::calls(
            &site.caller,
            &target.key,
            CallQuality::ExactStatic,
            "explicit-member-declaration",
        ));
        if target.kind.is_interface_member() {
            self.add_possible_implementations(site, target, graph);
        }
    }

    /// Interface calls keep the interface edge and add every explicitly
    /// declared implementation as a *possible* edge. The implementation count
    /// is reported, so a caller can see that no unique implementation is
    /// certified.
    fn add_possible_implementations(
        &self,
        site: &CallSite,
        interface_target: &DeclaredTarget,
        graph: &mut CallGraph,
    ) {
        let Some(interface_container) = interface_target.container.as_deref() else {
            graph.ambiguous_implementation_sets += 1;
            return;
        };
        let member = interface_target.member_name();
        let mut implementors: Vec<&ImplementsFact> = self
            .implements
            .iter()
            .filter(|fact| fact.interface == interface_container)
            .collect();
        implementors.sort_by(|left, right| left.implementor.cmp(&right.implementor));
        let mut added = 0_usize;
        for fact in &implementors {
            let Some(candidate) = self
                .targets
                .iter()
                .filter(|target| {
                    target.container.as_deref() == Some(fact.implementor.as_str())
                        && target.member_name() == member
                })
                .min_by(|left, right| left.key.cmp(&right.key))
            else {
                continue;
            };
            graph.edges.push(CallEdge::possible(
                &site.caller,
                &candidate.key,
                "explicit-interface-implementation",
            ));
            added += 1;
        }
        if added != 1 {
            graph.ambiguous_implementation_sets += 1;
        }
        graph.unproven_implementation_sets += 1;
    }
}

/// Resolve sites directly.
#[must_use]
pub fn resolve(input: &CallInput) -> CallGraph {
    input.resolve()
}

#[cfg(test)]
mod tests {
    use super::{
        resolve, CallEdgeKind, CallInput, CallKind, CallQuality, CallSite, DeclaredTarget,
        ImplementsFact, TargetKind, REASON_AMBIGUOUS_TARGET, REASON_DYNAMIC_DISPATCH,
        REASON_MISSING_TARGET,
    };

    fn method(key: &str, container: &str, name: &str, kind: TargetKind) -> DeclaredTarget {
        DeclaredTarget::new(
            key,
            ["App", container, name],
            Some(container.to_string()),
            kind,
        )
    }

    #[test]
    fn a_direct_call_to_one_declared_symbol_is_exact_static() {
        let input = CallInput {
            targets: vec![method("w-run", "Widget", "Run", TargetKind::Method)],
            implements: Vec::new(),
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::Direct,
                ["App", "Widget", "Run"],
                12,
            )],
        };
        let graph = resolve(&input);
        assert_eq!(graph.unresolved, Vec::new());
        assert_eq!(graph.edges.len(), 1);
        let edge = &graph.edges[0];
        assert_eq!(edge.caller, "app-main");
        assert_eq!(edge.target, "w-run");
        assert_eq!(edge.kind, CallEdgeKind::Calls);
        assert_eq!(edge.quality, CallQuality::ExactStatic);
        assert_eq!(graph.calls_of("app-main"), vec!["w-run"]);
    }

    #[test]
    fn an_interface_call_keeps_the_interface_and_never_certifies_one_implementation() {
        let input = CallInput {
            targets: vec![
                method("i-tick", "IClock", "Tick", TargetKind::InterfaceMethod),
                method("sys-tick", "SystemClock", "Tick", TargetKind::Method),
                method("fake-tick", "FakeClock", "Tick", TargetKind::Method),
            ],
            implements: vec![
                ImplementsFact::new("SystemClock", "IClock"),
                ImplementsFact::new("FakeClock", "IClock"),
            ],
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::InterfaceMember,
                ["App", "IClock", "Tick"],
                20,
            )],
        };
        let graph = resolve(&input);
        assert_eq!(graph.unresolved, Vec::new());
        let declared: Vec<&str> = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == CallEdgeKind::Calls)
            .map(|edge| edge.target.as_str())
            .collect();
        assert_eq!(declared, vec!["i-tick"]);
        let possible: Vec<&str> = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == CallEdgeKind::PossibleImplementation)
            .map(|edge| edge.target.as_str())
            .collect();
        assert_eq!(possible, vec!["fake-tick", "sys-tick"]);
        assert!(graph
            .edges
            .iter()
            .filter(|edge| edge.kind == CallEdgeKind::PossibleImplementation)
            .all(|edge| edge.quality == CallQuality::InferredStatic));
        assert_eq!(
            graph.ambiguous_implementation_sets, 1,
            "two implementations must keep the set instead of picking one"
        );
        assert_eq!(
            graph.unproven_implementation_sets, 1,
            "runtime selection is not proven even for a declared implementation"
        );
    }

    #[test]
    fn a_single_implementation_still_records_an_ambiguous_set() {
        let input = CallInput {
            targets: vec![
                method("i-tick", "IClock", "Tick", TargetKind::InterfaceMethod),
                method("sys-tick", "SystemClock", "Tick", TargetKind::Method),
            ],
            implements: vec![ImplementsFact::new("SystemClock", "IClock")],
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::InterfaceMember,
                ["App", "IClock", "Tick"],
                20,
            )],
        };
        let graph = resolve(&input);
        assert_eq!(graph.edges.len(), 2);
        assert_eq!(graph.ambiguous_implementation_sets, 0);
        assert_eq!(graph.unproven_implementation_sets, 1);
        assert_eq!(graph.unresolved, Vec::new());
    }

    #[test]
    fn a_computed_member_is_dynamic_and_produces_no_edge() {
        let input = CallInput {
            targets: vec![method("w-run", "Widget", "Run", TargetKind::Method)],
            implements: Vec::new(),
            sites: vec![CallSite::unresolved_kind(
                "src/App.cs",
                "app-main",
                CallKind::Dynamic,
                31,
            )],
        };
        let graph = resolve(&input);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.unresolved.len(), 1);
        assert_eq!(graph.unresolved[0].reason, REASON_DYNAMIC_DISPATCH);
    }

    #[test]
    fn a_delegate_target_is_never_certified_as_a_direct_call() {
        let input = CallInput {
            targets: vec![DeclaredTarget::new(
                "handler",
                ["App", "Handler"],
                None,
                TargetKind::Delegate,
            )],
            implements: Vec::new(),
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::Direct,
                ["App", "Handler"],
                7,
            )],
        };
        let graph = resolve(&input);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.unresolved[0].reason, REASON_DYNAMIC_DISPATCH);
        assert_eq!(graph.unresolved[0].candidates, vec!["handler".to_string()]);
    }

    #[test]
    fn an_unknown_target_is_unresolved_not_guessed() {
        let input = CallInput {
            targets: vec![method("w-run", "Widget", "Run", TargetKind::Method)],
            implements: Vec::new(),
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::Direct,
                ["App", "Widget", "Stop"],
                9,
            )],
        };
        let graph = resolve(&input);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.unresolved[0].reason, REASON_MISSING_TARGET);
    }

    #[test]
    fn two_matching_declarations_are_ambiguous_and_never_pick_the_first() {
        let input = CallInput {
            targets: vec![
                method("a-run", "Widget", "Run", TargetKind::Method),
                method("b-run", "Widget", "Run", TargetKind::Method),
            ],
            implements: Vec::new(),
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::Direct,
                ["App", "Widget", "Run"],
                4,
            )],
        };
        let graph = resolve(&input);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.unresolved[0].reason, REASON_AMBIGUOUS_TARGET);
        assert_eq!(
            graph.unresolved[0].candidates,
            vec!["a-run".to_string(), "b-run".to_string()]
        );
    }

    #[test]
    fn edge_order_is_deterministic() {
        let input = CallInput {
            targets: vec![
                method("i-tick", "IClock", "Tick", TargetKind::InterfaceMethod),
                method("sys-tick", "SystemClock", "Tick", TargetKind::Method),
                method("fake-tick", "FakeClock", "Tick", TargetKind::Method),
            ],
            implements: vec![
                ImplementsFact::new("SystemClock", "IClock"),
                ImplementsFact::new("FakeClock", "IClock"),
            ],
            sites: vec![CallSite::literal(
                "src/App.cs",
                "app-main",
                CallKind::InterfaceMember,
                ["App", "IClock", "Tick"],
                20,
            )],
        };
        let first = resolve(&input);
        for _ in 0..3 {
            assert_eq!(resolve(&input), first);
        }
    }
}
