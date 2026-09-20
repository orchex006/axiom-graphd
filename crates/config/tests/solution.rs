//! H-004 acceptance tests: the registered solution document is the only source of
//! solution membership and of the L3 cross-service alias map.
//!
//! Every document below is a committed H-003 fixture from
//! `axiom-specs/tests/fixtures/solution-alias-mapping/`, embedded verbatim, so the
//! positive, negative and boundary checks run over the real registered document
//! instead of a document shaped to make a test pass. Each fixture carries its own
//! `contract_refusals` list, which is the H-003 contract's section 5 identifier
//! registry.
//!
//! * positive: a bound two-repository solution yields one claim per `projects[]`
//!   entry and resolves the alias the operator declared;
//! * negative: every configuration refusal and both resolution refusals are
//!   produced by the same reader, never by a guessed project;
//! * boundary: prefix matching stops at a `/` boundary, a repeated declaration of
//!   one project is not an ambiguity, an `explicit` link without a `route_prefix`
//!   yields no alias, an authority-only key resolves with a trailing slash and
//!   mixed case, and a document without a bindings companion keeps its logical
//!   claims.

use axiom_config::solution::{
    normalize_service_key, read_registered_solution, AliasResolution, RegisteredSolution,
    ERR_ALIAS_AMBIGUOUS_HOST, ERR_ALIAS_UNRESOLVED_HOST, ERR_BINDING_KEY_DUPLICATE,
    ERR_BINDING_KEY_UNRESOLVED, ERR_DOCUMENT_SHAPE, ERR_DUPLICATE_PROJECT_ID,
    ERR_LINK_ENDPOINT_NOT_MEMBER, ERR_NOT_PORTABLE_ALIAS, ERR_NOT_PORTABLE_ID,
    ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE, ERR_PROJECT_ROOT_ESCAPES_BINDING,
    ERR_ROUTE_PREFIX_NOT_ABSOLUTE, ERR_ROUTE_PREFIX_NOT_PORTABLE_FREE_TEXT,
    ERR_ROUTE_PREFIX_REQUIRED,
};
use graph_core::error::{AxiomError, ErrorCode};
use serde_json::{json, Value};

/// Parse one embedded fixture document.
fn fixture_json(text: &str) -> Value {
    serde_json::from_str(text).expect("embedded fixture is valid JSON")
}

/// The `solution` part of a fixture record.
fn fixture_solution(text: &str) -> Value {
    fixture_json(text)["solution"].clone()
}

/// Read one embedded fixture the way operator registration reads a solution.
fn read_fixture(text: &str) -> Result<RegisteredSolution, AxiomError> {
    let document = fixture_json(text);
    read_registered_solution(&document["solution"], document.get("bindings"))
}

/// The contract's refusal identifier the reader reported in the `rule` detail.
fn refusal(error: &AxiomError) -> String {
    error
        .details()
        .get("rule")
        .cloned()
        .unwrap_or_else(|| error.envelope().code.as_str().to_string())
}

/// Patch one pointer of a fixture solution so a refusal can be isolated.
fn patched_solution(text: &str, pointer: &str, value: Value) -> Value {
    let mut document = fixture_solution(text);
    *document
        .pointer_mut(pointer)
        .expect("fixture pointer exists") = value;
    document
}
/// `alias.authority-only-key.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_AUTHORITY_ONLY_KEY: &str = r##"{
  "case": "alias.authority-only-key.json",
  "expected_reasons": [],
  "contract_refusals": [],
  "note": "Section 3/4: the authority-only service spelling, normalised to //auth.contoso.example.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      },
      {
        "repo_id": "orders",
        "binding_key": "orders"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      },
      {
        "project_id": "orders-api",
        "repo_id": "orders",
        "path": "src/Orders.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "orders-api",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "//Auth.Contoso.Example/"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `alias.endpoint-not-member.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_ENDPOINT_NOT_MEMBER: &str = r##"{
  "case": "alias.endpoint-not-member.json",
  "expected_reasons": [
    "semantic link references an unknown project: ghost"
  ],
  "contract_refusals": [
    "link-endpoint-not-member"
  ],
  "note": "M7.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "ghost",
        "protocol": "http",
        "route_prefix": "/api/ghost"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `alias.explicit-without-route-prefix.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_EXPLICIT_WITHOUT_ROUTE_PREFIX: &str = r##"{
  "case": "alias.explicit-without-route-prefix.json",
  "expected_reasons": [],
  "contract_refusals": [],
  "note": "Section 3 coverage: explicit without route_prefix produces no alias and stays accepted.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "explicit"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `alias.route-prefix-credential-shaped.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_ROUTE_PREFIX_CREDENTIAL_SHAPED: &str = r##"{
  "case": "alias.route-prefix-credential-shaped.json",
  "expected_reasons": [
    "portable solution document contains a machine-local secret at $.semantic_links[0].route_prefix",
    "semantic link route prefix is not absolute: sk-aaaaaaaaaaaaaaaaaaaa"
  ],
  "contract_refusals": [
    "route-prefix-not-portable-free-text"
  ],
  "note": "Section 3 step 1.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "sk-aaaaaaaaaaaaaaaaaaaa"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `alias.route-prefix-machine-local.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_ROUTE_PREFIX_MACHINE_LOCAL: &str = r##"{
  "case": "alias.route-prefix-machine-local.json",
  "expected_reasons": [
    "portable solution document contains a machine-local reference at $.semantic_links[0].route_prefix: %USERPROFILE%/api",
    "semantic link route prefix is not absolute: %USERPROFILE%/api"
  ],
  "contract_refusals": [
    "route-prefix-not-portable-free-text"
  ],
  "note": "Section 3 step 1.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "%USERPROFILE%/api"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `alias.route-prefix-required.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_ROUTE_PREFIX_REQUIRED: &str = r##"{
  "case": "alias.route-prefix-required.json",
  "expected_reasons": [
    "semantic link requires a route prefix: web-app -> auth-api"
  ],
  "contract_refusals": [
    "route-prefix-required"
  ],
  "note": "Section 3 coverage.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `alias.two-projects-one-key.json` (H-003 fixture, embedded verbatim).
const FIXTURE_ALIAS_TWO_PROJECTS_ONE_KEY: &str = r##"{
  "case": "alias.two-projects-one-key.json",
  "expected_reasons": [],
  "contract_refusals": [],
  "note": "Section 4 rule 6 boundary: two accepted members claim the same alias key; resolution must refuse.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      },
      {
        "project_id": "billing-api",
        "repo_id": "auth",
        "path": "src/Billing.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      },
      {
        "source_project": "web-app",
        "target_project": "billing-api",
        "protocol": "http",
        "route_prefix": "/api/"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `membership.absolute-project-path.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_ABSOLUTE_PROJECT_PATH: &str = r##"{
  "case": "membership.absolute-project-path.json",
  "expected_reasons": [
    "project path is not a repository-relative path: /src"
  ],
  "contract_refusals": [
    "project-path-not-repository-relative"
  ],
  "note": "M5.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "/src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `membership.backslash-project-path.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_BACKSLASH_PROJECT_PATH: &str = r##"{
  "case": "membership.backslash-project-path.json",
  "expected_reasons": [
    "project path must use forward slashes: src\\web"
  ],
  "contract_refusals": [
    "project-path-not-repository-relative"
  ],
  "note": "M5.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src\\web",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `membership.binding-key-unresolved.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_BINDING_KEY_UNRESOLVED: &str = r##"{
  "case": "membership.binding-key-unresolved.json",
  "expected_reasons": [
    "solution binding key has no local binding: web"
  ],
  "contract_refusals": [
    "binding-key-unresolved"
  ],
  "note": "M4: a declared binding_key has no machine-local root.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  },
  "bindings": {
    "status": "bound",
    "solution_id": "demo-solution",
    "bindings": {
      "workspace": "/srv/checkout/workspace",
      "auth": "/srv/checkout/auth"
    }
  }
}
"##;

/// `membership.duplicate-project-id.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_DUPLICATE_PROJECT_ID: &str = r##"{
  "case": "membership.duplicate-project-id.json",
  "expected_reasons": [
    "duplicate project identity: web-app",
    "conflicting project roots: web/src"
  ],
  "contract_refusals": [],
  "note": "M2 keeps the existing frozen evaluator rule for a duplicate project identity; section 5 does not re-spell it.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `membership.escape-project-path.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_ESCAPE_PROJECT_PATH: &str = r##"{
  "case": "membership.escape-project-path.json",
  "expected_reasons": [
    "project path escapes the repository root: ../other"
  ],
  "contract_refusals": [
    "project-path-not-repository-relative"
  ],
  "note": "M5.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "../other",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  }
}
"##;

/// `membership.shared-binding-key.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_SHARED_BINDING_KEY: &str = r##"{
  "case": "membership.shared-binding-key.json",
  "expected_reasons": [],
  "contract_refusals": [
    "binding-key-duplicate"
  ],
  "note": "M3 divergence: the frozen evaluator accepts this document, this contract refuses it.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "shared"
      },
      {
        "repo_id": "web",
        "binding_key": "shared"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  },
  "bindings": {
    "status": "bound",
    "solution_id": "demo-solution",
    "bindings": {
      "workspace": "/srv/checkout/workspace",
      "shared": "/srv/checkout/shared"
    }
  }
}
"##;

/// `membership.valid-bound-two-repos.json` (H-003 fixture, embedded verbatim).
const FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS: &str = r##"{
  "case": "membership.valid-bound-two-repos.json",
  "expected_reasons": [],
  "contract_refusals": [],
  "note": "M1/M4/M6: one claim per projects[] entry, every declared binding_key resolved and contained.",
  "solution": {
    "schema_version": 2,
    "solution_id": "demo-solution",
    "profile": "default",
    "catalog_host_repo": "workspace",
    "repositories": [
      {
        "repo_id": "workspace",
        "binding_key": "workspace"
      },
      {
        "repo_id": "auth",
        "binding_key": "auth"
      },
      {
        "repo_id": "web",
        "binding_key": "web"
      }
    ],
    "projects": [
      {
        "project_id": "auth-api",
        "repo_id": "auth",
        "path": "src/Auth.Api",
        "language_profile": "csharp-dotnet",
        "depends_on": [],
        "allow_untracked": true
      },
      {
        "project_id": "web-app",
        "repo_id": "web",
        "path": "src",
        "language_profile": "typescript-angular",
        "depends_on": [
          "auth-api"
        ],
        "allow_untracked": true
      }
    ],
    "graph_output_root": ".axiom/graph",
    "ignore": [
      "**/.git/**",
      "**/node_modules/**",
      "**/.axiom/graph/**"
    ],
    "watch": {
      "debounce_ms": 750,
      "max_wait_ms": 3000,
      "inventory_interval_seconds": 300,
      "backend": "auto"
    },
    "queue": {
      "worker_limit": 4,
      "max_batch_files": 64,
      "max_batch_bytes": 16777216,
      "retry_limit": 5
    },
    "semantic_links": [
      {
        "source_project": "web-app",
        "target_project": "auth-api",
        "protocol": "http",
        "route_prefix": "/api/auth"
      }
    ],
    "workspace_layout": 2
  },
  "bindings": {
    "status": "bound",
    "solution_id": "demo-solution",
    "bindings": {
      "workspace": "/srv/checkout/workspace",
      "auth": "/srv/checkout/auth",
      "web": "/srv/checkout/web"
    }
  }
}
"##;

#[test]
fn a_bound_two_repository_solution_yields_one_claim_per_project() {
    let registered =
        read_fixture(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS).expect("the fixture is accepted");
    assert_eq!(registered.solution_id(), "demo-solution");

    let claims = registered.claims();
    assert_eq!(claims.len(), 2, "one claim per projects[] entry");
    assert_eq!(claims[0].project_id(), "auth-api");
    assert_eq!(claims[0].repo_id(), "auth");
    assert_eq!(claims[0].binding_key(), "auth");
    assert_eq!(claims[0].path(), "src/Auth.Api");
    assert_eq!(
        claims[0].absolute_root(),
        Some("/srv/checkout/auth/src/Auth.Api")
    );
    assert_eq!(claims[0].language_profile(), Some("csharp-dotnet"));
    assert_eq!(claims[1].project_id(), "web-app");
    assert_eq!(claims[1].repo_id(), "web");
    assert_eq!(claims[1].absolute_root(), Some("/srv/checkout/web/src"));

    assert!(registered.is_member("auth-api"));
    assert!(!registered.is_member("ghost"));
    assert!(registered.claim_for("ghost").is_none());

    let aliases = registered.aliases();
    assert_eq!(
        aliases.len(),
        1,
        "one alias per link that carries a route prefix"
    );
    assert_eq!(aliases[0].alias_key(), "/api/auth");
    assert_eq!(aliases[0].project(), "auth-api");
    assert_eq!(aliases[0].protocol(), "http");

    assert_eq!(
        registered.resolve("http", "/api/auth"),
        AliasResolution::Resolved("auth-api")
    );
    assert_eq!(
        registered.resolve("http", "/api/auth/users"),
        AliasResolution::Resolved("auth-api")
    );
    assert_eq!(
        registered
            .resolve_or_refuse("http", "/api/auth/users")
            .expect("the operator-declared alias resolves"),
        "auth-api"
    );
}

#[test]
fn every_registry_refusal_comes_from_the_registered_document() {
    let refused = [
        (
            FIXTURE_MEMBERSHIP_SHARED_BINDING_KEY,
            ERR_BINDING_KEY_DUPLICATE,
        ),
        (
            FIXTURE_MEMBERSHIP_BINDING_KEY_UNRESOLVED,
            ERR_BINDING_KEY_UNRESOLVED,
        ),
        (
            FIXTURE_MEMBERSHIP_ABSOLUTE_PROJECT_PATH,
            ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE,
        ),
        (
            FIXTURE_MEMBERSHIP_BACKSLASH_PROJECT_PATH,
            ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE,
        ),
        (
            FIXTURE_MEMBERSHIP_ESCAPE_PROJECT_PATH,
            ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE,
        ),
        (
            FIXTURE_ALIAS_ENDPOINT_NOT_MEMBER,
            ERR_LINK_ENDPOINT_NOT_MEMBER,
        ),
        (
            FIXTURE_ALIAS_ROUTE_PREFIX_REQUIRED,
            ERR_ROUTE_PREFIX_REQUIRED,
        ),
        (
            FIXTURE_ALIAS_ROUTE_PREFIX_MACHINE_LOCAL,
            ERR_ROUTE_PREFIX_NOT_PORTABLE_FREE_TEXT,
        ),
        (
            FIXTURE_ALIAS_ROUTE_PREFIX_CREDENTIAL_SHAPED,
            ERR_ROUTE_PREFIX_NOT_PORTABLE_FREE_TEXT,
        ),
    ];
    for (document, expected) in refused {
        let error = read_fixture(document).expect_err("the fixture is refused");
        assert_eq!(
            refusal(&error),
            expected,
            "{expected} must be reported with the contract's spelling"
        );
    }

    for document in [
        FIXTURE_ALIAS_AUTHORITY_ONLY_KEY,
        FIXTURE_ALIAS_EXPLICIT_WITHOUT_ROUTE_PREFIX,
        FIXTURE_ALIAS_TWO_PROJECTS_ONE_KEY,
    ] {
        assert!(read_fixture(document).is_ok(), "the contract accepts it");
    }
}

#[test]
fn names_frozen_by_the_evaluator_keep_their_existing_spelling() {
    let error = read_fixture(FIXTURE_MEMBERSHIP_DUPLICATE_PROJECT_ID).expect_err("duplicate id");
    assert_eq!(refusal(&error), ERR_DUPLICATE_PROJECT_ID);
    assert_eq!(error.code(), ErrorCode::Conflict);

    let document = patched_solution(
        FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS,
        "/projects/0/project_id",
        json!("Auth-Api"),
    );
    let error = read_registered_solution(&document, None).expect_err("a non-portable project id");
    assert_eq!(refusal(&error), ERR_NOT_PORTABLE_ID);

    let document = patched_solution(
        FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS,
        "/repositories/1/binding_key",
        json!("Shared"),
    );
    let error = read_registered_solution(&document, None).expect_err("a non-portable alias");
    assert_eq!(refusal(&error), ERR_NOT_PORTABLE_ALIAS);

    let document = patched_solution(
        FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS,
        "/semantic_links/0/route_prefix",
        json!("api/auth"),
    );
    let error = read_registered_solution(&document, None).expect_err("a relative route prefix");
    assert_eq!(refusal(&error), ERR_ROUTE_PREFIX_NOT_ABSOLUTE);

    // A protocol that may omit the field, carrying a present but unusable value:
    // the declaration is reported, never silently dropped.
    let mut document = fixture_solution(FIXTURE_ALIAS_EXPLICIT_WITHOUT_ROUTE_PREFIX);
    document["semantic_links"][0]["route_prefix"] = json!("");
    let error = read_registered_solution(&document, None).expect_err("an empty route prefix");
    assert_eq!(refusal(&error), ERR_ROUTE_PREFIX_NOT_ABSOLUTE);

    // An `http` link carrying the empty spelling is the missing-route rule.
    let document = patched_solution(
        FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS,
        "/semantic_links/0/route_prefix",
        json!(""),
    );
    let error = read_registered_solution(&document, None).expect_err("no route prefix");
    assert_eq!(refusal(&error), ERR_ROUTE_PREFIX_REQUIRED);
}

#[test]
fn resolution_refusals_are_explicit_and_never_guess_a_project() {
    let ambiguous = read_fixture(FIXTURE_ALIAS_TWO_PROJECTS_ONE_KEY).expect("accepted");
    assert_eq!(
        ambiguous.resolve("http", "/api/auth"),
        AliasResolution::Ambiguous
    );
    assert_eq!(
        AliasResolution::Ambiguous.reason(),
        Some(ERR_ALIAS_AMBIGUOUS_HOST)
    );
    let error = ambiguous
        .resolve_or_refuse("http", "/api/auth")
        .expect_err("one address, two projects");
    assert_eq!(error.code(), ErrorCode::Conflict);
    assert_eq!(refusal(&error), ERR_ALIAS_AMBIGUOUS_HOST);
    assert_eq!(
        ambiguous.resolve("http", "/api/other"),
        AliasResolution::Resolved("billing-api")
    );

    let plain = read_fixture(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS).expect("accepted");
    assert_eq!(
        plain.resolve("http", "/api/other"),
        AliasResolution::Unresolved
    );
    assert_eq!(
        AliasResolution::Unresolved.reason(),
        Some(ERR_ALIAS_UNRESOLVED_HOST)
    );
    let error = plain
        .resolve_or_refuse("http", "/api/other")
        .expect_err("no declared alias matches");
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert_eq!(refusal(&error), ERR_ALIAS_UNRESOLVED_HOST);
}

#[test]
fn resolution_boundaries_follow_the_contract_order() {
    let plain = read_fixture(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS).expect("accepted");
    assert_eq!(
        plain.resolve("http", "/api/auth"),
        AliasResolution::Resolved("auth-api")
    );
    assert_eq!(plain.resolve("http", "/apix"), AliasResolution::Unresolved);
    assert_eq!(plain.resolve("http", "/api"), AliasResolution::Unresolved);
    assert_eq!(
        plain.resolve("sql", "/api/auth"),
        AliasResolution::Unresolved
    );
    assert_eq!(
        plain.resolve("message", "/api/auth"),
        AliasResolution::Unresolved
    );
    assert_eq!(
        plain.resolve("explicit", "/api/auth"),
        AliasResolution::Unresolved
    );

    let authority = read_fixture(FIXTURE_ALIAS_AUTHORITY_ONLY_KEY).expect("accepted");
    assert_eq!(
        authority.resolve("http", "//AUTH.contoso.EXAMPLE/orders"),
        AliasResolution::Resolved("auth-api")
    );
    assert_eq!(
        authority.resolve("http", "//Auth.Contoso.Example/"),
        AliasResolution::Resolved("auth-api")
    );
    assert_eq!(
        authority.resolve("http", "//unknown.example"),
        AliasResolution::Unresolved
    );
    assert_eq!(
        normalize_service_key("//Orders.Contoso.Example/"),
        "//orders.contoso.example"
    );

    let explicit = read_fixture(FIXTURE_ALIAS_EXPLICIT_WITHOUT_ROUTE_PREFIX).expect("accepted");
    assert!(explicit.aliases().is_empty());
    assert_eq!(
        explicit.resolve("explicit", "/api/auth"),
        AliasResolution::Unresolved
    );

    let mut repeated = fixture_solution(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS);
    repeated["semantic_links"] = json!([
        {"source_project": "web-app", "target_project": "auth-api", "protocol": "http", "route_prefix": "/api/auth"},
        {"source_project": "web-app", "target_project": "auth-api", "protocol": "http", "route_prefix": "/api/"}
    ]);
    let repeated = read_registered_solution(&repeated, None).expect("accepted");
    assert_eq!(
        repeated.resolve("http", "/api/auth/users"),
        AliasResolution::Resolved("auth-api"),
        "a repeated declaration of one project is not an ambiguity"
    );
}

#[test]
fn the_l3_alias_map_is_derived_from_the_registered_document() {
    let authority = read_fixture(FIXTURE_ALIAS_AUTHORITY_ONLY_KEY).expect("accepted");
    let declared = fixture_solution(FIXTURE_ALIAS_AUTHORITY_ONLY_KEY);
    assert_eq!(
        declared["semantic_links"][0]["target_project"],
        json!("auth-api")
    );
    assert_eq!(authority.aliases().len(), 1);
    assert_eq!(authority.aliases()[0].alias_key(), "//auth.contoso.example");
    assert_eq!(
        authority.l3_aliases(),
        vec![("auth.contoso.example".to_string(), "auth-api".to_string())],
        "the host pair is the one the registered document declares"
    );

    let route_only = read_fixture(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS).expect("accepted");
    assert_eq!(route_only.aliases().len(), 1);
    assert!(
        route_only.l3_aliases().is_empty(),
        "a route-only key names no authority and the join must not invent one"
    );
}

#[test]
fn a_document_without_a_bindings_companion_keeps_its_logical_claims() {
    let document = fixture_solution(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS);
    let registered = read_registered_solution(&document, None).expect("alias-only reading");
    assert_eq!(registered.claims().len(), 2);
    assert!(registered
        .claims()
        .iter()
        .all(|claim| claim.absolute_root().is_none()));
    assert_eq!(registered.aliases().len(), 1);

    let bound = read_fixture(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS).expect("accepted");
    assert_eq!(
        bound.claims()[1].absolute_root(),
        Some("/srv/checkout/web/src")
    );
}

#[test]
fn the_binding_coverage_and_containment_boundaries_are_enforced() {
    let solution = fixture_solution(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS);

    let mut bindings = fixture_json(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS)["bindings"].clone();
    bindings["bindings"]["web"] = json!("/srv/checkout/web/..");
    let error = read_registered_solution(&solution, Some(&bindings)).expect_err("an escaping root");
    assert_eq!(refusal(&error), ERR_PROJECT_ROOT_ESCAPES_BINDING);

    let mut bindings = fixture_json(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS)["bindings"].clone();
    bindings["bindings"]["shared"] = json!("/srv/checkout/shared");
    let error =
        read_registered_solution(&solution, Some(&bindings)).expect_err("an undeclared key");
    assert_eq!(refusal(&error), ERR_BINDING_KEY_UNRESOLVED);

    let error = read_registered_solution(&json!({"schema_version": 2, "projects": []}), None)
        .expect_err("a document missing a required field");
    assert_eq!(refusal(&error), ERR_DOCUMENT_SHAPE);
}

#[test]
fn a_claim_set_that_fails_the_rules_returns_no_registered_solution() {
    let document = patched_solution(
        FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS,
        "/projects/1/path",
        json!("../other"),
    );
    let error = read_registered_solution(&document, None).expect_err("the second claim is refused");
    assert_eq!(refusal(&error), ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE);
    assert!(
        read_fixture(FIXTURE_MEMBERSHIP_VALID_BOUND_TWO_REPOS).is_ok(),
        "the refusal was the claim, not the document"
    );
}
