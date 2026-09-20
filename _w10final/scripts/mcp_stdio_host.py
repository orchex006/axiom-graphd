"""A real MCP stdio host that binds the shipped axiom-mcp tool catalog.

Why this file exists
--------------------
The shipped stdio entry point (``python -m axiom_mcp.stdio``) builds the
transport server but registers *no* tools: ``axiom_mcp.stdio.build_stdio_server``
returns a bare ``FastMCP``, and its own docstring says the tool catalog "is
registered by the query layer, not here". Grepping axiom-mcp @ cebd159 shows no
production module that assembles ``axiom_mcp.tools.catalog.TOOL_SPECS`` onto a
server, so there is no shipped binary that answers ``graph_query`` over MCP yet.

This host fills exactly that one gap and nothing else:

* the tool *names*, descriptions and capability annotations come from the
  canonical catalog ``axiom_mcp.tools.catalog.TOOL_SPECS``;
* each *handler* is the shipped ``axiom_mcp.tools.*`` function, given the
  request as a plain dict plus a ``ToolContext`` built by the shipped
  ``load_registry`` -> ``GuardedSnapshotSource`` path (no lane byte-copy);
* the *transport* is the shipped ``axiom_mcp.stdio.serve_stdio``.

What this proves and what it does not
-------------------------------------
It proves the data plane axiom-mcp ships really answers a relationship question
over a real MCP JSON-RPC session on real stdio. It does NOT prove a shipped
production entry point exists -- it does not -- and that gap is recorded as a
finding rather than papered over.
"""
from __future__ import annotations

import argparse
import functools
import sys
from pathlib import Path
from typing import Any


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="w10-mcp-stdio-host")
    parser.add_argument("--home", required=True, help="AXIOM_HOME for the session")
    parser.add_argument("--mcp-src", required=True, help="axiom-mcp/src on sys.path")
    parser.add_argument("--name", default="axiom-mcp-w10-deliverables")
    parser.add_argument("--solution", default="agmws-license")
    parser.add_argument("--instance", default="default")
    parser.add_argument("--platform", default="windows")
    parser.add_argument("--no-banner", action="store_true")
    return parser.parse_args()


ARGS = _parse_args()
sys.path.insert(0, ARGS.mcp_src)

import anyio  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

from axiom_mcp import security, stdio  # noqa: E402
from axiom_mcp.registry import load_registry  # noqa: E402
from axiom_mcp.tools import catalog, context as tool_context  # noqa: E402
from axiom_mcp.tools import query as query_tools  # noqa: E402
from axiom_mcp.tools import status as status_tools  # noqa: E402
# NOTE: aliased on purpose. The nested tool for graph_query takes a parameter
# named `query` (the search selector), which would otherwise shadow the module
# inside that function body and produce a very confusing AttributeError.

HOME = Path(ARGS.home)


def build_context() -> tool_context.ToolContext:
    """The shipped registry + guarded-source path, exactly as a host would use it."""
    registry = load_registry(
        HOME / "config" / "registry.json",
        env={"AXIOM_HOME": str(HOME)},
        platform=ARGS.platform,
    )
    principal = tool_context.ToolPrincipal(
        token_id="w10-deliverables",
        capabilities=frozenset({security.CAPABILITY_READ}),
        solution_ids=frozenset({ARGS.solution}),
        project_ids=None,
    )
    return tool_context.ToolContext(
        registry=registry,
        principal=principal,
        source=tool_context.GuardedSnapshotSource(
            HOME / "instances" / ARGS.instance / "solution.guard"
        ),
    )


def _present(values: dict[str, Any]) -> dict[str, Any]:
    """Drop unset optional selectors; a closed argument set stays closed."""
    return {key: value for key, value in values.items() if value is not None}


def build_server():
    CONTEXT = build_context()
    server = stdio.build_stdio_server(ARGS.name)
    specs = {spec.name: spec for spec in catalog.TOOL_SPECS}

    @server.tool(
        name="graph_status",
        description=specs["graph_status"].summary,
        annotations=ToolAnnotations(**specs["graph_status"].annotations()),
    )
    def graph_status(
        solution_id: str,
        project_id: str | None = None,
        project_ids: list[str] | None = None,
        lane: str | None = None,
        include_daemon: bool | None = None,
    ) -> dict:
        """Pinned generations, coverage and capabilities for one solution."""
        return status_tools.graph_status(
            _present(
                {
                    "solution_id": solution_id,
                    "project_id": project_id,
                    "project_ids": project_ids,
                    "lane": lane,
                    "include_daemon": include_daemon,
                }
            ),
            CONTEXT,
        )

    @server.tool(
        name="graph_query",
        description=specs["graph_query"].summary,
        annotations=ToolAnnotations(**specs["graph_query"].annotations()),
    )
    def graph_query(
        solution_id: str,
        operation: str,
        project_id: str | None = None,
        project_ids: list[str] | None = None,
        target: str | None = None,
        query: str | None = None,
        depth: int | None = None,
        direction: str | None = None,
        edge_kinds: list[str] | None = None,
        projection: list[str] | None = None,
        max_nodes: int | None = None,
        max_edges: int | None = None,
        max_bytes: int | None = None,
        consistency: str | None = None,
        cursor: str | None = None,
        catalog_generation_id: str | None = None,
    ) -> dict:
        """One bounded graph operation over the pinned generations."""
        return query_tools.graph_query(
            _present(
                {
                    "solution_id": solution_id,
                    "operation": operation,
                    "project_id": project_id,
                    "project_ids": project_ids,
                    "target": target,
                    "query": query,
                    "depth": depth,
                    "direction": direction,
                    "edge_kinds": edge_kinds,
                    "projection": projection,
                    "max_nodes": max_nodes,
                    "max_edges": max_edges,
                    "max_bytes": max_bytes,
                    "consistency": consistency,
                    "cursor": cursor,
                    "catalog_generation_id": catalog_generation_id,
                }
            ),
            CONTEXT,
        )

    return server


def main() -> int:
    server = build_server()
    return anyio.run(
        functools.partial(stdio.serve_stdio, server, banner=not ARGS.no_banner)
    )


if __name__ == "__main__":
    raise SystemExit(main())
