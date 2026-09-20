"""Build the AXIOM_HOME the MCP side reads: a registry naming the real project.

Separate from the graphd home (`home-e2e`) on purpose: graphd writes the lane,
MCP only reads it, and keeping the two homes apart is what makes "MCP read what
graphd published" a real boundary crossing rather than a shared variable.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil


def main() -> int:
    parser = argparse.ArgumentParser(prog="w10-make-homemcp")
    parser.add_argument("--home", required=True)
    parser.add_argument("--repo", required=True, help="graphd-bound repo root")
    parser.add_argument("--repo-id", default="agmws")
    parser.add_argument("--solution", default="agmws-license")
    parser.add_argument("--project", default="agmws-web-service")
    parser.add_argument("--project-path", required=True, help="project dir under repo root")
    parser.add_argument("--instance", default="default")
    args = parser.parse_args()

    home = pathlib.Path(args.home).resolve()
    if home.exists():
        shutil.rmtree(home)
    (home / "config").mkdir(parents=True)
    (home / "instances" / args.instance).mkdir(parents=True)

    document = {
        "schema_version": 1,
        "axiom_home": str(home),
        "instances": [{"instance_id": args.instance}],
        "solutions": [
            {
                "solution_id": args.solution,
                "instance_id": args.instance,
                "catalog_host_repo": args.repo_id,
                "repositories": [
                    {
                        "repo_id": args.repo_id,
                        "repo_root": args.repo,
                        "projects": [{"project_id": args.project}],
                    }
                ],
            }
        ],
    }
    lane_root = pathlib.Path(args.repo) / ".axiom" / "graph" / args.solution / args.project
    (home / "config" / "registry.json").write_text(
        json.dumps(document, indent=2), encoding="utf-8"
    )
    # Recording this makes a wrong --repo visible immediately instead of surfacing
    # later as "current.json is unreadable" from deep inside a query.
    print(
        json.dumps(
            {
                "home": str(home),
                "registry": str(home / "config" / "registry.json"),
                "repo_root": args.repo,
                "lane_root": str(lane_root),
                "lane_root_exists": lane_root.exists(),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
