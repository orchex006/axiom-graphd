"""Answer one relationship question with no graphd at all.

The honest 'before' baseline: a client with no stored graph must read every
source file to locate the declaration, then read the declaring file(s) again to
enumerate the type members. Pure stdlib, replayable, no graph involved.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import time


def main() -> int:
    parser = argparse.ArgumentParser(prog="w10-baseline-scan")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--symbol", required=True)
    args = parser.parse_args()

    repo = pathlib.Path(args.repo)
    leaf = args.symbol.rsplit(".", 1)[-1]

    started = time.perf_counter()
    files_scanned = 0
    declaring: list[tuple[str, int]] = []
    for path in repo.rglob("*.cs"):
        if ".axiom" in path.parts:
            continue
        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(rf"\b(class|interface|struct|enum|record)\s+{re.escape(leaf)}\b", line):
                declaring.append((str(path.relative_to(repo)).replace("\\", "/"), number))

    members: list[dict] = []
    for relative, _line in declaring:
        text = (repo / relative).read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if re.match(r"(public|internal|protected|private)\s", stripped) and "(" in stripped:
                members.append({"file": relative, "start_line": number, "signature": stripped})

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    print(
        json.dumps(
            {
                "mode": "no-graphd-text-scan",
                "symbol": args.symbol,
                "files_scanned": files_scanned,
                "declaring_files": declaring,
                "member_count": len(members),
                "members": members[:12],
                "elapsed_ms": elapsed_ms,
                "note": (
                    "untyped text hits only: no node ids, no kinds, no edges, no resolution and "
                    "no evidence of what else in the repository depends on this symbol"
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
