#!/usr/bin/env python3
"""How the no-graphd scan cost scales with repository size, measured on REAL files.

The honest 'before' leg of the bench is a full text scan per question, so its cost is
linear in the number of source files. This measures that slope on the real repository
(reading real .cs files, no synthetic content) for several prefix sizes, then derives
the break-even file count where a full scan costs the same as one warmed graph_query
MQP round trip measured in evidence/11-bench.out.
"""
import argparse, json, pathlib, re, statistics, time

def timed_scan(files, leaf):
    t0 = time.perf_counter()
    hits = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if re.search(rf"\b(class|interface|struct|enum|record)\s+{re.escape(leaf)}\b", line):
                hits += 1
                break
    return round((time.perf_counter() - t0) * 1000, 2), hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--leaf", default="LicenseRegistryRequestDto")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--graphd-per-question-ms", type=float, required=True)
    a = ap.parse_args()

    repo = pathlib.Path(a.repo)
    all_files = sorted(p for p in repo.rglob("*.cs") if ".axiom" not in p.parts)
    total = len(all_files)

    points = []
    for n in sorted({16, 32, 64, 96, 128, total}):
        if n > total:
            continue
        subset = all_files[:n]
        samples = [timed_scan(subset, a.leaf)[0] for _ in range(a.repeats)]
        points.append({"files": n, "median_ms": round(statistics.median(samples), 2),
                       "samples_ms": samples,
                       "ms_per_file": round(statistics.median(samples) / n, 4)})

    body = [p for p in points if p["files"] >= 64]
    slope = statistics.median(p["ms_per_file"] for p in body)
    break_even = round(a.graphd_per_question_ms / slope) if slope > 0 else None

    report = {
        "mode": "measured-scan-scaling-on-real-files",
        "repo": str(repo), "files_total": total, "leaf": a.leaf, "repeats": a.repeats,
        "points": points,
        "median_ms_per_file": slope,
        "graphd_per_question_ms_measured": a.graphd_per_question_ms,
        "break_even_files": break_even,
        "verdict_at_this_size": ("graphd_query round trip is at/over parity because this repo sits "
                                 "at about the break-even file count" if break_even and total <= break_even * 1.1
                                 else "see break_even_files vs files_total"),
        "is_extrapolation": True,
        "note": ("points are REAL measured scans over real files at several prefix sizes; "
                 "break_even_files is derived (graphd latency / measured slope) and is an "
                 "extrapolation, not a scan of a 170+ file tree"),
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    raise SystemExit(main())
