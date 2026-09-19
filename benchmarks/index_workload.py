#!/usr/bin/env python3
"""Initial and incremental graph-work benchmark (task F-030).

`axiom-specs/docs/26-PERFORMANCE-AND-TOKEN-EVALUATION.md` defines the workload
tiers, the measures and - most importantly - the rule this harness exists to
obey: *there is no benchmark runtime in the specification package; every number
there is a design budget or an acceptance target that has to be measured on
reference hardware and a recorded dataset, and no target may be claimed without
measured data.*

This harness therefore does two things and refuses to do a third:

1. it BUILDS a real dataset on disk - real files, real bytes, at one of the
   three recorded tiers - and runs a real cold pass and a series of real
   incremental passes over it, measuring wall time, process CPU time, peak
   resident set size, files read, bytes read, symbol and edge counts and the
   size of the published index;
2. it CHECKS the incremental result against a full rebuild of the same bytes,
   so a fast incremental answer that is wrong fails here instead of looking
   good;
3. it does NOT claim any specification target. Every budget the specification
   names is printed as `claimed: false`, and a target that names a measure this
   host did not take is reported `not_run` with the reproducible command
   rather than asserted.

What is real here: the dataset, the bytes, the reads, the hashes, the wall
clock, the CPU time, the peak RSS, the file counts, the edge counts, the
closure sizes and the published artifact bytes. What is modelled: the
*indexer*. The production cold/incremental index is Rust
(`graph-analyze`/`graph-export`); this harness cannot link a Rust crate, so it
runs a deterministic Python indexer over the same kind of input and reports the
Rust measurement as `not_run` with the exact command a later lane can run.

Negative and boundary legs (AC2), each of which must be caught:

* an incremental pass that skips a changed file must be detected - the harness
  runs a deliberately stale incremental pass and requires the
  `incremental == full rebuild` oracle to reject it;
* a same-size, restored-mtime rewrite must still be noticed, which is only true
  for a content-digest cache, not an mtime-only cache;
* a symbol that does not exist must have an empty closure and must not raise;
* an empty dataset must index to an empty graph without crashing.

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import time

# --- workload tiers (axiom-specs/docs/26-PERFORMANCE-AND-TOKEN-EVALUATION.md) --
#
# Small: 3 projects / 2,000 source files. Medium: 10 projects / 10,000 files.
# Large-V2: 30 projects / 50,000 files. The generator below reproduces the
# recorded shape; the actual counts and bytes are measured and reported, never
# assumed.
TIERS = {
    "small": {"projects": 3, "files_per_project": 667},
    "medium": {"projects": 10, "files_per_project": 1000},
    "large": {"projects": 30, "files_per_project": 1667},
}

DEFAULT_TIER = "small"

# The prototype budgets the specification records. They are design budgets, not
# claims, and this harness never marks one as met.
DESIGN_TARGETS = [
    {
        "id": "warm-bounded-query-p95",
        "target": "warm bounded query p95 < 250 ms in the small tier",
        "needs": "the real daemon query path",
        "reproduce": "cargo test -p axiom-graphd --locked",
    },
    {
        "id": "no-edit-daemon-cpu",
        "target": "no-edit daemon CPU < 1% of one logical core on average",
        "needs": "the real running daemon",
        "reproduce": "cargo run -p axiom-graphd -- serve --json",
    },
    {
        "id": "cold-index",
        "target": "the real cold-index wall time, CPU peak and RSS for this tier",
        "needs": "the real Rust indexer (graph-analyze / graph-export)",
        "reproduce": "cargo test -p graph-analyze --locked",
    },
]

SYMBOL_RE = re.compile(r"^pub fn ([a-z0-9_]+)\(", re.MULTILINE)


def peak_rss_bytes():
    """Peak resident set size of this process, or None when the host has none.

    POSIX hosts answer from `resource`; Windows has no such module, so the peak
    working set is read from `psapi`/`kernel32` through `ctypes`, which is
    standard library on every CPython build. A host that exposes neither returns
    None and the memory measure is reported `not_run` rather than guessed.
    """
    try:
        import resource  # type: ignore[import-not-found]
    except ImportError:
        resource = None
    if resource is not None:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if platform.system().lower() == "darwin":
            return int(usage)
        return int(usage) * 1024
    try:
        import ctypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32")
        # The current-process pseudo handle is (HANDLE)-1, which is not an int:
        # without these prototypes ctypes truncates it and every call fails.
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        handle = kernel32.GetCurrentProcess()
        for library, entry in (
            ("psapi", "GetProcessMemoryInfo"),
            ("kernel32", "K32GetProcessMemoryInfo"),
        ):
            try:
                call = getattr(ctypes.WinDLL(library), entry)
            except (AttributeError, OSError):
                continue
            call.restype = ctypes.c_int
            call.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            if call(handle, ctypes.byref(counters), ctypes.sizeof(counters)):
                return int(counters.PeakWorkingSetSize)
        return None
    except Exception:  # pragma: no cover - a host with none of the three
        return None


def host_description():
    return {
        "platform": platform.platform(),
        "system": platform.system().lower(),
        "machine": platform.machine().lower(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "filesystem": os.path.abspath(os.sep),
    }


# --- deterministic dataset ---------------------------------------------------


def module_name(project, index):
    """Stable symbol prefix for one module of one project."""
    return "p%02d_m%04d" % (project, index)


def source_text(project, index):
    """One module of real, parseable Rust-shaped source text."""
    name = module_name(project, index)
    lines = ["// project %d module %d" % (project, index), ""]
    lines.append("pub fn %s_fn00(x: u32) -> u32 { x + %d }" % (name, index + 1))
    lines.append("pub fn %s_fn01(x: u32) -> u32 { %s_fn00(x) + 2 }" % (name, name))
    lines.append("pub fn %s_fn02(x: u32) -> u32 { %s_fn01(x) + 3 }" % (name, name))
    if index > 0:
        previous = module_name(project, index - 1)
        lines.append(
            "pub fn %s_export(x: u32) -> u32 { %s_fn02(x) + %s_fn01(x) + %s_export(x) }"
            % (name, name, previous, previous)
        )
    else:
        lines.append("pub fn %s_export(x: u32) -> u32 { %s_fn02(x) + 1 }" % (name, name))
    lines.append("")
    return "\n".join(lines)


def write_dataset(root, projects, files_per_project):
    """Create the dataset and return (files, expected symbols, expected edges).

    The expectation is built from the generator's intent, not from the text, so
    the extraction in `GraphIndex` is checked against something it did not
    produce itself. Both are up to their boundaries: a generator bug shows up as
    an extraction mismatch rather than hiding.
    """
    files = []
    symbols = set()
    edges = set()
    for project in range(projects):
        project_dir = os.path.join(root, "project%02d" % project)
        source_dir = os.path.join(project_dir, "src")
        os.makedirs(source_dir, exist_ok=True)
        for index in range(files_per_project):
            name = module_name(project, index)
            path = os.path.join(source_dir, name + ".rs")
            with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(source_text(project, index))
            files.append(path)
            for leg in range(3):
                symbols.add("%s_fn%02d" % (name, leg))
            symbols.add("%s_export" % name)
            edges.add(("%s_fn01" % name, "%s_fn00" % name))
            edges.add(("%s_fn02" % name, "%s_fn01" % name))
            edges.add(("%s_export" % name, "%s_fn02" % name))
            if index > 0:
                previous = module_name(project, index - 1)
                edges.add(("%s_export" % name, "%s_fn01" % previous))
                edges.add(("%s_export" % name, "%s_export" % previous))
    return files, symbols, edges


# --- the indexer -------------------------------------------------------------
#
# The production index is Rust; this is the Python stand-in that makes the
# workload measurable here. Its fast path is content-addressed on purpose: the
# warm pass still reads and hashes every file and only skips the parse, so a
# rewrite that restores the size and the mtime is still observed. An mtime-only
# fast path would pass a cost review and fail the boundary leg below.

CALL_RE = re.compile(r"\b([a-z][a-z0-9_]{3,})\s*\(")


class GraphIndex:
    """Symbol table plus caller edges over a set of source files."""

    def __init__(self):
        self.digests = {}      # path -> sha256
        self.symbols = {}      # path -> [definition names]
        self.raw_calls = {}    # path -> {caller: [names called in that body]}
        self.edges = {}        # path -> [callee names reachable from that file]
        self.callees = {}      # caller symbol -> [callee symbols]
        self.symbol_file = {}  # symbol -> path

    # -- reading ------------------------------------------------------------

    def _digest(self, path):
        digest = hashlib.sha256()
        total = 0
        with io.open(path, "rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
        return digest.hexdigest(), total

    def _parse(self, text):
        """Return (definitions, {caller: [callee names]}) for one file's text.

        A definition site is not a call site, and a callee belongs to the
        definition whose body it appears in. Both matter: the first keeps a
        one-line function from looking like it calls itself, and the second
        keeps every function in a file from inheriting every call in that file,
        which would let a wrong index satisfy the edge oracle in `run()`.
        """
        placed = [(match.start(1), match.group(1)) for match in SYMBOL_RE.finditer(text)]
        definitions = [name for _, name in placed]
        spans = []
        for offset, name in placed:
            spans.append((text.rfind("\n", 0, offset) + 1, offset, name))
        calls = {}
        for position, (start, own_offset, name) in enumerate(spans):
            end = spans[position + 1][0] if position + 1 < len(spans) else len(text)
            body = text[start:end]
            own = own_offset - start
            found = set()
            for match in CALL_RE.finditer(body):
                if match.start() == own:
                    continue
                found.add(match.group(1))
            calls[name] = sorted(found)
        return definitions, calls

    def scan(self, files, stale_paths=()):
        """One incremental pass. Returns the per-pass facts this harness reports.

        `stale_paths` deliberately pretends a changed file did not change. It is
        only used by the negative leg, to prove the incremental-vs-rebuild
        oracle has teeth.
        """
        stale = set(stale_paths)
        facts = {
            "files_read": 0,
            "bytes_read": 0,
            "files_hashed": 0,
            "files_parsed": 0,
            "files_skipped_stale": 0,
            "dirty_files": [],
        }
        seen = set()
        for path in files:
            seen.add(path)
            if path in stale:
                facts["files_skipped_stale"] += 1
                continue
            digest, size = self._digest(path)
            facts["files_read"] += 1
            facts["bytes_read"] += size
            facts["files_hashed"] += 1
            if self.digests.get(path) == digest:
                continue
            with io.open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            definitions, calls = self._parse(text)
            self.digests[path] = digest
            self.symbols[path] = definitions
            self.raw_calls[path] = calls
            facts["files_parsed"] += 1
            facts["dirty_files"].append(path)
        removed = [path for path in list(self.digests) if path not in seen]
        for path in removed:
            self.digests.pop(path, None)
            self.symbols.pop(path, None)
            self.raw_calls.pop(path, None)
        facts["files_removed"] = len(removed)
        self._resolve()
        return facts

    def _resolve(self):
        """Turn per-file call names into the symbol table and the edge set."""
        self.symbol_file = {}
        for path in sorted(self.symbols):
            for name in self.symbols[path]:
                self.symbol_file[name] = path
        known = set(self.symbol_file)
        self.callees = {}
        self.edges = {}
        for path in sorted(self.raw_calls):
            reachable = set()
            for caller, names in self.raw_calls[path].items():
                resolved = sorted(name for name in set(names) if name in known and name != caller)
                self.callees[caller] = resolved
                reachable.update(resolved)
            self.edges[path] = sorted(reachable)

    # -- reporting ----------------------------------------------------------

    def symbol_count(self):
        return len(self.symbol_file)

    def edge_set(self):
        edges = set()
        for caller, callees in self.callees.items():
            for callee in callees:
                if callee != caller:
                    edges.add((caller, callee))
        return edges

    def closure(self, target):
        """Symbols reachable from `target` through call edges, plus their bytes."""
        if target not in self.symbol_file:
            return {"target": target, "found": False, "nodes": 0, "bytes": 0, "symbols": []}
        reached = []
        seen = {target}
        queue = [target]
        while queue:
            current = queue.pop(0)
            for callee in self.callees.get(current, ()):
                if callee in seen:
                    continue
                seen.add(callee)
                reached.append(callee)
                queue.append(callee)
        paths = sorted({self.symbol_file[name] for name in [target] + reached})
        total = 0
        for path in paths:
            try:
                total += os.path.getsize(path)
            except OSError:
                continue
        return {
            "target": target,
            "found": True,
            "nodes": len(reached) + 1,
            "bytes": total,
            "symbols": sorted([target] + reached),
        }

    def publish(self):
        """Canonical index artifact bytes, one record per project bucket."""
        buckets = {}
        for path in sorted(self.symbols):
            parts = os.path.normpath(path).split(os.sep)
            bucket = parts[-3] if len(parts) >= 3 else "root"
            buckets.setdefault(bucket, []).append(
                {
                    "file": parts[-1],
                    "symbols": sorted(self.symbols.get(path, ())),
                    "calls": sorted(self.edges.get(path, ())),
                }
            )
        records = {}
        for bucket, items in buckets.items():
            items.sort(key=lambda item: item["file"])
            records[bucket] = canonical_json(items)
        return records

# --- canonical artifact bytes -------------------------------------------------


def canonical_json(value):
    """Canonical JSON, byte-for-byte stable across passes and across hosts."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


# --- measurement --------------------------------------------------------------


def measure(function, *args, **kwargs):
    """Run a pass and return (result, wall seconds, CPU seconds)."""
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    outcome = function(*args, **kwargs)
    return outcome, time.perf_counter() - wall_start, time.process_time() - cpu_start


def graph_state(index):
    """Everything comparable about an index: symbols, edges, artifact bytes."""
    return {
        "digests": sorted("%s:%s" % (path, digest) for path, digest in index.digests.items()),
        "symbols": sorted(index.symbol_file),
        "edges": sorted("%s->%s" % (caller, callee) for caller, callee in index.edge_set()),
        "publish": index.publish(),
    }


def fresh_index(files):
    """A cold index over the given files: the oracle side of every pass."""
    index = GraphIndex()
    index.scan(files)
    return index


def pass_facts(facts, wall, cpu, index):
    return {
        "wall_seconds": round(wall, 6),
        "cpu_seconds": round(cpu, 6),
        "files_read": facts["files_read"],
        "bytes_read": facts["bytes_read"],
        "files_hashed": facts["files_hashed"],
        "files_parsed": facts["files_parsed"],
        "files_skipped_stale": facts["files_skipped_stale"],
        "files_removed": facts["files_removed"],
        "dirty_files": len(facts["dirty_files"]),
        "symbols": index.symbol_count(),
        "edges": len(index.edge_set()),
    }


def append_salt(path, salt):
    """Append one comment line: a real, same-shape edit to a real file."""
    with io.open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("// %s\n" % salt)


def append_definition(path):
    """Append one real function definition, so the symbol table must change."""
    name = os.path.basename(path)[:-3]
    with io.open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("\npub fn %s_fn03(x: u32) -> u32 { %s_fn00(x) }\n" % (name, name))


def project_bytes(files, bucket):
    marker = os.sep + bucket + os.sep
    return sum(os.path.getsize(path) for path in files if marker in path)


# --- the workload -------------------------------------------------------------


def run(tier, projects, files_per_project, keep=False):
    problems = []
    not_run = []
    record = {
        "task": "F-030",
        "harness": "index_workload",
        "tier": tier,
        "host": host_description(),
        "indexer": "python stand-in for the Rust graph-analyze / graph-export index",
    }

    shard = tempfile.mkdtemp(prefix="axiom-f030-")
    try:
        root = os.path.join(shard, "dataset")
        write_start = time.perf_counter()
        files, expected_symbols, expected_edges = write_dataset(root, projects, files_per_project)
        write_seconds = time.perf_counter() - write_start
        total_bytes = sum(os.path.getsize(path) for path in files)
        record["dataset"] = {
            "projects": projects,
            "files_per_project": files_per_project,
            "files": len(files),
            "bytes": total_bytes,
            "generation_seconds": round(write_seconds, 6),
            "root": root if keep else "temporary tree, removed when this harness exits",
        }

        # --- cold pass -------------------------------------------------------
        index = GraphIndex()
        cold_facts, cold_wall, cold_cpu = measure(index.scan, files)
        record["cold"] = pass_facts(cold_facts, cold_wall, cold_cpu, index)
        record["cold"]["peak_rss_bytes"] = peak_rss_bytes()
        if record["cold"]["peak_rss_bytes"] is None:
            not_run.append("peak resident set size (this host exposes no rusage or psapi counter)")
        if cold_facts["files_parsed"] != len(files):
            problems.append("cold pass parsed %d of %d files" % (cold_facts["files_parsed"], len(files)))
        extracted = set(index.symbol_file)
        if extracted != expected_symbols:
            problems.append(
                "cold symbol extraction diverged: missing=%d unexpected=%d"
                % (len(expected_symbols - extracted), len(extracted - expected_symbols))
            )
        extracted_edges = index.edge_set()
        if extracted_edges != expected_edges:
            problems.append(
                "cold edge extraction diverged: missing=%d unexpected=%d"
                % (len(expected_edges - extracted_edges), len(extracted_edges - expected_edges))
            )
        published = index.publish()
        record["artifact"] = {
            "buckets": len(published),
            "bytes": sum(len(blob.encode("utf-8")) for blob in published.values()),
            "sha256": hashlib.sha256(
                "".join(published[key] for key in sorted(published)).encode("utf-8")
            ).hexdigest(),
        }
        cold_state = graph_state(index)

        # --- closure size ----------------------------------------------------
        if files_per_project > 0 and projects > 0:
            target = "%s_export" % module_name(0, files_per_project - 1)
            closure = index.closure(target)
            expected_nodes = 4 * files_per_project
            expected_bytes = project_bytes(files, "project00")
            record["closure"] = {
                "target": target,
                "nodes": closure["nodes"],
                "expected_nodes": expected_nodes,
                "bytes": closure["bytes"],
                "expected_bytes": expected_bytes,
            }
            if closure["nodes"] != expected_nodes:
                problems.append(
                    "closure from %s reached %d symbols, expected %d"
                    % (target, closure["nodes"], expected_nodes)
                )
            if closure["bytes"] != expected_bytes:
                problems.append(
                    "closure bytes from %s was %d, expected %d"
                    % (target, closure["bytes"], expected_bytes)
                )
        else:
            record["closure"] = {"target": None, "nodes": 0, "bytes": 0}
            not_run.append("closure size on an empty dataset (no symbol exists to close over)")

        # --- warm no-op pass -------------------------------------------------
        warm_facts, warm_wall, warm_cpu = measure(index.scan, files)
        record["warm"] = pass_facts(warm_facts, warm_wall, warm_cpu, index)
        if warm_facts["files_parsed"] != 0:
            problems.append("warm no-op pass reparsed %d unchanged files" % warm_facts["files_parsed"])
        if warm_facts["files_hashed"] != len(files):
            problems.append("warm pass hashed %d of %d files" % (warm_facts["files_hashed"], len(files)))
        if warm_facts["files_removed"] != 0:
            problems.append("warm no-op pass reported %d removals" % warm_facts["files_removed"])
        if graph_state(index) != cold_state:
            problems.append("warm no-op pass changed the graph")

        if not files:
            # Nothing else in this workload is meaningful without a dataset.
            record["negative_empty_dataset"] = {
                "held": index.symbol_count() == 0 and index.publish() == {},
                "symbols": index.symbol_count(),
                "detail": "an empty dataset indexed to an empty graph without raising",
            }
            record["incremental_single_edit"] = {"wall_seconds": None}
            record["incremental_burst"] = {"wall_seconds": None, "edited_files": 0}
            if index.symbol_count() != 0 or index.publish() != {}:
                problems.append("an empty dataset did not index to an empty graph")
            record["design_targets"] = _design_targets(not_run)
            record["not_run"] = not_run
            record["problems"] = problems
            record["ok"] = not problems
            return record, problems, not_run

        # --- incremental: one body edit --------------------------------------
        single_target = files[-1]
        append_salt(single_target, "single-edit")
        single_facts, single_wall, single_cpu = measure(index.scan, files)
        record["incremental_single_edit"] = pass_facts(single_facts, single_wall, single_cpu, index)
        if single_facts["files_parsed"] != 1:
            problems.append("a one-file edit reparsed %d files" % single_facts["files_parsed"])
        if graph_state(index) != graph_state(fresh_index(files)):
            problems.append("incremental index after one edit != full rebuild")

        # --- incremental: burst save of up to 100 files ----------------------
        burst = files[: min(100, len(files))]
        for path in burst:
            append_salt(path, "burst-save")
        burst_facts, burst_wall, burst_cpu = measure(index.scan, files)
        record["incremental_burst"] = pass_facts(burst_facts, burst_wall, burst_cpu, index)
        record["incremental_burst"]["edited_files"] = len(burst)
        if burst_facts["files_parsed"] != len(burst):
            problems.append("a burst of %d files reparsed %d" % (len(burst), burst_facts["files_parsed"]))
        if graph_state(index) != graph_state(fresh_index(files)):
            problems.append("incremental index after a burst != full rebuild")

        # The deletion and both incremental negative legs each need their own
        # file, so a dataset too small for that reports them not_run instead of
        # quietly reusing one file for two different faults.
        if len(files) >= 3:
            removed_path = files[1]
            live = [path for path in files if path != removed_path]
            touch_path = files[0]
            stale_path = files[2]

            # --- incremental: a deleted file ---------------------------------
            os.remove(removed_path)
            removal_facts, removal_wall, removal_cpu = measure(index.scan, live)
            record["incremental_removal"] = pass_facts(removal_facts, removal_wall, removal_cpu, index)
            if removal_facts["files_removed"] != 1:
                problems.append("a deleted file produced %d removals" % removal_facts["files_removed"])
            gone = "%s_fn00" % os.path.basename(removed_path)[:-3]
            if gone in index.symbol_file:
                problems.append("symbol %s survived the deletion of its file" % gone)
            if graph_state(index) != graph_state(fresh_index(live)):
                problems.append("incremental index after a deletion != full rebuild")

            # --- negative 1: a stale incremental pass must be caught --------
            append_definition(stale_path)
            stale_facts, _, _ = measure(index.scan, live, [stale_path])
            stale_caught = graph_state(index) != graph_state(fresh_index(live))
            record["negative_stale_incremental_pass"] = {
                "rejected": stale_caught,
                "files_skipped_stale": stale_facts["files_skipped_stale"],
                "detail": "a pass told a changed file was unchanged must not equal a rebuild",
            }
            if stale_facts["files_skipped_stale"] != 1:
                problems.append("the stale leg skipped %d files" % stale_facts["files_skipped_stale"])
            if not stale_caught:
                problems.append("a deliberately stale incremental pass matched a full rebuild")

            # --- negative 2: same-size rewrite with the mtime restored ------
            touch_name = os.path.basename(touch_path)[:-3]
            before_stat = os.stat(touch_path)
            before_size = os.path.getsize(touch_path)
            text = io.open(touch_path, encoding="utf-8").read()
            old_line = "pub fn %s_fn01(x: u32) -> u32 { %s_fn00(x) + 2 }" % (touch_name, touch_name)
            new_line = old_line.replace("_fn00(", "_fn02(")
            if old_line not in text or len(new_line) != len(old_line):
                problems.append("the same-size leg could not build a same-size rewrite")
            else:
                with io.open(touch_path, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text.replace(old_line, new_line))
                os.utime(touch_path, (before_stat.st_atime, before_stat.st_mtime))
            after_stat = os.stat(touch_path)
            restored = os.path.getsize(touch_path) == before_size and after_stat.st_mtime == before_stat.st_mtime
            index.scan(live)
            caller = "%s_fn01" % touch_name
            callees = index.callees.get(caller, [])
            noticed = ("%s_fn02" % touch_name) in callees and ("%s_fn00" % touch_name) not in callees
            record["negative_same_size_restored_mtime"] = {
                "noticed": noticed,
                "size_bytes": before_size,
                "size_and_mtime_restored": restored,
                "detail": "only a content digest notices this; an mtime+size cache would not",
            }
            if not restored:
                problems.append("the same-size leg failed to restore the size and mtime")
            if not noticed:
                problems.append("a same-size rewrite with the mtime restored was not noticed")
            if graph_state(index) != graph_state(fresh_index(live)):
                problems.append("incremental index after a same-size rewrite != full rebuild")
        else:
            live = list(files)
            for skipped in (
                "the deleted-file incremental leg",
                "the stale incremental pass leg",
                "the same-size restored-mtime leg",
            ):
                not_run.append(
                    "%s (the dataset has %d files; three distinct files are needed)"
                    % (skipped, len(files))
                )

        # --- negative 3: an unknown symbol closes to nothing, and does not raise
        try:
            unknown = index.closure("symbol_that_does_not_exist")
            unknown_ok = unknown.get("found") is False and unknown.get("nodes") == 0
        except Exception as exc:  # noqa: BLE001 - the leg exists to prove it does not raise
            unknown = {"error": type(exc).__name__}
            unknown_ok = False
            problems.append("closure of an unknown symbol raised %s" % type(exc).__name__)
        record["negative_unknown_symbol_closure"] = {
            "held": unknown_ok,
            "closure": unknown,
            "detail": "an unknown symbol must close to nothing rather than raise",
        }
        if not unknown_ok:
            problems.append("an unknown symbol did not close to an empty closure")

        # --- negative 4: an empty project indexes to an empty graph ---------
        empty_root = os.path.join(shard, "empty")
        write_dataset(empty_root, 1, 0)
        empty_index = GraphIndex()
        empty_facts = empty_index.scan([])
        empty_ok = (
            empty_index.symbol_count() == 0
            and empty_index.edge_set() == set()
            and empty_index.publish() == {}
            and empty_facts["files_removed"] == 0
        )
        record["negative_empty_dataset"] = {
            "held": empty_ok,
            "symbols": empty_index.symbol_count(),
            "detail": "a project with no source files must index to an empty graph",
        }
        if not empty_ok:
            problems.append("an empty project did not index to an empty graph")

        record["design_targets"] = _design_targets(not_run)
        not_run.append(
            "the real Rust cold/incremental index measurement (graph-analyze / graph-export); "
            "this harness measures a Python stand-in over the same input shape"
        )
        not_run.append("native Windows and macOS runtime evidence (this host is the only one available)")
        not_run.append("cargo test -p graph-analyze --locked (the Rust gate runs in the Docker lane, not here)")
        record["not_run"] = not_run
        record["problems"] = problems
        record["ok"] = not problems
        return record, problems, not_run
    finally:
        if not keep:
            shutil.rmtree(shard, ignore_errors=True)


def _design_targets(not_run):
    """The specification budgets, recorded as unclaimed and reported not_run."""
    recorded = []
    for target in DESIGN_TARGETS:
        recorded.append(
            {
                "id": target["id"],
                "target": target["target"],
                "needs": target["needs"],
                "reproduce": target["reproduce"],
                "claimed": False,
                "status": "not_run",
            }
        )
        not_run.append(
            "%s: %s (needs %s; reproduce: %s)"
            % (target["id"], target["target"], target["needs"], target["reproduce"])
        )
    return recorded


def main(argv=None):
    parser = argparse.ArgumentParser(description="F-030 initial and incremental graph-work benchmark")
    parser.add_argument("--tier", choices=sorted(TIERS), default=DEFAULT_TIER)
    parser.add_argument("--projects", type=int, help="override the tier's project count")
    parser.add_argument("--files-per-project", type=int, help="override the tier's file count")
    parser.add_argument("--json-out", help="write the structured report to this path as well")
    parser.add_argument("--keep", action="store_true", help="keep the generated dataset (default: remove it)")
    args = parser.parse_args(argv)

    tier = TIERS[args.tier]
    projects = tier["projects"] if args.projects is None else args.projects
    files_per_project = tier["files_per_project"] if args.files_per_project is None else args.files_per_project
    if projects < 0 or files_per_project < 0:
        print("usage: --projects and --files-per-project must not be negative", file=sys.stderr)
        return 1

    try:
        record, problems, not_run = run(args.tier, projects, files_per_project, keep=args.keep)
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1

    if args.json_out:
        with io.open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    for item in not_run:
        print("not_run: %s" % item)
    for problem in problems:
        print("PROBLEM: %s" % problem)
    if problems:
        print("FAIL: %d problem(s)" % len(problems))
        return 2
    cold = record["cold"]
    print(
        "ok: F-030 %s tier, %d files and %d bytes; cold wall=%ss cpu=%ss peak_rss=%s bytes, "
        "warm no-op wall=%ss reparsed 0, one-edit wall=%ss, burst wall=%ss; "
        "%d symbols, %d edges, closure %s nodes, artifact %s bytes; "
        "0 specification targets claimed and %d measures reported not_run"
        % (
            args.tier,
            record["dataset"]["files"],
            record["dataset"]["bytes"],
            cold["wall_seconds"],
            cold["cpu_seconds"],
            cold["peak_rss_bytes"],
            record["warm"]["wall_seconds"],
            record["incremental_single_edit"]["wall_seconds"],
            record["incremental_burst"]["wall_seconds"],
            cold["symbols"],
            cold["edges"],
            record["closure"]["nodes"],
            record["artifact"]["bytes"],
            len(not_run),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
