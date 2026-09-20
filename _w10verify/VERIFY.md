# W10 — Independent verification lane (`_w10verify`)

Verifying the owner-facing deliverables produced by lane `W10-DELIVERABLES`
(subagent Faraday). Everything below was **re-measured from scratch** in this lane.

- Host: Windows 11 x64, PowerShell 7, Python 3.13.14
- Date: 2026-09-20 (Asia/Bangkok)
- Read-only reference package: `D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final\_w10final\`
- My write area (only): `D:\SP-Billy\axiom\_coord\_w10verify\`
- Protected scratch project: `D:\SP-Billy\axiom\_coord\_w10verify\proj` (robocopy of the owner
  project, `.axiom` excluded). Owner project `D:\SP-Billy\axiom\agmws-license-management-netcore`
  treated as read-only.

## 0. Binary identity (asked first)

| item | expected | measured | verdict |
|---|---|---|---|
| `target\release\axiom-graphd.exe` sha256 | `5c92ab426313a3beb407310d317b56938296b85619ac969808e97c90452da36d` | `5c92ab426313a3beb407310d317b56938296b85619ac969808e97c90452da36d` | **EXACT** (no rebuild needed) |
| binary bytes | 3736576 | 3736576 | EXACT |
| graphd worktree HEAD vs README `graphd_revision=51782bb…` | `51782bb4337799b8479de1ea2ce4f29e1bbd038d` | HEAD is `bb4c168179dae549035109e6581352a5755d0c3a` | **EXPLAINED, not a mismatch** |

`51782bb` **is an ancestor** of the worktree HEAD. The only commits since are
`33e88dd` and `bb4c168`, which touch **nothing but `_w10final/`** (the package itself,
110 files added). No graphd source changed after `51782bb`, so the release binary is
**not source-stale**; the README quotes the source revision that produced the binary.

Raw:
```powershell
(Get-FileHash 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final\target\release\axiom-graphd.exe' -Algorithm SHA256).Hash.ToLower()
git -C 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final' rev-parse HEAD
git -C 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final' diff --stat 51782bb4337799b8479de1ea2ce4f29e1bbd038d HEAD
```

## 1. Owner-project protection

Copy made with:
```powershell
robocopy 'D:\SP-Billy\axiom\agmws-license-management-netcore' 'D:\SP-Billy\axiom\_coord\_w10verify\proj' /E /XD .axiom
```
Result: `Dirs 153 copied / 1 skipped (.axiom)`, `Files 508`, `Bytes 3.19 m`.

| check | value |
|---|---|
| copy files (all) | 508 |
| copy `.cs` files | 156 |
| copy `.axiom` present? | **False** |
| copy `.git` present? | True |
| copy git HEAD | `24410f3665447a7555c711e8aafe74f4c0f0ced7` (branch `feature/graphd`), clean |
| copy `DateTimeExtensions.cs` sha256 | `1d7480e92bf8a1ad73c2070f32ab77043b93ef9852dfdf5aa5d9c127e85de7f7` — **byte-identical to the package's recorded `before_sha256`** |
| owner project after all work | `?? .axiom/` only (unchanged tracked state) |

### 1.1 Scope deviation I must report (self-inflicted)

The package's `run_e2e.ps1` builds `bindings.json` with `"agmws": "D:\\SP-Billy\\axiom"` and
`solution.json` with project path `agmws-license-management-netcore`. My first adapted run kept
that binding, so graphd resolved the project root back to the **real owner project**
(`project_root":"D:/SP-Billy/axiom/agmws-license-management-netcore"`) and re-published there at
18:41:39 before I caught it. I then redirected the binding to scratch and re-ran everything.

Impact assessment of that single run:
- It **content-addressed onto an already-existing generation** (`1d78915…`) — no new generation
  directory, no change to `nodes/`, `edges/`, `coverage.json` or `manifest.json` (those files still
  carry their 18:23/18:25 mtimes).
- Only `live\current.json` and `checkpoint\current.json` were rewritten, and their bytes are
  **identical** to the recorded reference: sha256 `0a8006210f4b16ef64a43db79ea50414e0c9c09369f88ca37f0160edc223f612`.
- Tracked files: still only `?? .axiom/`. No repo content changed; `.axiom` is graphd scratch
  (regenerable by `serve`), which the previous lane's own README states.

Net effect: **mtime-only change to two scratch pointer files; zero content change**. Reported
rather than hidden. All reproduction numbers below come from the scratch copy.

## 2. Claim-by-claim reproduction (items 1–4)

| # | claim | previous-lane value | my measured value | reproduces? | raw command |
|---|---|---|---|---|---|
| 1a | generation dir | `1d7891525f028ecff06a6b8d7a8ac8a4ee3b31cc8067f1431e900b0cf7cdf6f7` | `1d7891525f028ecff06a6b8d7a8ac8a4ee3b31cc8067f1431e900b0cf7cdf6f7` | **EXACT** | adapted `run_e2e.ps1` → `evidence\02-serve.out` |
| 1b | `nodes\000000.json` | 597010 B / `0fc1039146ad693462f1add68449e9581e7c72d1e2849e4029d6b3ccf00fed26` | 597010 B / `0fc1039146ad693462f1add68449e9581e7c72d1e2849e4029d6b3ccf00fed26` | **EXACT** | `Get-FileHash` in `run_e2e.ps1` → `evidence\05-digests.txt` |
| 1c | `edges\000000.json` | 624413 B / `8117ddd68d3b3734391cc1bcda95f08ce1e5d38b94caee856c71743a8c9b0aad` | 624413 B / `8117ddd68d3b3734391cc1bcda95f08ce1e5d38b94caee856c71743a8c9b0aad` | **EXACT** | same |
| 1d | `coverage.json` | 126 B / `518b83780b44a93bee4e34ddb1f3bf8025687cba8740717b22b4f97b1f219317` | 126 B / `518b83780b44a93bee4e34ddb1f3bf8025687cba8740717b22b4f97b1f219317` | **EXACT** | same |
| 1e | `live\current.json` | 189 B / `0a8006210f4b16ef64a43db79ea50414e0c9c09369f88ca37f0160edc223f612` | 189 B / `0a8006210f4b16ef64a43db79ea50414e0c9c09369f88ca37f0160edc223f612` | **EXACT** | `run_e2e.ps1` → `evidence\04-pointer.txt` |
| 1f | `sha256(manifest.json) == generation_id` | True | True | **EXACT** | → `evidence\05b-manifest-identity.txt` |
| 1g | specs evaluator verdict | `ok:true`, nodes 1368, edges 1213, reasons `[]` | `ok:true`, nodes 1368, edges 1213, reasons `[]` | **EXACT** | `python scripts\check_contract.py --generation … --out …` → `evidence\07-contract.out` |
| 2a | `result.html` | 919717 B / `ea3f4bd2dc248c2525eeeea114ca405f0b7d6e9dbe74955d5d60d018dc6c2bee` | 919717 B / `ea3f4bd2dc248c2525eeeea114ca405f0b7d6e9dbe74955d5d60d018dc6c2bee` | **EXACT** | `axiom-graphd.exe render --solution agmws-license --project agmws-web-service --out … --json` → `evidence\09-render.out` |
| 2b | `summary.json` | 1295279 B | 1295279 B (sha `98371d9f5ad5a0d86a50db5e01f5c583de71be369803cb3717b4dd2d4be586b4`) | **EXACT** | same |
| 3a | MCP `graph_query context DateTimeExtensions` | 7 nodes / 6 edges | 7 nodes / 6 edges | **EXACT** | `python scripts\mcp_stdio_client.py --host-script … --calls evidence\06-calls.json …` → `evidence\06-mcp-results.json` |
| 3b | location of `…DateTimeExtensions.ToUnixTimeStamp` | `Src/Shared/Extensions/DateTimeExtensions.cs:26` | `Src/Shared/Extensions/DateTimeExtensions.cs:26` (`source.file`/`source.start_line`) | **EXACT** | same |
| 3c | MCP `catalog_generation_id` (not in the claim list, cross-check) | `4869b499eb6ef4328c5e61f53149b7278b9a3f7a6930cfa209bc76742dcdca55` | `4869b499eb6ef4328c5e61f53149b7278b9a3f7a6930cfa209bc76742dcdca55` | **EXACT** | same |
| 4a | edit → generation change | `1d78915…` → `8b632b5da319dbf03de49f3370d391a5b0f8711d4890d480eb860a3abcfc91f2` | `1d78915…` → `8b632b5da319dbf03de49f3370d391a5b0f8711d4890d480eb860a3abcfc91f2` | **EXACT** | adapted `run_edit_proof.ps1` → `evidence\12-serve-after-edit.txt` |
| 4b | node/edge counts after edit | 1368/1213 → 1369/1214 | 1368/1213 → 1369/1214 | **EXACT** | `evidence\12-serve-after-edit.out` (`nodes:1369, edges:1214`) |
| 4b' | after-edit `nodes\000000.json` | 597414 B / `03c01e033a0e454192d42f1ad50ce18bbd69ef2b02cc99eb893139c76c40c190` | 597414 B / `03c01e033a0e454192d42f1ad50ce18bbd69ef2b02cc99eb893139c76c40c190` | **EXACT** | `evidence\12-serve-after-edit.txt` |
| 4b'' | after-edit `edges\000000.json` | 624915 B / `12dbdbe94550c89b27a645f0702ba0e091c754b756717f3fe4fb50b91a313df8` | 624915 B / `12dbdbe94550c89b27a645f0702ba0e091c754b756717f3fe4fb50b91a313df8` | **EXACT** | same |
| 4c | byte-exact restore → original generation returns | restored = `1d78915…`, `matches_original=True` | restored = `1d78915…`, `matches_original=True` | **EXACT** | `evidence\14-restore.txt`, `evidence\15-serve-restored.txt` |
| 5 (package index) | `00-manifest.txt` 118 entries | 118 entries | 118 entries, **all 118 verify** (size + sha256, 0 mismatch, 0 missing) | **EXACT** | re-hash of every listed file against `00-manifest.txt` |

Notes:
- The MCP demo (claim 3) was driven through the **shipped `axiom_mcp` handlers** on a real
  stdio JSON-RPC session (`mcp_stdio_host.py` binds `axiom_mcp.tools.query` to the shipped
  `GuardedSnapshotSource`). The package is explicit that **no shipped production stdio entry
  point registers those handlers yet** — that gap is a recorded finding, not a hidden one, and my
  reproduction inherits the same caveat.
- Project size is **156 `.cs` source files** (coverage `input_files=156`), while graphd's
  `analyzed_files=473` counts every file it ingests under the project root. Both are real; do not
  conflate them.

## 3. Item 5 — before/after cost, done properly

I distrusted the previous lane's number and rebuilt the comparison myself.

**Design**
- **without graphd:** each of N relationship questions answered by a full, **uncached** text scan —
  read every `.cs` file, find the declaring type, read the declaring file again to count members.
  Per-question wall time recorded.
- **with graphd:** ONE real MCP stdio session per repetition; each question is a real
  `tools/call graph_query`. Per-call `elapsed_ms` comes from the MCP client, which polls at
  **20 ms**, so it is **quantised**.
- **R repetitions**; for each we compute per-question means and the paired difference
  `scan − graphd`. Then across-repetition mean/stdev and sign-flip count.
- The one-off `serve` build is measured **separately** (amortised, not free).

**Parameters:** N = 20 questions, R = 8 repetitions, `files_scanned_per_question = 156`.

**Per-repetition (ms/question)**

| rep | without graphd (scan) | with graphd (MCP) | delta (scan − graphd) |
|---|---|---|---|
| 1 | 46.0 | 155.6 | −109.6 |
| 2 | 79.1 | 63.4 | +15.7 |
| 3 | 69.4 | 104.5 | −35.1 |
| 4 | 59.2 | 87.9 | −28.7 |
| 5 | 29.2 | 68.7 | −39.5 |
| 6 | 23.5 | 75.8 | −52.3 |
| 7 | 29.2 | 62.6 | −33.4 |
| 8 | 19.4 | 72.7 | −53.3 |

**Summary**

| metric | without graphd | with graphd |
|---|---|---|
| per-question mean (mean of the 8 rep means) | **44.4 ms** | **86.4 ms** |
| across-rep stdev of the mean | 22.6 ms | 31.2 ms |
| min / max rep mean | 19.4 / 79.1 | 62.6 / 155.6 |

| delta (scan − graphd) | value |
|---|---|
| mean | **−42.0 ms** (negative ⇒ the untyped scan is *faster* per question here) |
| stdev | **34.7 ms** |
| min / max | −109.6 / +15.7 |
| sign distribution | 1 positive, 7 negative |
| **sign flips?** | **yes** (rep 2 is positive while the other 7 are negative) |

**Quantisation evidence** — 160 MCP calls, distinct `elapsed_ms` values cluster on a ~20 ms
lattice: `60.7…63.8, 81.2…84.1, 101.7…103.5, 121.8…124.6, 143.0…143.9, 162.7…164.5, 179.1,
186.9, 203.6…205.7, 223.6`. So any single per-call number carries **±20 ms** of artefact.

**One-off `serve` costs (measured separately, amortised — not free)**

| serve | measured wall | notes |
|---|---|---|
| full analyse, fresh AXIOM_HOME (`analyzed_files=473`) | **8194 ms** | warm OS page cache on this host |
| incremental after a 1-file edit | **474 ms** | `evidence\12-serve-after-edit.txt` |
| incremental after restoring that file | **407 ms** | `evidence\15-serve-restored.txt` |
| re-serve with no change | 832 / 158 / 229 ms | inventory already current (`analyzed_files=0`) |

> The previous lane reported cold **16720 ms** / warm **9227 ms** / incremental **445 & 313 ms**.
> I cannot force a cold page cache, so `16720` is **not reproduced (could be cold-cache only)**;
> my fresh-home full analyse is **8194 ms**. The claimed incremental `445/313` is **not
> reproduced** — I measure **474/407**, and the package's *own* evidence files record 402/411, so
> `445/313` does not even match its own recorded evidence.

**Honest conclusion**
- **There is no statistically distinguishable per-question saving from graphd at this project
  size (156 `.cs` files).** The previous lane's mean **+11.7 ms** does **not** reproduce; my
  independent mean is **−42.0 ms with stdev 34.7** — i.e. the sign flipped *and* reversed relative
  to the previous lane, and the spread is larger than the effect in both lanes.
- Even within *my* sample the sign flips (1 of 8 reps positive). With ±20 ms poll quantisation on
  the graphd leg, the per-question figure is not resolvable below the noise floor.
- The interesting asymmetry is that the no-graphd leg is cheap here: 156 files × ~2.3 MB is a
  sub-100 ms full scan on a warm cache, while a graphd answer pays a JSON-RPC round trip plus
  20 ms poll granularity. Above the break-even size measured by the previous lane
  (≈200–390 files, a *derived* extrapolation, not a scan of such a tree) the scan grows linearly
  and graphd stays ~flat — but **this repository is below that line**.
- The real, defensible wins at this size are **not latency**: graphd gives node identity, kinds,
  resolution and edges (the untyped scan cannot answer "what depends on this"), it is
  deterministic (identical generation id and digests on every rebuild), and an edit refreshes the
  graph in **~0.4 s** instead of re-scanning. Those are capability and refresh-cost wins, and they
  reproduce exactly.
- The previously reported **+32.3 ms/question saving does not reproduce** — confirmed, by a
  different method, with more repetitions, and with the opposite-sign mean.

## 4. Headline verdicts

- Item 1 (analysis output, digests, generation identity, contract verdict): **EXACT** — all five
  digests, the manifest==generation_id identity, and `ok:true/1368/1213/[]`.
- Item 2 (`result.html` + `summary.json`): **EXACT**.
- Item 3 (MCP stdio demo): **EXACT** — 7 nodes / 6 edges, `DateTimeExtensions.cs:26`, identical
  `catalog_generation_id`.
- Item 4 (edit → refresh → restore): **EXACT** — ids, counts, per-file digests, and the byte-exact
  round trip.
- Item 5 (per-question cost): **NOT REPRODUCED / no saving** — see §3. One-off build and
  incremental-refresh costs are real but amortised.
- Binary identity: **MATCH**; the README's `graphd_revision` is an ancestor of the worktree HEAD
  with only `_w10final/` added afterwards, so the binary is not stale.
- Could not reproduce: a **cold-cache** `serve` (no way to drop the OS page cache here).

## 5. Artifacts (all under `_coord\_w10verify\`)

- `VERIFY.md` — this file
- `01-robocopy.txt`, `02-e2e-run.txt`, `03-editproof-run.txt`, `04-bench5-run.txt`,
  `05-serve-run.txt`, `06-build-run.txt`
- `scripts\` — `run_e2e.ps1`, `run_edit_proof.ps1` (paths adapted to the scratch copy),
  `bench5.py` (item-5 harness), `measure_serve.ps1`, `measure_build.ps1`, plus the package
  drivers copied verbatim for the MCP client/host
- `evidence\` — the fresh outputs (`05-digests.txt`, `07-contract.out`, `09-render.out`,
  `06-mcp-results.json`, `12-*`/`13-*`/`14-*`/`15-*`, `serve-timings.txt`, `build-timings.txt`,
  `bench5\bench5-report.json` + per-rep transcripts)