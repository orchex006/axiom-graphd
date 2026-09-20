# W10 deliverables - end-to-end run (deliverables 1, 2, 3, 5).
#
# Publishes a fresh generation for the real project with the release
# axiom-graphd, then reads it back through a real MCP stdio session, renders the
# relationship graph, and measures the before/after cost.
$ErrorActionPreference = 'Stop'

$wt    = 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final'
$pkg   = Join-Path $wt '_w10final'
$bin   = Join-Path $wt 'target\release\axiom-graphd.exe'
$out   = Join-Path $pkg 'evidence'
$axh   = Join-Path $pkg 'home-e2e'
$axmcp = Join-Path $pkg 'home-mcp'
$repo  = 'D:\SP-Billy\axiom\agmws-license-management-netcore'
$mcp   = 'D:\SP-Billy\axiom\axiom-mcp'
$gw    = Join-Path $repo '.axiom\graph\agmws-license\agmws-web-service'
$SOL   = 'agmws-license'
$PRJ   = 'agmws-web-service'

# --- every recursive delete stays inside a verified root ---------------------
$repoFull = [System.IO.Path]::GetFullPath($repo)
$gwFull   = [System.IO.Path]::GetFullPath($gw)
if (-not $gwFull.StartsWith($repoFull, [System.StringComparison]::OrdinalIgnoreCase)) { throw "gw outside repo: $gwFull" }
$pkgFull = [System.IO.Path]::GetFullPath($pkg)
foreach ($p in @($out, $axh, $axmcp)) {
    $pf = [System.IO.Path]::GetFullPath($p)
    if (-not $pf.StartsWith($pkgFull, [System.StringComparison]::OrdinalIgnoreCase)) { throw "outside package: $pf" }
    if (Test-Path $pf) { Remove-Item -Recurse -Force -LiteralPath $pf }
}
New-Item -ItemType Directory -Force -Path $out, (Join-Path $axh 'config') | Out-Null

# --- 00 environment ----------------------------------------------------------
"binary=$bin" | Out-File (Join-Path $out '00-env.txt') -Encoding utf8
"binary_bytes=$((Get-Item $bin).Length)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"binary_sha256=$((Get-FileHash $bin -Algorithm SHA256).Hash.ToLower())" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"graphd_branch=$(git -C $wt rev-parse --abbrev-ref HEAD)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"graphd_revision=$(git -C $wt rev-parse HEAD)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"cargo_profile=release" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo=$repo" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo_branch=$(git -C $repo rev-parse --abbrev-ref HEAD)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo_head=$(git -C $repo rev-parse HEAD)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo_status=$(git -C $repo status --porcelain)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"mcp_revision=$(git -C $mcp rev-parse HEAD)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"python=$(python --version 2>&1)" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8

Set-Content -NoNewline -Path (Join-Path $axh 'config\bindings.json') -Value '{ "status": "ok", "bindings": { "agmws": "D:\\SP-Billy\\axiom" } }'
Set-Content -NoNewline -Path (Join-Path $axh 'config\registry.json') -Value '{ "storage": { "journalMode": "DELETE" } }'
Set-Content -NoNewline -Path (Join-Path $axh 'solution.json') -Value '{ "id": "agmws-license", "profile": "default", "projects": [ { "id": "agmws-web-service", "repo_id": "agmws", "path": "agmws-license-management-netcore" } ] }'

# --- the lanes are scratch: drop them so this is a fresh publication ---------
foreach ($lane in @('live','checkpoint')) {
    $lanePath = Join-Path $gw $lane
    if (Test-Path $lanePath) {
        $lf = [System.IO.Path]::GetFullPath($lanePath)
        if (-not $lf.StartsWith($gwFull, [System.StringComparison]::OrdinalIgnoreCase)) { throw "lane outside gw: $lf" }
        Remove-Item -Recurse -Force -LiteralPath $lanePath
    }
}

$env:AXIOM_HOME = $axh

& $bin solution register --config (Join-Path $axh 'solution.json') --bindings (Join-Path $axh 'config\bindings.json') --apply --json 1> (Join-Path $out '01-register.out') 2> (Join-Path $out '01-register.err')
"exit=$LASTEXITCODE" | Out-File (Join-Path $out '01-register.txt') -Encoding utf8

$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $bin serve --json 1> (Join-Path $out '02-serve.out') 2> (Join-Path $out '02-serve.err')
$code = $LASTEXITCODE
$sw.Stop()
$buildMs = $sw.ElapsedMilliseconds
"exit=$code wall_ms=$buildMs" | Out-File (Join-Path $out '02-serve.txt') -Encoding utf8

"=== every published file under the project's graph root ===" | Out-File (Join-Path $out '03-tree.txt') -Encoding utf8
Get-ChildItem -Recurse -Force $gw -File | ForEach-Object { $_.FullName.Replace("$gw\", '') + "  bytes=" + $_.Length } | Out-File (Join-Path $out '03-tree.txt') -Append -Encoding utf8

"=== current.json bytes (both lanes) ===" | Out-File (Join-Path $out '04-pointer.txt') -Encoding utf8
foreach ($lane in @('live','checkpoint')) {
    $pt = Join-Path $gw "$lane\current.json"
    if (Test-Path $pt) {
        $raw = [System.IO.File]::ReadAllBytes($pt)
        "lane=$lane size=$($raw.Length)" | Out-File (Join-Path $out '04-pointer.txt') -Append -Encoding utf8
        "lane=$lane text=$([System.Text.Encoding]::UTF8.GetString($raw))" | Out-File (Join-Path $out '04-pointer.txt') -Append -Encoding utf8
        "lane=$lane sha256=$((Get-FileHash $pt -Algorithm SHA256).Hash.ToLower()) ends_with_lf=$($raw[-1] -eq 10)" | Out-File (Join-Path $out '04-pointer.txt') -Append -Encoding utf8
    } else {
        "lane=$lane POINTER_MISSING" | Out-File (Join-Path $out '04-pointer.txt') -Append -Encoding utf8
    }
}

"=== generation digests (live lane) ===" | Out-File (Join-Path $out '05-digests.txt') -Encoding utf8
$genRoot = Join-Path $gw 'live\generations'
if (Test-Path $genRoot) {
    Get-ChildItem $genRoot -Directory | ForEach-Object {
        $gen = $_
        "generation_dir=$($gen.Name)" | Out-File (Join-Path $out '05-digests.txt') -Append -Encoding utf8
        Get-ChildItem -Recurse -File $gen.FullName | ForEach-Object {
            "  " + $_.FullName.Replace("$($gen.FullName)\", '') + " bytes=" + $_.Length + " sha256=" + ((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())
        } | Out-File (Join-Path $out '05-digests.txt') -Append -Encoding utf8
    }
}

# --- the live pointer must equal the manifest bytes (a real claim) ----------
$liveGen = (Get-Content (Join-Path $gw 'live\current.json') -Raw | ConvertFrom-Json).generation_id
$manifestPath = Join-Path $gw ("live\generations\$liveGen\manifest.json")
"live_pointer_generation_id=$liveGen" | Out-File (Join-Path $out '05b-manifest-identity.txt') -Encoding utf8
"manifest_sha256=$((Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLower())" | Out-File (Join-Path $out '05b-manifest-identity.txt') -Append -Encoding utf8
"manifest_equals_generation_id=$(((Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLower()) -eq $liveGen)" | Out-File (Join-Path $out '05b-manifest-identity.txt') -Append -Encoding utf8

# --- 09 render: the relationship graph as result.html ----------------------
$renderOut = Join-Path $out 'render'
New-Item -ItemType Directory -Force -Path $renderOut | Out-Null
$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $bin render --solution $SOL --project $PRJ --out $renderOut --json 1> (Join-Path $out '09-render.out') 2> (Join-Path $out '09-render.err')
$code = $LASTEXITCODE
$sw.Stop()
"exit=$code wall_ms=$($sw.ElapsedMilliseconds)" | Out-File (Join-Path $out '09-render.txt') -Encoding utf8

# --- 06 MCP: a real JSON-RPC session over stdio -----------------------------
python (Join-Path $pkg 'scripts\make_homemcp.py') --home $axmcp --repo $repo --project-path '.' 1> (Join-Path $out '06-home-mcp.out') 2> (Join-Path $out '06-home-mcp.err')
"exit=$LASTEXITCODE" | Out-File (Join-Path $out '06-home-mcp.txt') -Encoding utf8

Copy-Item -Force (Join-Path $pkg 'scripts\demo-calls.json') (Join-Path $out '06-calls.json')

python (Join-Path $pkg 'scripts\mcp_stdio_client.py') --host-script (Join-Path $pkg 'scripts\mcp_stdio_host.py') --mcp-src (Join-Path $mcp 'src') --home $axmcp --calls (Join-Path $out '06-calls.json') --transcript (Join-Path $out '06-mcp-transcript.txt') --results (Join-Path $out '06-mcp-results.json') --pretty-results (Join-Path $out '06-mcp-answers.txt') 1> (Join-Path $out '06-mcp.out') 2> (Join-Path $out '06-mcp.err')
"exit=$LASTEXITCODE" | Out-File (Join-Path $out '06-mcp.txt') -Encoding utf8

# --- 07 the payload contract checker (specs-side reference evaluator) ------
# tools/graph_contract.py lives in axiom-specs and is READ-ONLY for this lane.
# A verbatim copy is kept in scripts/ so nothing is ever written into axiom-specs.
python (Join-Path $pkg 'scripts\check_contract.py') --generation (Join-Path $gw "live\generations\$liveGen") --out (Join-Path $out '07b-contract-combined.json') 1> (Join-Path $out '07-contract.out') 2> (Join-Path $out '07-contract.err')
"exit=$LASTEXITCODE" | Out-File (Join-Path $out '07-contract.txt') -Encoding utf8

# --- 10 baseline: the same question with no graphd --------------------------
python (Join-Path $pkg 'scripts\baseline_scan.py') --repo $repo --symbol 'AgriMap.Web.Service.Shared.Extensions.DateTimeExtensions' 1> (Join-Path $out '10-baseline-scan.out') 2> (Join-Path $out '10-baseline-scan.err')

# --- 11 benchmark -----------------------------------------------------------
python (Join-Path $pkg 'scripts\run_bench.py') --repo $repo --generation-dir (Join-Path $gw "live\generations\$liveGen") --home $axmcp --mcp-src (Join-Path $mcp 'src') --host-script (Join-Path $pkg 'scripts\mcp_stdio_host.py') --client-script (Join-Path $pkg 'scripts\mcp_stdio_client.py') --out-dir (Join-Path $out 'bench') --questions 20 --graph-build-ms $buildMs 1> (Join-Path $out '11-bench.out') 2> (Join-Path $out '11-bench.err')
"exit=$LASTEXITCODE" | Out-File (Join-Path $out '11-bench.txt') -Encoding utf8

Write-Host "e2e done: build_ms=$buildMs live_generation=$liveGen"
