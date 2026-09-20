# graph-mermaid-view - end-to-end render of the real project's published
# generation, twice, to show the three artifacts and their byte-determinism.
#
# Runs against the ALREADY PUBLISHED generation in the real project
# (agmws-license-management-netcore, branch feature/graphd). Nothing in the
# target repository is published, edited or deleted by this script: it only
# reads the graph root and writes its own evidence folder.
$ErrorActionPreference = 'Stop'

$wt   = 'D:\SP-Billy\axiom-worktrees\axiom-graphd-mermaid'
$pkg  = Join-Path $wt '_w10mermaid'
$bin  = Join-Path $wt 'target\release\axiom-graphd.exe'
$out  = Join-Path $pkg 'evidence'
$axh  = Join-Path $pkg 'home'
$repo = 'D:\SP-Billy\axiom\agmws-license-management-netcore'
$gw   = Join-Path $repo '.axiom\graph\agmws-license\agmws-web-service'
$SOL  = 'agmws-license'
$PRJ  = 'agmws-web-service'

if (-not (Test-Path $bin)) { throw "build first: cd $wt; cargo build --release --locked -p axiom-graphd" }
if (-not (Test-Path $gw))  { throw "the real project has no published generation at $gw - run serve in it first" }

# The scratch AXIOM_HOME is rebuilt from nothing every run, so a second run never
# answers CONFLICT/duplicate-solution. Every recursive delete stays inside the
# verified package root.
$pkgFull = [System.IO.Path]::GetFullPath($pkg)
$axhFull = [System.IO.Path]::GetFullPath($axh)
if (-not $axhFull.StartsWith($pkgFull, [System.StringComparison]::OrdinalIgnoreCase)) { throw "home outside package: $axhFull" }
if (Test-Path $axhFull) { Remove-Item -Recurse -Force -LiteralPath $axhFull }

New-Item -ItemType Directory -Force -Path $out, (Join-Path $axh 'config') | Out-Null
Set-Content -NoNewline -Path (Join-Path $axh 'config\bindings.json') -Value '{ "status": "ok", "bindings": { "agmws": "D:\\SP-Billy\\axiom" } }'
Set-Content -NoNewline -Path (Join-Path $axh 'config\registry.json') -Value '{ "storage": { "journalMode": "DELETE" } }'
Set-Content -NoNewline -Path (Join-Path $axh 'solution.json') -Value '{ "id": "agmws-license", "profile": "default", "projects": [ { "id": "agmws-web-service", "repo_id": "agmws", "path": "agmws-license-management-netcore" } ] }'

"binary=$bin"                                                          | Out-File (Join-Path $out '00-env.txt') -Encoding utf8
"binary_bytes=$((Get-Item $bin).Length)"                               | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"binary_sha256=$((Get-FileHash $bin -Algorithm SHA256).Hash.ToLower())" | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"graphd_branch=$(git -C $wt rev-parse --abbrev-ref HEAD)"              | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"graphd_revision=$(git -C $wt rev-parse HEAD)"                         | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
# The worktree is dirty at evidence time by exactly this package: the run below
# writes the files listed here, and they are committed right after the run.
"graphd_status_porcelain=" + ((git -C $wt status --porcelain) -join "; ") | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"cargo_profile=release"                                                | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo=$repo"                                                           | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo_branch=$(git -C $repo rev-parse --abbrev-ref HEAD)"              | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo_head=$(git -C $repo rev-parse HEAD)"                             | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8
"repo_status=$(git -C $repo status --porcelain)"                       | Out-File (Join-Path $out '00-env.txt') -Append -Encoding utf8

$env:AXIOM_HOME = $axh

$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $bin solution register --config (Join-Path $axh 'solution.json') --bindings (Join-Path $axh 'config\bindings.json') --apply --json `
    1> (Join-Path $out '01-register.out') 2> (Join-Path $out '01-register.err')
$code = $LASTEXITCODE; $sw.Stop()
"exit=$code wall_ms=$($sw.ElapsedMilliseconds)" | Out-File (Join-Path $out '01-register.txt') -Encoding utf8

foreach ($tag in @('a','b')) {
    $d = Join-Path $out "render-$tag"
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $bin render --solution $SOL --project $PRJ --out $d --json 1> (Join-Path $out "02-render-$tag.out") 2> (Join-Path $out "02-render-$tag.err")
    $code = $LASTEXITCODE; $sw.Stop()
    "exit=$code wall_ms=$($sw.ElapsedMilliseconds)" | Out-File (Join-Path $out "02-render-$tag.txt") -Encoding utf8
}

"=== artifacts of both renders (bytes / sha256) ===" | Out-File (Join-Path $out '03-artifacts.txt') -Encoding utf8
foreach ($tag in @('a','b')) {
    Get-ChildItem (Join-Path $out "render-$tag") -File | Sort-Object Name | ForEach-Object {
        "render-$tag $($_.Name) bytes=$($_.Length) sha256=$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())"
    } | Out-File (Join-Path $out '03-artifacts.txt') -Append -Encoding utf8
}

"=== two renders of one generation, artifact by artifact ===" | Out-File (Join-Path $out '04-determinism.txt') -Encoding utf8
foreach ($name in @('result.html','summary.json','graph.mmd')) {
    $a  = (Get-FileHash (Join-Path $out "render-a\$name") -Algorithm SHA256).Hash.ToLower()
    $b  = (Get-FileHash (Join-Path $out "render-b\$name") -Algorithm SHA256).Hash.ToLower()
    "byte_identical $name $($a -eq $b) sha256=$a" | Out-File (Join-Path $out '04-determinism.txt') -Append -Encoding utf8
}

Write-Host "evidence in $out"
