# Repeat the before/after bench several times so the owner sees the real spread,
# not one hand-picked number. Each repetition opens its own real MCP stdio session.
$ErrorActionPreference = 'Stop'
$wt  = 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final'
$pkg = Join-Path $wt '_w10final'
$out = Join-Path $pkg 'evidence'
$axmcp = Join-Path $pkg 'home-mcp'
$repo  = 'D:\SP-Billy\axiom\agmws-license-management-netcore'
$mcp   = 'D:\SP-Billy\axiom\axiom-mcp'
$gw    = Join-Path $repo '.axiom\graph\agmws-license\agmws-web-service'
$gen   = (Get-Content (Join-Path $gw 'live\current.json') -Raw | ConvertFrom-Json).generation_id
$build = 9227.0
$rep   = Join-Path $out 'bench-repeats'
New-Item -ItemType Directory -Force -Path $rep | Out-Null
for ($i = 1; $i -le 3; $i++) {
  $d = Join-Path $rep "run$i"
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  python (Join-Path $pkg 'scripts\run_bench.py') --repo $repo --generation-dir (Join-Path $gw "live\generations\$gen") --home $axmcp --mcp-src (Join-Path $mcp 'src') --host-script (Join-Path $pkg 'scripts\mcp_stdio_host.py') --client-script (Join-Path $pkg 'scripts\mcp_stdio_client.py') --out-dir $d --questions 20 --graph-build-ms $build 1> (Join-Path $d 'bench.out') 2> (Join-Path $d 'bench.err')
  "run$i exit=$LASTEXITCODE" | Out-File (Join-Path $rep "run$i.txt") -Encoding utf8
  Write-Host "run$i done"
}
