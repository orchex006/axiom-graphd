# W10 deliverables - proof that editing a source file refreshes the analysis.
#
# The owner can replay this whole sequence. It ends with the file restored
# byte-for-byte and the lane republished at the original generation id.
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
$src   = Join-Path $repo 'Src\Shared\Extensions\DateTimeExtensions.cs'

if (-not (Test-Path $src)) { throw "source file not found: $src" }

# --- snapshot the original bytes so the restore is exact --------------------
$origBytes = [System.IO.File]::ReadAllBytes($src)
[System.IO.File]::WriteAllBytes((Join-Path $out '12-edit-before-DateTimeExtensions.cs'), $origBytes)
$origHash = (Get-FileHash $src -Algorithm SHA256).Hash.ToLower()
"before_sha256=$origHash bytes=$($origBytes.Length)" | Out-File (Join-Path $out '12-edit-before.txt') -Encoding utf8

$genBefore = (Get-Content (Join-Path $gw 'live\current.json') -Raw | ConvertFrom-Json).generation_id
$manBefore = Join-Path $gw ("live\generations\$genBefore\manifest.json")
"preedit_generation_id=$genBefore" | Out-File (Join-Path $out '12-edit-before.txt') -Append -Encoding utf8
"preedit_manifest_sha256=$((Get-FileHash $manBefore -Algorithm SHA256).Hash.ToLower())" | Out-File (Join-Path $out '12-edit-before.txt') -Append -Encoding utf8

# --- the edit: add exactly one member to the class -------------------------
$text = [System.Text.Encoding]::UTF8.GetString($origBytes)
$idx  = $text.LastIndexOf('}')
$member = "    public static long ToUnixTimeTicks(DateTime dateTime)`r`n    {`r`n        return ((DateTimeOffset)dateTime).ToUnixTimeMilliseconds() * 10000L;`r`n    }`r`n`r`n"
$newText = $text.Substring(0, $idx) + $member + $text.Substring($idx)
[System.IO.File]::WriteAllText($src, $newText, (New-Object System.Text.UTF8Encoding($false)))
"after_edit_sha256=$((Get-FileHash $src -Algorithm SHA256).Hash.ToLower()) bytes=$((Get-Item $src).Length)" | Out-File (Join-Path $out '12-edit-after.txt') -Encoding utf8

# --- re-analyse and publish ------------------------------------------------
$env:AXIOM_HOME = $axh
$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $bin serve --json 1> (Join-Path $out '12-serve-after-edit.out') 2> (Join-Path $out '12-serve-after-edit.err')
$code = $LASTEXITCODE
$sw.Stop()
"exit=$code wall_ms=$($sw.ElapsedMilliseconds)" | Out-File (Join-Path $out '12-serve-after-edit.txt') -Encoding utf8

$genAfter = (Get-Content (Join-Path $gw 'live\current.json') -Raw | ConvertFrom-Json).generation_id
$manAfter = Join-Path $gw ("live\generations\$genAfter\manifest.json")
"postedit_generation_id=$genAfter" | Out-File (Join-Path $out '12-serve-after-edit.txt') -Append -Encoding utf8
"postedit_manifest_sha256=$((Get-FileHash $manAfter -Algorithm SHA256).Hash.ToLower())" | Out-File (Join-Path $out '12-serve-after-edit.txt') -Append -Encoding utf8
"generation_changed=$($genAfter -ne $genBefore)" | Out-File (Join-Path $out '12-serve-after-edit.txt') -Append -Encoding utf8

Get-ChildItem -Recurse -File (Join-Path $gw "live\generations\$genAfter") | ForEach-Object {
    "  " + $_.FullName.Replace("$(Join-Path $gw "live\generations\$genAfter")\", '') + " bytes=" + $_.Length + " sha256=" + ((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())
} | Out-File (Join-Path $out '12-serve-after-edit.txt') -Append -Encoding utf8

# --- MCP reads the freshly published generation ----------------------------
python (Join-Path $pkg 'scripts\mcp_stdio_client.py') --host-script (Join-Path $pkg 'scripts\mcp_stdio_host.py') --mcp-src (Join-Path $mcp 'src') --home $axmcp --calls (Join-Path $pkg 'scripts\edit-calls.json') --transcript (Join-Path $out '13-mcp-after-edit-transcript.txt') --results (Join-Path $out '13-mcp-after-edit-results.json') --pretty-results (Join-Path $out '13-mcp-after-edit-answers.txt') 1> (Join-Path $out '13-mcp-after-edit.out') 2> (Join-Path $out '13-mcp-after-edit.err')
"exit=$LASTEXITCODE" | Out-File (Join-Path $out '13-mcp-after-edit.txt') -Encoding utf8

# --- restore the file byte-for-byte, then prove the lane comes back ---------
[System.IO.File]::WriteAllBytes($src, $origBytes)
$restoredHash = (Get-FileHash $src -Algorithm SHA256).Hash.ToLower()
"restored_sha256=$restoredHash matches_original=$($restoredHash -eq $origHash)" | Out-File (Join-Path $out '14-restore.txt') -Encoding utf8
"repo_status=$(git -C $repo status --porcelain)" | Out-File (Join-Path $out '14-restore.txt') -Append -Encoding utf8

$sw2 = [System.Diagnostics.Stopwatch]::StartNew()
& $bin serve --json 1> (Join-Path $out '15-serve-restored.out') 2> (Join-Path $out '15-serve-restored.err')
$code2 = $LASTEXITCODE
$sw2.Stop()
"exit=$code2 wall_ms=$($sw2.ElapsedMilliseconds)" | Out-File (Join-Path $out '15-serve-restored.txt') -Encoding utf8
$genRestored = (Get-Content (Join-Path $gw 'live\current.json') -Raw | ConvertFrom-Json).generation_id
"restored_generation_id=$genRestored equals_preedit=$($genRestored -eq $genBefore)" | Out-File (Join-Path $out '15-serve-restored.txt') -Append -Encoding utf8

Write-Host "edit proof done: before=$genBefore after=$genAfter restored=$genRestored"
