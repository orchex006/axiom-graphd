$pkg = 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final\_w10final'
$targets = @((Join-Path $pkg '_smoke'), (Join-Path $pkg 'scripts\__pycache__'))
foreach ($t in $targets) {
  if (Test-Path $t) {
    $resolved = (Resolve-Path $t).Path
    if ($resolved.StartsWith($pkg)) { Remove-Item -Recurse -Force $resolved; Write-Output "removed $resolved" }
    else { Write-Output "SKIP outside package: $resolved" }
  } else { Write-Output "absent $t" }
}
