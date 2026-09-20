"""Rewrite every tracked file from its index blob so the working tree is byte-identical
to what git stores (the repo .gitattributes normalises EOLs). Then sha256s verify after clone."""
import pathlib, subprocess

WT = pathlib.Path(r'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final')

subprocess.run(['git', 'add', '-A', '_w10final'], cwd=WT, check=True)

entries = subprocess.run(['git', 'ls-files', '-s', '_w10final'], cwd=WT,
                         capture_output=True, text=True, check=True).stdout.splitlines()
changed = []
for line in entries:
    meta, rel = line.split('\t', 1)
    blob = meta.split()[1]
    raw = subprocess.run(['git', 'cat-file', 'blob', blob], cwd=WT,
                         capture_output=True, check=True).stdout
    path = WT / rel
    if path.exists() and path.read_bytes() != raw:
        changed.append(rel)
    path.write_bytes(raw)
print('tracked files: %d' % len(entries))
print('rewritten to stored bytes: %d' % len(changed))
for rel in changed:
    print('  ' + rel)
