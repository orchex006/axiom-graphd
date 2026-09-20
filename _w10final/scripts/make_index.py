"""Index every file in the package with size + sha256 (skips the manifest itself)."""
import hashlib, pathlib, sys

PKG = pathlib.Path(r'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final\_w10final')
OUT = PKG / '00-manifest.txt'
REVISION = '51782bb4337799b8479de1ea2ce4f29e1bbd038d'

def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

files = sorted(p for p in PKG.rglob('*') if p.is_file() and p.name != '00-manifest.txt')
rows, total = [], 0
for p in files:
    size = p.stat().st_size
    total += size
    rows.append((str(p.relative_to(PKG)).replace('\\', '/'), size, sha256(p)))

lines = [
    '=== W10-DELIVERABLES package index ===',
    'graphd_revision=' + REVISION,
    'measured_binary_sha256=5c92ab426313a3beb407310d317b56938296b85619ac969808e97c90452da36d',
    'project=agmws-license-management-netcore @ 24410f3665447a7555c711e8aafe74f4c0f0ced7',
    'generation=1d7891525f028ecff06a6b8d7a8ac8a4ee3b31cc8067f1431e900b0cf7cdf6f7',
    'files=%d total_bytes=%d' % (len(rows), total),
    'NOTE: home-e2e/** and home-mcp/** are transient AXIOM_HOME scratch rebuilt by run_e2e.ps1;',
    '      their lock/sqlite bytes are listed for completeness but are not part of the evidence.',
    '',
    'relative_path\tsize_bytes\tsha256',
]
for rel, size, digest in rows:
    lines.append('%s\t%d\t%s' % (rel, size, digest))
OUT.write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('indexed %d files, %d bytes' % (len(rows), total))
