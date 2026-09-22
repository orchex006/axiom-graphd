# Native executable activation evidence

Host: macOS 26.6.2, x86_64. Engine worktree binary:
`target/debug/axiom` (`Mach-O 64-bit executable x86_64`).

The input fixture was copied from `<TEMP_ROOT>/release` into the
scoped temporary root `<TEMP_ROOT>`. Before planning, its
verified native payload was deliberately changed from mode `0644` and its
bundle declaration was set to `permissions: ["read", "execute"]`; the wheel
remained `permissions: ["read"]`.

```
PATH=<USER_HOME>/.local/share/uv/python/cpython-3.13.15-macos-x86_64-none/bin:$PATH \
AXIOM_HOME=<TEMP_ROOT>/home \
target/debug/axiom install plan --bundle <TEMP_ROOT>/bundle \
  --out <TEMP_ROOT>/plan.json --json
```

Exit `0`; plan digest:
`a7cfe2a4ec152b31baa26251b64929a73684da095e682d867905f0ae7f6939d7`.

The corresponding `install apply` command exited `0` with `status: installed`.
The installed payload at
`home/installs/ecosystem/versions/0.0.0-dev/bin/axiom-graphd` had mode `0755`
and ran successfully:

```
axiom-graphd version
{"component":"axiom-graphd","version":"0.1.0",...,"sqlite_version":"3.50.2",...}
```

The scoped temporary root is pending root-coordinated cleanup. This evidence is
local macOS x64 executable-mode proof only; it makes no release or certification
claim.
