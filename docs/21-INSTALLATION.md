# Installation / Bootstrap / First Run

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

## 0. สถานะปัจจุบัน

แพ็กนี้เป็น spec พร้อม referenceutilities **ไม่มี axiom-graphd.exe,productionaxiom,MCPwheel หรือ GitHubrelease ให้ติดตั้งตอนนี้** ขั้นตอน A รันได้กับแพ็ก ขั้นตอน B–F เป็น runbook เป้าหมายที่ SpecE/D ต้องทำให้จริงและทดสอบก่อน release

## A. ใช้ specification pack วันนี้

Prerequisite: Python3.11+สำหรับ validator/reference ไม่ต้องติดตั้ง Rust/FastAPI เพื่ออ่าน spec

WindowsPowerShell:

```powershell
Expand-Archive .\axiom-graph-ecosystem-spec-v2.zip -DestinationPath .\graph-spec
Set-Location .\graph-spec\axiom-graph-ecosystem-spec-v2
python tools/specctl.py validate
python -m unittest discover -s tests -v
```

macOS/Linux:

```bash
unzip axiom-graph-ecosystem-spec-v2.zip -d graph-spec
cd graph-spec/axiom-graph-ecosystem-spec-v2
python3 tools/specctl.py validate
python3 -m unittest discover -s tests -v
```

ทดลอง bootstrapreference กับ explicitrepository ที่ผู้ใช้เลือก:

```bash
python reference/bootstrap_reference.py plan --repo /path/to/repo-a --repo /path/to/repo-b --out bootstrap-plan.json
# อ่าน plan/diff ก่อน ไม่มีไฟล์ project ถูกแก้ตอน plan
python reference/bootstrap_reference.py apply --plan bootstrap-plan.json --approve-digest <digest-from-plan>
```

บน Windows ใช้`--repo "C:\work\repo-a"`;ห้ามคัดลอก placeholder โดยไม่แทนค่า. Reference แก้เฉพาะ AGENTS.md+ownedpolicy/lock ไม่ติดตั้ง hostconfig/service และไม่ commit/push

## B. Runtime prerequisites หลังมี release

| User type | Prerequisites |
|---|---|
| Enduserprebuiltbundle | supportedOS/localdisk,Git ถ้าใช้ checkpoint,Pythonruntimecompatible ที่ bundle จัดให้หรือ installer ตรวจ;ไม่ต้อง Rusttoolchain |
| Developergraphd/axiom | pinnedRusttoolchain,Cargolock,platformlinker/buildtools,Git |
| DeveloperMCP | pinnedPython+environmentmanager,lockedFastAPI/MCPdependencies,Git |
| Integrationtester | above + exactCodex/Claude/Gemini/AGYversions ที่ได้รับสิทธิ์ใช้;ไม่ต้องเปิดทุก host พร้อมกันเพื่อ unit tests |

Watcher เป็น library ที่ compile เข้า Rustbinary และใช้ OSnotifications;ไม่ต้อง installOSFileWatcher แยก [S01]. SQLitebundled/pinned ใน Rustpackage เพื่อลด systemSQLiteversiondrift แต่ต้องตรวจ runtimeversion/fix ตาม queuecontract

## C. Install from verified release bundle

1. เลือก GitHubowner/repositories/trustroot จาก organization ที่ผู้ใช้กำหนดจริงและบันทึก trustedsourceconfig
2. ดาวน์โหลด bootstrapaxiomarchive ของ OS จาก trustedrelease,verifychecksum+signature กับ knownroot ก่อน execute;installer ต้องมี offlineverificationprocedure
3. `axiom install plan --bundle <verified-local-bundle> --out install-plan.json`
4. reviewcomponentversions,OSpaths,servicechanges,requiredpermissions และ plannednetworkaccess
5. `axiom install apply --plan install-plan.json`
6. `axiom version --all --json` และ `axiom doctor --all --json`

Defaultinstallper-user ไม่ admin;ห้ามใช้`curl|sh`เป็น defaultrunbook. Archive ต้องมี versioneddirectory;rollbackkeep อย่างน้อย previousworkingversion

## D. Define Solution / roots

คัดลอก`examples/config/solution.yaml`แล้วแก้ logicalprojectids/repoaliases. สร้าง localbindings จาก template แยก absolutecheckoutpaths. Registryconfig อยู่นอก Git โดย owner-onlyACL

```bash
axiom-graphd solution register --config solution.yaml --bindings bindings.json --dry-run
axiom-graphd solution register --config solution.yaml --bindings bindings.json --apply
axiom-graphd solution list --json
```

Dryrun แสดงทุก root/outputpath/excludedpath/profile/crossprojectalias และ collision;missingroot ไม่ autoclone. หากมีหลาย projects ใน repo เดียวต้อง define source_root/outputprojectid ไม่ให้ทับกัน

## E. Start daemon and gateway

Development/foreground:

```bash
axiom-graphd serve --registry <registry.json>
# อีก terminal หลังตั้ง scoped credentials แล้ว
axiom-mcp serve --registry <registry.json> --host 127.0.0.1 --port 8766
```

Manageduserprocess:

```bash
axiom service install --user --component axiom-graphd
axiom service install --user --component mcp
axiom service start --component axiom-graphd
axiom service start --component mcp
axiom service status --component axiom-graphd
```

Windowsadapter ใช้ per-userstartupmechanism ที่ทดสอบแล้ว(defaultScheduledTaskatlogon เป็น designchoice);Linuxsystemduserunit;macOSlaunchdagent. Implementation ต้องให้ logs/restartpolicy/stop/uninstall/testpermissiondenial ครบ. ไม่มี adminpermission ให้ใช้ foreground ไม่แก้ executionpolicy ทั้งเครื่อง

## F. Bootstrap projects / configure hosts

```bash
axiom host detect --json
axiom bootstrap plan --solution demo-solution --hosts codex,claude,gemini,agy --out bootstrap-plan.json
axiom bootstrap apply --plan bootstrap-plan.json
axiom bootstrap verify --solution demo-solution
```

ConfigureMCP ต้อง preserveexistingservers และใช้ env/credentialreference;ไม่ใส่ token ใน trackedprojectconfig. Templateexamples อยู่`examples/hosts/` เป็น shapeexamples ต้อง render ผ่าน certifiedadapter ของ installedversion ไม่ blindoverwritewholeconfig

## G. First index / human edit smoke test

```bash
axiom-graphd reconcile --solution demo-solution --scope full --wait --timeout 30s --json
axiom-graphd status --solution demo-solution --json
```

Firstindex อาจเกิน timeout ตาม size: command ต้องคืน jobid แล้วติดตาม`queue list`/jobstatus ไม่อ้าง failed ถ้ายัง processing และไม่รับประกันเสร็จภายใน 30s

เปิด VSCode แก้/savefixturemethod →ตรวจ dirtyseq/job →อ่าน newgeneration ผ่าน MCP →ตรวจ sourcefingerprint/coverage. ทำ rename/delete/untracked/SaveAll และ daemonrestartsmoketests ตาม conformance ก่อนใช้ productionrepos

## H. Offline/read-only mode

Validcheckpoint+trustedrootbindings+localcoordinationlock เพียงพอสำหรับ snapshotquery;ไม่ต้อง daemonalive. Freshnessunknown จน verify กับ source. Offlineinstall ใช้ signedbundle+cachedtrustedmetadata ที่ policy อนุญาตและ expiry ตรวจ;ไม่ network อย่างเงียบ

## I. Uninstall

Planremoveservices/runtimecomponents และ ownedbootstrapblocks แยกกัน. Defaultpreserveprojectsource,annotations,checkpointJSON และ userinstructions. Credentials revoke/securedelete ตาม OSpolicy;DBcachecleanup ต้อง explicitoption. เก็บ uninstallreport และไม่ removeotherhostplugins/MCPservers

## J. The `axiom` executable in this release (E-001)

`crates/axiom-cli` is the thin `axiom` binary and `crates/axiom` holds its reviewable behaviour. Both are members of this workspace and are built from the same locked toolchain and the same core version (`0.0.0-dev`) as `axiom-graphd`; `cargo build --locked` produces both executables. There is no separate CLI repository and no separate CLI release.

`axiom version --json` prints exactly one frozen `version-report.schema.json` object with `component: "axiom"` and the shared core version. `axiom version --all --json` prints exactly one object, `{"components": [...]}`, containing the frozen report of every component this build can report honestly (the daemon and the CLI). MCP, skills and pinned spec provenance are added by the work packages that implement their registry lookup.

Documented commands that a later work package implements (`install`, `service`, `bootstrap`, `host`, `skills`, `specs`, `update`, `doctor`, `support-bundle`, `migrate`) exit with the frozen `not ready/stale` code `4` and name the command, instead of being misreported as a typo. Unknown commands and invalid flags exit `2`; in `--json` mode the failure is one error envelope on stdout with the diagnostic on stderr.

## K. Update activation, doctor, rollback and release manifest (E-042 - E-048)

This slice is the half of an update that runs *after* a payload exists. It is
library behaviour in `crates/axiom` with no CLI verb wired yet, so `axiom update`,
`axiom doctor` and `axiom support-bundle` still exit with the frozen
`not ready/stale` code `4` and name the command; what follows is what the modules
already guarantee for the command work package that binds them.

- **Activation (`update/rust_binary.rs`, `update/python_env.rs`)** stages each
  version into its own directory and activates it by moving a pointer, never by
  replacing the executable or environment that is currently running. A payload
  that is missing, whose bytes do not match the staged digest, that was never
  smoke checked, or whose version is not one safe path segment is refused; the
  pointer is written as a temporary sibling and renamed, so a refused activation
  leaves the previous pointer exactly as it was.
- **Doctor (`update/verify.rs`)** probes health, handshake, graph/queue schema and
  a fixture query. A non-2xx status, an unexpected document, a protocol or
  version mismatch, a missing capability, a schema mismatch, a transport error or
  a body past the bound produces a *bounded* rollback with named rules instead of
  a superficial success, and the expected protocol/schema set is derived from
  `crate::version` rather than guessed.
- **Rollback (`update/rollback.rs`)** rolls the binary, the database schema and
  the policy back as one compatible set. A downgrade that the release set,
  migrations or the policy floor make `Irreversible` or `Missing` is blocked with
  a named reason, a partial scope is refused, and a plan may claim to restore one
  set only when it also restores the compatible backup that set depends on.
- **Update policy (`update/policy.rs`)** defaults to explicit approval. Auto-apply
  is reachable only with an opt-in compatible-patch policy, a strictly newer patch
  on an allowed channel, no crossed boundary (minor/major version, schema
  migration, security advisory, trust root change, host config rewrite) and every
  readiness condition present (idle window, drain, verified signed bundle, backup
  plus rollback, scope grants). A prerelease never auto-applies, and every gate
  that forced approval is named.
- **Support bundle (`support.rs`)** accepts only allowlisted diagnostics, refuses
  absolute/UNC/traversing names, secret-shaped file names, non-portable
  destinations and source-body or private-key content, scrubs every body before
  hashing it, and renders a manifest (name, size, SHA-256, redacted flag) that a
  user can inspect before anything is written.
- **Release manifest (`release/core-manifest.json`, `tests/core_manifest.py`)**
  declares one core release containing both `axiom-graphd` and `axiom` from one
  workspace version and revision, with no separate bootstrap component, and
  records the real SHA-256 of `Cargo.toml` and `Cargo.lock` plus the declared
  targets and compatibility set. The harness re-reads those files and reports
  signing, tagging, publishing, archive/SBOM hashing and clean-user installation
  evidence as `not_run`: the release gate is closed for this workstream (the
  revision is `unpinned`, the state is `not_published`), and nothing here claims a
  released or signed artifact. Each target additionally declares its provenance (the release revision and both components at the release version, so an archive cannot be declared after one of them moved), its executable metadata (`.exe` on Windows, `0755` on POSIX) and its installation evidence, which is either a real command, output and digest or an honest `not_run` with the command it would run and the reason and no digest (V2-021).

Native Windows activation of a running image is the one leg that cannot be proven
on this host: a running executable cannot be replaced on Windows, which is why
activation is a pointer move, and the native `BinaryActivation` evidence is
recorded as `not_run` rather than invented.

## L. Ecosystem prerequisite probe and one-command install (I-004)

`crates/axiom/src/install/ecosystem.rs` owns the *ecosystem* view of an
installation, and the `axiom` entrypoint composes it (task I-004):
`axiom install plan --bundle <verified-local-bundle> [--out install-plan.json]
[--json]` probes and writes one plan, and `axiom install apply --plan <file>
--approve-digest <sha256> [--json]` re-verifies and applies it. Applying at a
digest other than the one the plan was approved at, or omitting
`--approve-digest`, is `FORBIDDEN` with code `5`, exactly as section 6 of the
installation contract requires; a bare `axiom install` is a
`VALIDATION_ERROR` with code `2` because these forms require a subcommand. The
binding delegates to the module rather than re-implementing it - it resolves the
install root from the resolved `AXIOM_HOME`, probes through the host probe and
stages the declared payloads - and it invents no second digest or encoder. What
the module guarantees:

- **Probe before write.** `plan_ecosystem` probes all thirteen declared
  `(component, class)` rows — interpreter, toolchain, runtime, native dependency,
  host executable, permission and approval, for `axiom-graphd`, `axiom-mcp` and
  `axiom-skills` — and reports each as `satisfied`, `unsatisfied` or `unknown`
  before it opens the bundle. A required row that is unsatisfied or unknown
  refuses with exit code `4` (`ErrorCode::NotReady`, rule
  `prerequisite-unsatisfied`) naming every blocking row. `unknown` is never
  treated as satisfied.
- **Declared, never invented.** A row the owning repository declares as
  `undeclared` — the patched SQLite runtime, whose baseline is rendered from
  `graph_store::open::MIN_SQLITE_VERSION` rather than copied — is reported and
  recorded in `verification_gaps`. The store's own runtime gate stays the
  enforcement point, and no pin is invented where the contract declares none.
- **One plan, one digest, contract order.** The plan carries one sealed
  component plan per contract position (`axiom-graphd`, `axiom-mcp`,
  `axiom-skills`) behind a single approval digest. `apply_ecosystem` re-verifies
  every component digest, the contract order and positions, the per-component
  activation digests and the recorded prerequisite rows before it writes a byte.
  A bundle that omits a core component, or declares a component with no contract
  position, is refused by name (`component-missing`, `component-order`) rather
  than silently dropped.
- **Exit codes.** `0` for a successful apply and for an already-installed re-run,
  `4` when a required prerequisite is not ready, `5` when the plan is not
  approved at the digest it is applied at, `6` when a planned payload is not
  staged as the plan declared. The exit-code table in `CLI-EXIT-CODES.md` is
  unchanged: the module reports through the existing `ErrorCode` mapping.
- **Idempotent re-run.** A re-run whose destinations already hold the planned
  bytes reports `already-installed` and moves nothing — no payload, pointer,
  journal entry or rollback record is rewritten, and a consumed staging tree
  never blocks it. An interrupted or partially applied installation resumes at
  component granularity: only the components whose bytes are not in place are
  activated.
- **Engine boundaries preserved.** Activation goes through the existing update
  engine (`install::apply`), so each component keeps its own transaction
  identifier, journal entry and rollback record, the versioned directory plus
  pointer layout and the byte-equality rollback boundary that a later human edit
  survives.
- **Never required.** The plan is per-user, requests no `elevated` permission and
  launches programs as program plus argv rather than an interpolated shell
  string. A foreground install requires no WSL, Docker, Bash, Node.js, elevation
  or system service.

Evidence status for this slice: Windows 11 x64 native is the primary verified
leg (unit tests, the real probe over the local search path, and native
positive/negative/partially-applied runs). The Linux leg is now executed for
real too: a Rust toolchain was provisioned in the WSL2 Ubuntu 26.04.1 LTS distro
(`x86_64-unknown-linux-gnu`, the workspace's pinned `1.85.0` channel), where the
same 31 in-module tests pass and the operator surface was driven with the
Linux-built binary. The host facts observed there are unchanged (Ubuntu 26.04.1
LTS, glibc 2.43, `python3` 3.14.4 - outside the declared `>=3.13,<3.14` range -
and no `python`), which is exactly why the refused-prerequisite leg reproduces
there. No macOS host exists in the environment, so the Apple rows stay `not_run`.

The composed operator surface is exercised with real runs on both hosts:
`axiom install plan` exits `0` and writes one plan (thirteen prerequisite rows,
one sealed component plan per contract position in contract order, one approval
digest), `axiom install apply --plan ... --approve-digest ...` exits `0` with
`status=installed`, the idempotent re-run exits `0` with
`status=already-installed` and moves no bytes, a refused prerequisite exits `4`
naming every blocking `(component, class)` row before any write, a stale or
absent approval digest exits `5`, and a bare `axiom install` exits `2`. The
installation mechanism itself requires no WSL, Docker, Bash, elevation or system
service; WSL2 was used only as the Linux test host, and every generated plan
requests no elevation.
