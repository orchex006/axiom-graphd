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
