# Development — axiom-graphd

## Pinned governance

The canonical workflow is Development.md in `axiom-specs` at the exact revision in `spec.lock.json`. A missing or unverified pin blocks implementation; do not treat `spec.lock.example.json` as valid authorization.

## Before work

Read the selected task and contracts, verify completed dependencies, claim a single owner, record branch/base revision/dirty tree, explicit commit and push authority, allowed files and tests. Preserve unrelated changes. A–G letters do not override task `repo` ownership.

## During work

Implement one bounded task; coordinate public changes through spec ADR/RFC first. Include positive, negative and failure-boundary tests. Native behavior must not depend on Bash, WSL, Docker, administrator privileges or symlinks. Executable launches use program and argv, not an interpolated shell string. Bootstrap and migration require a reviewed plan and ownership-aware application.

## Completion

Attach real test output/hashes, acceptance mapping, changed-file review, compatibility and rollback notes, updated local docs and Changelog.md. Record actual platform coverage and unrun tests. Complete the canonical six preflight and eight completion checks; spec tooling validates evidence consistency, but independent CI reruns remain required.

## Branch/release policy

Canonical policy: `Development.md` §3 (`Branch/worktree policy`) ใน `axiom-specs` ณ revision ที่ `spec.lock.json` pin ไว้

| Branch | ใช้สำหรับ | การรวม |
| --- | --- | --- |
| `main` | integration branch ของงานพัฒนา | merge จาก task branch ที่ผ่าน merge gate; ห้าม push implementation commit ตรงเข้า `main` |
| `feature/<task-id>-<slug>` | task branch ต่อหนึ่ง bounded task | merge เข้า `main` เมื่อผ่าน merge gate; PR เมื่อ repo ต้องมี reviewer |
| `release/vX.Y.Z` | release candidate, stabilization และจุดออก release | เฉพาะ release authority; ห้าม merge เข้า release branch เอง |

ไม่สร้างหรือใช้ `develop` ใน repository นี้

### Merge gate

Agent MAY merge task branch เข้า `main` ได้เองโดยไม่ต้องขอ authorization เพิ่มเติม เมื่อครบทุกข้อ:

1. task status เป็น `done` และ ledger ตรงกับ card;
2. acceptance ครบทุกข้อ พร้อม command evidence จริง;
3. required checks ของ repository ผ่านจริง (format, lint, test, build) และบันทึกคำสั่งกับ exit code จริง;
4. final diff ถูก review แล้วว่าไม่หลุด scope และไม่รวม human-owned/unrelated changes;
5. `Changelog.md` และ local implementation docs ที่ได้รับผลถูกอัปเดตแล้ว;
6. ไม่มี blocker หรือ limitation ที่ยังไม่ถูกบันทึกใน evidence;
7. merge ไม่ทับงานที่ยังไม่ commit ของ checkout ที่เกี่ยวข้อง.

Agent MUST NOT merge เมื่อ task ยัง `in_progress`/`blocked`, evidence ไม่ครบ หรือ required checks ไม่ผ่าน/ยังไม่ได้รัน หรือ merge ก่อ conflict ที่ต้องตัดสินใจเชิง requirement/contract

หลัง merge MUST push `main` ขึ้น canonical remote และตรวจ remote SHA แล้วรายงาน merge commit SHA กับ main remote SHA ให้เจ้าของ workspace ทราบ

Merge เข้า `release/vX.Y.Z`, การ tag และ publish MUST มี release authorization ที่ระบุชัดเจนเสมอ ห้ามใช้ standing authorization แทน

### Worktree และ checkout หลัก

งานที่ทำใน worktree MUST NOT จบอยู่แค่ใน worktree เมื่อ task verified แล้ว MUST:

1. integrate เข้า `main` ตาม merge gate ข้างต้น; และ
2. อัปเดต checkout หลัก ที่ตรวจพบด้วย `git worktree list` ให้ตรงกับ branch ที่ integrate แล้ว เมื่อ working tree ของ checkout นั้นสะอาดพอ; หรือ
3. ถ้าทำไม่ได้เพราะมีงานที่ยังไม่ commit ของเจ้าของ checkout ให้ preserve งานนั้นไว้ และรายงานชัดเจนว่า checkout หลักยังไม่ได้รับงาน พร้อมขั้นตอนถัดไปที่เฉพาะเจาะจง

ห้ามรายงานว่างาน "เสร็จ" โดยไม่ระบุว่า checkout หลักได้งานแล้วหรือยัง

รายงานปิดงานของทุก task MUST ระบุ: task ID, branch, commit SHA, สถานะการ integrate เข้า `main` และ path ของ checkout หลักที่อัปเดตแล้ว

Daemon plus CLI share one core release; MCP and skills version independently. Documentation follows its component version. Do not invent a remote, push credentials or release version. No production action is authorized by copying this seed.

## K-302 Windows x64 core candidate

The Windows packager and verifier consume native MSVC x64 PE binaries, create
and inspect a deterministic ZIP archive, and refuse incompatible architecture or
manifest data. The owner candidate remains unsigned and unpublished. Runtime
graph/watch and installed consumer checks require their own native evidence.
The K-305 downstream correction uses the same K-302 owner branch to fix native
Windows uninstall planning. The original candidate remains historical evidence;
the corrected source and candidate require new immutable revision and hashes.

## K-308 Windows 0.1.2 core B candidate

The shared graphd daemon and engine CLI advance together to workspace version
`0.1.2` for K-306's native Windows A-to-B update test. The `0.1.1` corrected
K-302/K-305 candidate is immutable A. Build both native MSVC x64 executables
with the same committed `AXIOM_BUILD_REVISION`, then package and verify the
unsigned ZIP/SBOM with `release/package_core.py` and
`release/verify_core_candidate.py`. Record real-source graph/watch and refusal
evidence under `evidence/K-308/`. This local candidate carries no release,
signing or three-lane certification claim.
`Cargo.lock` has a fixed LF checkout so the SBOM byte hash reproduces from the
same commit on Windows. The manifest hashes the checked-out LF workspace bytes.

## K-309 Windows public service lifecycle candidate

The public graphd-owned `axiom service` runtime now dispatches Windows to its
per-user Task Scheduler adapter. It stores a separate Windows identity record
at the existing owned service-state path and verifies user SID, definition
bytes, exported scheduler task, and active generation before control/removal.
The daemon's explicit `serve --axiom-home` argv carries the approved user root
into a scheduler action without a shell wrapper or an ambient environment
override. Task Scheduler imports the exact UTF-16/BOM definition; a failed
registration cleans its own definition. The existing K-308 ZIP remains
historical; any K-309 core candidate requires a new committed source revision
and hashes. Native Task Scheduler, update/restart and rollback evidence gate
K-309 completion separately from unit checks and unsigned packaging.

## K-402 Linux x64 candidate handoff

`evidence/K-402/` contains the unsigned core `0.1.1` Linux x64 candidate,
manifest, SBOM, source graph fixture, and test outputs. The source revision and
binary digests are recorded in `candidate-manifest.json`; the fixture's
candidate and source identities are recorded in `real-source-report.json`.
Downstream CLI and MCP container work may use these as candidate inputs after
verifying their SHA-256 values. This handoff does not grant release or signing
authority. The local candidate check is independent of the parent K-005
four-lane release gate.
