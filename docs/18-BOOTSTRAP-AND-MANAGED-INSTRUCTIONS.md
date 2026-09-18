# Bootstrap / Managed AGENTS.md / Multi-repo Updates

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

## 1. Owned content layout

แต่ละ repository มี canonicalpolicy ที่ `.axiom/agent/POLICY.md` และ `bootstrap.lock.json`;AGENTS.md มี smallmanagedblock ชี้ไป policy. Policy อธิบาย graphusage ไม่ใส่ fullspec/ทุก toolcatalog จน context โต

```markdown
<!-- axiom-graph:begin -->
## Axiom code graph
Before changing code, explicitly read `.axiom/agent/POLICY.md`.
Use scoped graph queries; do not manually edit generated graph JSON.
Before reporting completion, reconcile/verify the affected scope and report
freshness, coverage and evidence. If unavailable, report it; never claim fresh.
<!-- axiom-graph:end -->
```

Hyperlink/pointer ไม่ใช่ automaticincludecontract ของทุก host จึงมี explicitreadinstruction และ criticalrules ใน block. หาก higher-priority/nestedhostinstruction ขัดกันต้อง report ไม่ overwrite เพื่อให้ graph มีอำนาจมากกว่า

## 2. Host adapters

Codex: AGENTS.md + skilldirectory ที่ host รุ่นนั้นรองรับ + MCPconfigadapter.
ClaudeCode: CLAUDE.mdmanagedpointer,skill/nativepluginlayout และ hooksettings เฉพาะรุ่น.
GeminiCLI: GEMINI.mdmanagedpointer,extension/skills/config ตาม version.
AGY/Antigravity: `.agents/rules`/`.agents/skills`เป็น documentedcurrentpaths แต่เก่ามี`.agent`compatibility;MCPserverUrl ต่างจาก GeminihttpUrl [S13][S14][S15]. ต้อง detectversion และไม่เขียนทั้งสองโดยไม่มี migrationplan

CanonicalSKILL.md เก็บ repoA;axiommaterializeversionedcopy ใต้ hostlocation. Datafiles ไม่ selfexecute; `axiom skills update...`ทำ actualupdate. ไม่ symlink เป็น default เพราะ Windowsprivilege และ Gitportability;ใช้ copieswithhashmanifest

## 3. Plan contract

`bootstrap plan`อ่าน explicitregisteredsolution และ targethosts สร้าง per-repooperations, beforefilehashes, managedblockhashes, templateversion/hash, destinationrelativepaths, changeclassification, proposedgitdiff, policyconfig และ planSHA256.

Plan ไม่แก้ files. เมื่อ apply ต้องอ่าน approvedplanexactdigest,verifyrootbindings/ownership/beforehashes อีกครั้งและ rejectexpired/staleplan. Pathcanonicalization ต้อง reject..,absolutepaths,symlinkescape/casecollision. NoautodiscoveryrewriteallHOMErepositories

## 4. Managed merge algorithm

- AGENTS.md ไม่มี: createownedsection และ preserveencodingpolicy
- มีไฟล์แต่ไม่มี markers: appendsection โดยเก็บทุก byte เดิมนอก section;existinghumantext ต้องไม่ reformat
- มี markers คู่เดียวและ blockhash ตรง lastapplied: replace เฉพาะ block ด้วย newtemplate
- มี markers แต่ไม่มี ownershipmanifest: adoption ต้อง explicitplan/approval ไม่ assumeowned
- duplicate/missing/nestedmarkers หรือ humaneditinsideownedblock: reportCONFLICT;ไม่ overwrite หรือ silentlyappendsecondblock
- Canonicalpolicyfile ที่ generated ทั้งไฟล์ใช้ lastappliedfilehash: editedfile ต้อง conflict หรือ manualadoption แยก `POLICY.local.md` สำหรับ humanoverrides ที่ policyreference ชัดเจน

CRLF/LF/BOM/no-final-newline ต้อง preserveoutsideblock และ recordencoding;ห้ามเปลี่ยนทั้ง repo เป็น LF ขณะ bootstrap. Markdowncodefences ที่มี marker ตัวอย่างต้องไม่ถูกมองเป็นจริงโดย parser;managedsectiondetector ต้อง testfencecontext

## 5. Apply/journal and rollback

Takeper-repobootstraplock → recheckbeforehashes → backupaffectedbytesinAXIOM_HOME → writejournalintent → atomicwriteownedfiles/configfragments → verifyoutsidecontenthashes → updatebootstrap.lock เป็น laststep → markjournalcomplete

หลายไฟล์ใน repo ไม่ใช่ atomicfilesystemtransaction;journalrecovery ต้อง handlehalfapply. หลาย repo ยิ่งไม่ atomic: plan+apply ราย repo,aggregate ผล success/conflict/blocked;defaultcontinueunaffectedrepos พร้อม nonzeroexit20. ห้าม claimallreposupdated จากบาง repo สำเร็จ

Rollbackrestore เฉพาะเมื่อ currenthash ยังตรง afterhash ที่ installer เขียน;หากผู้ใช้แก้ต่อให้ conflict และเก็บ backup ไม่ overwriteuserwork เพื่อ rollback

## 6. Scope of commit/push

Bootstrapdefault ไม่ commit/push เอง; `--commit`/`--push`เป็น explicitoptions ที่ต้อง authorizedrepo+branch+remote ใน plan. Commitstage เฉพาะ ownedchangedpaths และ checkno-secrets. Repo ที่มี unrelateddirtyfiles สามารถ plan ได้แต่ apply ต้อง preservethem;หากทับ path เดียวกันให้ skiprepo ไม่ stash

## 7. Updating all repositories

Templateversion ใหม่→`axiom bootstrap update plan --solution demo-solution --to x.y.z`→per-repodiff→applyapprovedplan→verifyownership/hostcapability→reportold/newversion และ remainingrepos→ผู้ใช้ review/authorizedpush

Updatingcentralpolicy ไม่ทำให้ copies ทุก repo ใหม่เองโดย magic ต้องมี actualsynccommand หรือ opt-inscheduledmaintenance. Skills/MCP/axiom-graphd ทุกตัว reportinstalledandavailableversions แยกกัน

## 8. Uninstall

Removeownedblock/ownedfiles เฉพาะเมื่อ unchangedhash. Preserveallhumantext,unknownconfigkeys,otherMCPservers/skills/hooks. ไม่ deleteAGENTS.md ทั้งไฟล์ถ้ามี usertext;ไม่ deleteprojectgraphcheckpoints โดยไม่ได้ระบุ cleanup

## 9. Reference included in this pack

`reference/bootstrap_reference.py` เป็น offlinebehaviorreference ที่ใช้ Pythonstdlib เพื่อให้ทดลอง managedAGENTS.md หลาย repo ได้ก่อน Rustaxiom. รองรับ AGENTS.md+canonicalpolicy+ownershiplock,plan/apply,beforehashes และ unitfixtures ตาม READMEreference;ไม่ใช่ productionhostconfig/updater หรือ graphengine และไม่แทนงาน SpecE
