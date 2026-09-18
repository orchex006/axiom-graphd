# SQLite, Self-managed Queue และ Incremental Reconciliation

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

## 1. Durable model

ไม่ใช้ externalmessagebroker. SQLite เก็บ pending intents, dirtygeneration, lease/fencing, retries, graphfacts, versions และ publicationoutbox. Memorychannel ทำหน้าที่ wake-up/scheduling hint เท่านั้น; daemonrestart ต้อง reconstruct งานที่ควรทำได้

SQLite ใช้ WAL บน localdisk, foreign_keys=ON, busy_timeout bounded, synchronous=FULL สำหรับ durablestate baseline. หนึ่ง writerconnection ต่อ instance; worker threads ส่งผลให้ writeractor. SQLiteWAL อนุญาต reader/writerconcurrency แต่ยังมี writer ได้ครั้งละหนึ่ง และไม่เหมาะกับ networkfilesystem [S02]

**Security/version baseline:** runtimeSQLite ต้องมี WAL-resetfix; baseline ยอมรับ 3.51.3 ขึ้นไปหรือ verifiedbackport ที่ระบุใน lock. ตรวจจริงด้วย sqlite_version()ไม่เดาจาก Rustcrateversion. SQLite ระบุ fix และ backports ในเอกสาร [S02]

## 2. Tables

`solutions`, `projects`, `files`, `symbols/nodes`, `edges`, `dirty_files`, `jobs`, `job_files`, `job_attempts`, `graph_revisions`, `publish_outbox`, `published_generations`, `catalog_refs`, `runtime_checkpoints`, `schema_migrations`, `audit_events`.

รายละเอียด DDL reference: `contracts/sqlite/schema-v1.sql`. DDL เป็น startingcontract สำหรับ implementation/migration ไม่ใช่แค่ documenttablelist; foreignkey/index/uniqueness ต้องผ่าน conformance

## 3. Dirty-file generation prevents lost updates

แต่ละ file มี `desired_generation`(เพิ่มเมื่อรับ changehint ที่ต้องตรวจ) และ `indexed_generation`(รุ่นที่ผล analysis อิงจริง). `dirty = desired_generation > indexed_generation` หรือ inventory/hashmissing/deleted;contenthashalone ไม่แทน queuegeneration

```text
A.cs changed → desired=41
worker claims target=41, reads bytes H41
A.cs changed again → desired=42
worker returns graph for H41
commit result: indexed=41, indexed_hash=H41
because desired=42, A.cs remains dirty
next batch analyzes generation42
```

ห้าม `DELETE dirty_files WHERE path=A.cs` แบบไม่เช็ก generation. ใช้ conditionalupdate/ack ที่ targetgeneration เท่านั้น. Lateworker ต้องถูก fencingtoken ปฏิเสธถ้า leaseexpired และ jobreclaimed

ไฟล์ถูกลบใช้ tombstone; worker จัดการ removeownednodes/edges พร้อม invalidateincomingreferences. Rename เป็น oldpathdelete+newpathcreate จน provenmapping ได้;case-onlyrename ทดสอบ Windows โดยเฉพาะ

## 4. Job state machine

`PENDING → LEASED → RUNNING → SUCCEEDED`

`RUNNING → RETRY_WAIT → PENDING`; `RUNNING → FAILED`; `PENDING/RUNNING → CANCEL_REQUESTED → CANCELLED`; `PENDING → SUPERSEDED`เฉพาะเมื่อมี newjob ครอบ scope และ generation เดิมครบจริง

Leaseclaim ใน `BEGIN IMMEDIATE` transaction; chooseeligiblejob, incrementattempt/fence, setleaseowner+deadline แล้ว commit. Do notholdDBtransaction ระหว่าง parse. Heartbeatextension ต้อง matchowner+fence;finishack ต้อง match ด้วย

ใช้ at-least-onceexecution + idempotentwrites ไม่อ้าง exactly-once. Dedupkey เป็น(workspaceinstance,jobkind,scope,profile)สำหรับ pendingcoalescing;runningjob ไม่โดน mutatetarget กลาง analysis;newdirtygeneration ไป nextbatch

## 5. Job types

InventoryScan, ParseBatch, ResolveAffected, PublishProject, PublishCatalog, CheckpointExport, VerifyCheckpoint, SnapshotGC, Repair. Mutation ประเภท bootstrap/update ไม่เอามาปน graphqueue;maintenancecoordinator สั่ง drain/pause ได้

## 6. Scheduling defaults

- Debounce750ms, maximumwait3s เพื่อไม่ starve ไฟล์ที่ save ต่อเนื่อง
- CPU workers = max(1,min(4,logical_cpu_count-1)); memory/inflightbudget ต้อง bounded
- Parser batch สูงสุด 64files หรือ 16MiBinputs; oversizedfilehandled ด้วย per-filelimit/report
- Priority: explicitcheckpoint/on-demandfresh > interactivechangedfiles > inventory > GC แต่มี aging ให้ lowpriority เดินได้
- RetrytransientI/O/lock5attempts: exponentialbackoff เริ่ม 250ms cap10s+jitter; parse/unsupportedsyntax ไม่ retry ถี่จนกว่าจะมี newinput
- Queuehighwater10,000distinctdirtypaths: persist`full_scan_required`แล้ว coalescememory;ไม่ dropstate แบบเงียบ
- Periodicinventoryevery5minutes ค่าเริ่มต้นปรับได้;startup/reconnect/overflow/branchchange บังคับ inventory

ตัวเลขเป็น proposeddefaults ต้องทดสอบตาม benchmarkprofile ห้ามกล่าวว่า processing จะเร็วเท่านี้แน่นอน

## 7. Reconciliation scope

Body-onlychange: reparsechangedfile และ replaceedges ของ owner; exporteddatasignature/import/referenceconfigchange:invalidate reverse dependencies ตาม exportfingerprint. `.csproj`,package/lockfile,tsconfig,Directory.Build.*,solutionmembership,annotations,routealias/configchange อาจ invalidate ทั้ง project หรือ solution อย่างมีเหตุผล

วิเคราะห์ incomingedges ช่วยหา affectedset แต่ graph เดิมอาจไม่รู้ newdependencies จึงต้อง scannewfile/importsymbols ด้วย. จำกัด depth ไม่ทำให้ semantics ครบ;หาก affectedclosure เกิน budget ให้ queuefullprojectreconcile และ reportpending ไม่หยุด closure แล้ว claimfresh

## 8. ensure_fresh / barrier semantics

On-demandrequestcapture `target_event_seq` +inputinventorybaseline. Success เมื่อ requiredscopeindexed ครบถึง barrier,publicationavailable,catalogvectorverified และ postvalidationfingerprint ไม่เปลี่ยนใน verificationwindow. Newchanges หลัง barrier ยังเกิดได้: report`verified_at`/snapshotid และ newdirtygeneration ตรงไปตรงมา

`--wait-timeout30s`หมดเวลา: returnpendingjobid/WORKTREE_BUSY ไม่ fakefresh. Querydefault`allow_stale`อ่าน snapshot ล่าสุดพร้อม status; `require_fresh`เรียก boundedreconcile ก่อน. Completionhook ไม่ควร blockingfullrebuild โดยไม่จำกัดเวลา

## 9. Filesystem recovery

Filewatcher เป็น hint ไม่ใช่ truth [S01]. เมื่อ daemon หยุดแล้วมีคนแก้ไฟล์ DB จะไม่รู้ currenthash ใหม่ startup ต้อง inventory จริง ไม่ใช่ query แค่`content_hash!=indexed_hash`จากข้อมูลเก่า

Inventory ต้อง detectnew/deletedfiles รวม untracked, exclusions, permissionerrors, symlinkpolicy และ dirtyconfig. `git diff HEAD~1`ไม่ครอบคลุม workingtree/untracked หรือ branchswitch โดยทั่วไป ใช้ explicitbase/target และ inventory ร่วมกัน

## 10. Shutdown/upgrade

Stopclaimnewwork → allowboundedgrace/markcancelrequest → flushdirty/outbox → closeconnections. Queueleaseleftbehind recover ได้. Upgradebackup ใช้ SQLiteBackupAPI/consistentbackup ไม่ copy เฉพาะ.db ขณะ WALactive; supporteddownmigration ไม่พร้อมต้องเก็บ oldDBbackup สำหรับ rollback [S02]
