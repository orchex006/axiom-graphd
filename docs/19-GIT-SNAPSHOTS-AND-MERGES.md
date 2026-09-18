# Git Snapshot / Merge / Checkpoint Policy

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

## 1. Two lanes under required project path

LiveJSON อยู่ใน projectfolder ตามข้อกำหนดและอัปเดตจาก daemon แต่ Git-ignore เพื่อไม่ให้ทุก save สร้าง trackedchanges. CheckpointJSON เป็น optionaltrackedartifact สำหรับ share ผ่าน Git สร้างด้วย explicitcheckpointcommand/taskpolicy ไม่ publish ทุก debounce

Tracked: solutionconfig/projectmetadata,annotations,policy/skillsbootstrap-ownedassets เมื่อ repo เลือก,checkpointcurrent+reachablegenerations.
Ignored: live/**,.staging/**,DB/WAL/SHM,queue/leases/locks,logs,credentials,localbindings,bootstrapbackups,temp และ performanceartifacts ที่ไม่ได้เลือกเก็บ

ตัวอย่าง `.gitattributes`กำหนด LF สำหรับ generatedJSON เท่านั้น;ห้าม bootstrap เปลี่ยน humanfiles ทั้งหมด. GeneratedJSON ทำ deterministicsort/sharding แล้ว diff ยังควร review;ไม่ใช้ binarySQLite เป็น mergeartifact

## 2. Checkpoint source selection

`--source staged`: materializeGitindex เป็น isolatedinputtree และ analyze จาก tree นั้น;includeonlystagedsourceplusversionedconfig ที่อยู่ index. ห้าม resetworkingtree/stash/uncommit. Symlinksubmodule/contentoutsideindex ต้อง explicitpolicy. Checkpointoutputs ไม่ included ใน inputfingerprint และไม่ execGitfilter โดยไม่ trustpolicy

`--source worktree --verify-stable`: sourceinventorybefore/after +dirtybarrier;หากเปลี่ยนระหว่าง export ให้ retry/WORKTREE_BUSY. Output ไม่รับประกันตรง stagedsource จน verify อีกครั้ง

`--source commit --ref SHA`: cleanCIcheckout/analyzerspinned;SHA เป็น inputselector ได้ แต่ portablegeneration ไม่ embedown-containingcommitSHA ให้เกิด self-reference

## 3. Commit procedure

เตรียม sourcechanges→stage เฉพาะงาน→createcheckpointfromstaged→stagecheckpointfiles→verifyfromstaged(ignoringgeneratedoutputs)→inspectdiff→commit. Precommithook เช็คได้แต่ host/gitconfig สามารถ bypass จึงต้อง CIverify ซ้ำ

ทุก repo ใน solution ทำขั้นตอนของตัวเอง;optionalcheckpoint-setmanifest เก็บ projectinputfingerprints/repoSHAs หลังมี commit แล้ว ไม่อ้าง crossrepoatomiccommit. CataloginGit อาจ refergeneration จากอีก repo ที่ยังไม่ push;releasecheck ต้อง verifysetcompleteness จาก remotecommitset ที่ specified

## 4. Merge procedure

Merge/rebase/cherry-picksource ก่อน→resolvehumanconfig/annotations→regeneratecheckpointfromresult→validatecatalogrefs→tests/CI. Textmerge สำเร็จไม่แปลว่า Graphsemantics ถูกต้อง

ห้าม merge=union สำหรับ nodes/edges เพื่อกลบ conflict;ห้าม choosetheirgraph ทั้งก้อนแล้ว claim ตรง source. Generatedconflict อาจใช้ remove/recreateownedoutputs ได้เมื่อ sourcefinal แล้วโดยไม่ลบ humanannotations

Graphdaemon ต้อง detectbranch/worktreeepochchange แล้ว invalidateoldjobs;Git อาจ modifygeneratedcheckpoint ขณะ MCPread ต้อง checksums+boundedretry/statusinvalid ไม่อ้าง filesystemguard ควบคุม Git ได้

## 5. Size budgets

เริ่ม warningcheckpoint>20MiB/project หรือ PRgenerateddiff>5MiB;hardstopdefault100MiB/project ที่ explicitoverride ได้พร้อม review. เป็น localproductbudget ไม่ใช่ GitHubuploadlimit หรือ benchmark. ให้ summaryprofile/reducededgeprojection หรือ artifactmode เมื่อเกิน budget ไม่แอบ omitrelations โดยไม่ coverageflag

Stablebuckets ลด unrelateddiff แต่ content-addressedgenerationdirectories ยังเกิด add/deletepaths;Gitobjectreuse อาจช่วยแต่ห้ามรับประกัน historysize. Storeonlycurrentreachablecheckpointgeneration ใน workingtree เมื่อ explicitprune;oldversions ยังอยู่ Git history. ไม่เก็บทุก livegeneration ใน Git

## 6. CI

Cleancheckout ของ PRmergeresult และ pinnedanalyzers→exporttoseparatetemp→comparecanonicalpayloadwithtrackedcheckpoint→verifycrossreporefs ที่ประกาศ available→failwithregenerateinstructions. CI ไม่ auto-pushfixes บน protectedbranch. Artifact-onlymode ยังเก็บ config+summary+fingerprint ใน Git และต้อง advertiseavailability/retention อย่างชัดเจน

## 7. Security

Generatedgraphs สามารถเผย architecture,privateendpoint/table/service names ได้ เก็บตาม repoaccesspolicy;ไม่ promotesnapshotpublic อัตโนมัติ. Connectionstrings/.env/tokenvalues ต้อง redact/skip ก่อน export ไม่หวัง secret-scan ทีหลังเพียงอย่างเดียว
