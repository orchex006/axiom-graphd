# Full Ecosystem Operations Runbook

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

## Daily usage

Daemonwatching ทำงานต่อแม้ไม่มี Agent;human แก้ save แล้ว dirtyqueue เดินเอง. Agent ก่อนแก้ใช้ boundedgraphquery,หลังจบ batchreconcile/verify และ reviewimpact. Hook เป็น accelerator/boundarycheck ไม่แทน watcher/inventory

Default ไม่ publishGitcheckpoint ทุก save. Taskowner สร้าง checkpoint เมื่อจะ commit/share ตาม repo policy

## Operator states

| Observation | Diagnosis | Safe action |
|---|---|---|
| graphfresh แต่มี unresolved | analysiscoveragepartial ไม่ใช่ watcher เสีย | ดู coverage/provenance และ analyzerprofile |
| queuesize ขึ้นต่อ | editstorm/slowparser/poisonfile | inspectjob/limits;debounce;quarantinefailingfilewithdiagnostic |
| filechanged แต่ไม่มี event | nativewatcherlimit/unsupportedmount | forceinventory และ PollWatcherfallback;อย่าปิด freshnesschecks |
| daemonrestart แล้ว snapshot เก่า | recovery/inventory ยังไม่จบ | querystale โดยเปิดเผยหรือ waitbarrier |
| MCP401/403 | tokenaudience/scope/Origin/Host | regenerateconfiguredtokenreference;อย่า bind0.0.0.0 หรือ disableauth |
| MCProute404 | duplicatedmountprefix/protocolmismatch | doctor+MCPhandshaketest ไม่เปลี่ยนเป็น REST แทน |
| JSONchecksumerror | externaledit/corruptpublish/missingfile | keepoldvalidgeneration,reconcile,collectdiagnostics |
| WindowsPUBLISH_BLOCKED | sharingviolation/AV/openhandle | boundedretry;closeoffendingreader;neverdeletecurrentfirst |
| databasebusy | duplicatedaemon/longtransaction | ownership/leasecheck;inspectwriterqueue;notremoveDBlockbyguess |
| diskbudgetfull | retention/generationchurn | dry-runGC/unpinunusedsnapshot;neverdeleteactivevector |
| branchswitch | sourceepochchanged | rescan/invalidateoldjobs;waitnewcatalog |
| bootstrapconflict | humaneditedownedblock | showdiff/manualadoptionplan;preserveusertext |
| updateincompatible | schema/componentrangeconflict | choosecompatiblebundle/pinold;noautomajormigration |
| install prerequisite not ready (exit4) | one declared row is unsatisfied/unknown: interpreter,toolchain,runtime,hostexecutable หรือ permission | read the named `component/class` row and install that prerequisite per-user;neverrelaunchaselevatedortrytobypassbyeditingtheplan |
| install staging incomplete (exit6) | a planned payload is not staged or its bytes/byte-count differ from the approved plan | re-download and re-verify the bundle;suspectahand-editedstagingtree;nothingwaswritten |
| install already-installed (exit0) | every destination already holds the planned bytes | nothing to do;there-runrewritesnopointer,journalorrollbackrecord |
| install partially applied | the previous run stopped between components | re-run the same approved plan;onlythecomponentsnotyetinplaceareactivated,eachkeepsitsowntransactionandjournal |
| hooksloop | hookcontinuationwithoutnewwork | loopguard/circuitbreaker+surfaceblockedstate |

## Health/metrics

Metrics ขั้นต่ำ: daemonuptime; watchedroots/files; dirtyfiles; oldestdirtyage; pending/running/retry/failedjobs; queuewait/parse/resolve/publishlatency; publishfailures; snapshotbytes; GCbytes; SQLitebusy/WALsize; querylatency/returnedbytes/truncation; freshnessunknown/stalerequests; bootstrapconflicts; updatecheck/applyfailures

LogsstructuredJSONstderr/file,request_id/job_id/solution_id/project_id/schema/componentversion. Excludesecrets/sourcecontents/absolutepathsfromdefaultsupportbundle;redactiontestmandatory. Localdebugopt-inmayincludeidentifiedpathsbutnotcredentials

## Recovery

DBcorrupt: stopwriter,consistentbackupofforensics,quarantineDB,initializecleaninstance,inventoryallsourceandrebuild,validatepublishedsnapshots;neverclaimoldqueuedworkdonewithoutscan. SQLiteisreconstructableforgraphfactsbutrecoverpendingintentsandpolicyconfigurationfromregistry/journal

Snapshotcorrupt: keepknownvalidcatalog;rebuildfromsource;checkpointfilesinGitcanrestoreviareviewedGitoperationnotautorevertuserwork. Stagingorphancleanuponlyownednamespacedpathsandoutsideactiveoutbox

## Maintenance

Periodicinventory,boundedGC,WALcheckpointthroughsinglewriter,updatechecksifallowed,compatibilitydriftdoctorandbackupaudit. Noautomaticforce-updatesduringactiveparse/query/session. Hash/sourceconfigchangestriggerappropriateinvalidation

## Support bundle

Includeversionmatrix,OSfilesystemclass,configwithrootaliases,queue/statussummaries,failedtestids,recentredactedlogs,hashes/manifestmetadataandtraceids. Nofullsource/SQLite/tokenstoresbydefault. Userreviewsbundlebeforeupload;MCPdoesnotuploaditself
