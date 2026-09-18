# Static Analysis Coverage — V2

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

## 1. ไม่ต้องมี logs สำหรับ L3

V2 วิเคราะห์ source/config/manifests และ humanannotations ไม่รับ runtime logs/traces. Node/edge อธิบาย structural/staticpossible relationships ไม่ยืนยัน request วิ่งจริง การเพิ่ม RuntimeGraph เป็น V2+extension ที่ต้องแยก observededges

Core และ adapters เขียน Rust. ใช้ Tree-sitter สำหรับ syntaxincrementalparsing [S03] แต่ไม่ถือว่า syntaxparser ทำ compilerbinding ให้ครบ. ไม่มี mandatoryRoslyn/Nodehelper ใน V2. หากภายหลังเพิ่ม semanticcompilerbridges ให้ ADR/featureversion ระบุ dependencies และ trustboundaries ใหม่

## 2. Required V2 adapter profiles

| Profile | Required supported subset | ต้องรายงานไม่รองรับ/ไม่แน่ชัด |
|---|---|---|
| repository/project | files/folders, .csprojreferences, package.jsondependencies, Cargo.tomldependencies, solutionmembership | conditionalbuildscriptresults, dynamicworkspacegeneration |
| csharp-syntax | namespaces/types/interfaces/methodsignatures/properties/inheritance/using, lexical direct refs/calls | full overloadresolution, reflection, genericdispatch, runtimeDIselection |
| typescript-syntax | import/export, classes/interfaces/functions/methods, staticlocalreferences, alias/pathconfig ที่ resolve ได้ | runtimecomputedimports, decorators ที่ generatecode, fulltypeinference |
| aspnet-routes | Controller Route/Http*attributes, literalprefixes, basicliteralMapGet/MapPost/MapGroup | dynamicroutes, middlewareconditionals, generatedendpoints |
| angular-http | HttpClient.get/post/put/delete/patch กับ literal/allowlistedconstantservicebase และ routes | arbitrarytemplateexpressions/interceptorsrewrites/runtimeenv |
| sql-literals | literalSQL ที่จับ table/SP ได้, literalDapperCommandTypemapping, constantstoredprocname | dynamicSQL, arbitraryconcatenation, runtimequerybuilders |
| ef-static | explicit[Table] และ literalToTablemapping; entity-to-datastoreannotation | convention-onlymappingwithoutresolvedmodel, runtimefilters |
| messaging-config | literalpublish/subscribe/topicnames และ explicitannotations | runtimecomputedtopic/partition/routing |
| deployment-config | allowlistedservice/deployment/image/serviceport/configidentifierfields | Secretkind/.envvalues/credential-bearingurls |

L3adapters ใช้ patternregistryversioned พร้อม positive/negativefixtures ต่อ pattern ไม่ทำ regexscan ทั้ง file แล้ว claimsemanticaccuracy. Regex ใช้ได้เฉพาะ boundedliteralparsing หลัง ASTmatch

## 3. Resolution rules

Explicitprojectreference/import ที่ resolveunique ได้ → exact_static. Multiplecandidates → inferred_static+candidate set หรือ unresolved ตาม querypolicy;ไม่เลือกตัวแรก. DIregistration เป็น declaredbinding ไม่ใช่ runtimeguarantee. Callthroughinterface เก็บ interfacecall และ possibleimplementationedges แยกชนิด/attributes

API client/serverlink ต้อง servicealiasbinding จาก solutionconfig;ถ้า method/route เหมือนกันหลาย service ให้ ambiguousdiagnostic. SQLrelation ถ้าไม่รู้ datastorelogicalid ห้าม join ทุก database ที่มี table ชื่อเดียว

## 4. Parse errors and transient saves

Editor อาจเขียน file กลาง save;watcher ต้อง stable-read(stat/hash before/after)+boundedretry. Parseerror ไม่ crashdaemon. Retainlast-known-goodextract พร้อม `stale_for_file=true`หรือ publishpartialdiagnostic ตาม policy แต่ coverage/freshness ต้องเผยว่ามี error ไม่เอา oldgraph ไป claimfresh

Large/binary/invalidencodingfile ใช้ skipdiagnostic ตาม limits. Buildoutputs/sourcegeneratorsignoredbydefault;generatedsource ใช้ได้ถ้า explicitprofileallowlist และ trackedprovenance

## 5. Invalidation

Exported-symbolfingerprint/importset/routeidentity/tablemapping เปลี่ยนต้อง invalidatedependents. Removal ต้องล้าง incomingresolvededge และสร้าง unresolveddiagnostic ถ้า sourcecaller ยังอยู่. Newlyaddedreference ค้นผ่าน newparse ไม่อิง oldreverseedges อย่างเดียว

## 6. No source execution

ห้าม run`npm install`, `dotnet build`, shellplugins, project-definedscripts หรือ DBqueries เพื่อ discovergraph โดยอัตโนมัติ. Optionaltrustedbuildenrichment ต้อง explicitgrant และไม่อยู่ใน requiredV2

## 7. Acceptance and quality metrics

ต่อ adapter มี goldencorpus,expectednodes/edges,negatives,ambiguouscases,incremental-vs-full equivalence. Measureprecision/recall เฉพาะ declaredfixturecorpus และ unresolvedcoverage;ห้ามรายงาน 100%ทั้งภาษาจาก fixture เล็ก

V2release ต้องมี L1+L2syntax+C#API↔AngularHTTP+SQLliteralL3verticalslice ครบ ส่วน profile ที่ตารางระบุ required ต้องผ่านของตัวเองก่อนอ้างรองรับ profile นั้น;unsupportedprofiles ยังแสดงรายการชัดเจนไม่ fallbackLLM เดา
