# W10-DELIVERABLES : graphd graph-query : คู่มือเล่นจริง + หลักฐานจริง

**lane:** `W10-DELIVERABLES` (subagent)  **branch:** `feature/w10-deliverables`
**วัดที่ revision:** `axiom-graphd` **`51782bb4337799b8479de1ea2ce4f29e1bbd038d`**
**ไบนารีที่ใช้:** `target\release\axiom-graphd.exe`
`sha256 = 5c92ab426313a3beb407310d317b56938296b85619ac969808e97c90452da36d` (RELEASE, ไม่ใช่ DEBUG)
**โปรเจกต์ทดสอบ:** `D:\SP-Billy\axiom\agmws-license-management-netcore`
branch `feature/graphd` @ `24410f3665447a7555c711e8aafe74f4c0f0ced7`
**generation ที่ใช้อ้างอิง:** `1d7891525f028ecff06a6b8d7a8ac8a4ee3b31cc8067f1431e900b0cf7cdf6f7`

> เอกสารนี้เขียนให้ "กดตามได้จริง" ทุกข้อ: มี **คำสั่งที่ copy ไปวางได้เลย**,
> **ผลลัพธ์ที่ต้องเห็น**, และ **revision/digest ที่วัดมา** กำกับทุกตัวเลข
> ทุกตัวเลขในนี้มาจาก output จริงใน `evidence\` ไม่มีการปั้นแต่ง
> ถ้าตัวเลขไหนวัดซ้ำแล้วไม่ตรงกับที่เลนก่อนหน้าเคยรายงาน ผม **บันทึกการแก้ไว้ตรง ๆ** (ดูข้อ 5)

---

## 0. เตรียมก่อนเริ่ม (ทำครั้งเดียว)

ตัวแปรที่ใช้ทั้งเอกสาร (วางทีละบล็อกใน PowerShell 7):

```powershell
$WT   = 'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final'
$PKG  = Join-Path $WT '_w10final'
$BIN  = Join-Path $WT 'target\release\axiom-graphd.exe'
$REPO = 'D:\SP-Billy\axiom\agmws-license-management-netcore'
$GW   = Join-Path $REPO '.axiom\graph\agmws-license\agmws-web-service'
$MCP  = 'D:\SP-Billy\axiom\axiom-mcp'
```

ตรวจว่าไบนารีตรงกับที่ผมวัด (ต้องได้ hash นี้เป๊ะ):

```powershell
(Get-FileHash $BIN -Algorithm SHA256).Hash.ToLower()
# คาดหวัง: 5c92ab426313a3beb407310d317b56938296b85619ac969808e97c90452da36d
git -C $WT rev-parse HEAD
# คาดหวัง: 51782bb4337799b8479de1ea2ce4f29e1bbd038d
```

ถ้าต้อง build ใหม่เอง:

```powershell
cd $WT; cargo build --release --locked
```

**หมายเหตุสำคัญเรื่อง "ห้ามแตะ"** — โปรเจกต์เป้าหมายมีแค่ `?? .axiom/` ที่เป็น scratch
(ไม่ track) ทั้งเลนนี้ **ไม่ commit อะไรลงโปรเจกต์เป้าหมายเลย** ทุกอย่างที่เขียนลงไป
คือโฟลเดอร์ `.axiom\` ซึ่งสร้างใหม่ได้จาก `serve`

---

## 1. ไฟล์ผลลัพธ์ analysis ที่ MCP ใช้ตอบคำถามความสัมพันธ์

**คืออะไร:** generation ที่ publish ลงโปรเจกต์ ประกอบด้วย `manifest.json` + `nodes/` + `edges/` + `coverage.json`
นี่คือไฟล์ที่ MCP อ่านจริงเพื่อตอบคำถาม (ไม่ใช่ตัว index SQLite ภายใน)

**ดูของจริง:**

```powershell
Get-ChildItem -Recurse -Force (Join-Path $GW 'live') -File |
  ForEach-Object { $_.FullName.Replace("$GW\",'') + '  bytes=' + $_.Length }
```

**ต้องเห็น (จริง ณ revision นี้):**

```
live\current.json  bytes=189
live\generations\1d7891...df6f7\coverage.json  bytes=126
live\generations\1d7891...df6f7\manifest.json  bytes=1090
live\generations\1d7891...df6f7\edges\000000.json  bytes=624413
live\generations\1d7891...df6f7\nodes\000000.json  bytes=597010
```

**digest ที่ตรึงไว้** (ตรวจด้วย `Get-FileHash -Algorithm SHA256`):

| ไฟล์ | bytes | sha256 |
|---|---|---|
| `nodes\000000.json` | 597010 | `0fc1039146ad693462f1add68449e9581e7c72d1e2849e4029d6b3ccf00fed26` |
| `edges\000000.json` | 624413 | `8117ddd68d3b3734391cc1bcda95f08ce1e5d38b94caee856c71743a8c9b0aad` |
| `coverage.json` | 126 | `518b83780b44a93bee4e34ddb1f3bf8025687cba8740717b22b4f97b1f219317` |
| `live\current.json` | 189 | `0a8006210f4b16ef64a43db79ea50414e0c9c09369f88ca37f0160edc223f612` |
| `manifest.json` | 1090 | `1d7891525f...df6f7` (เท่ากับ generation id เป๊ะ) |

**ข้อเท็จจริงที่พิสูจน์ได้:** `sha256(manifest.json) == generation_id` ใน `current.json`
(ยืนยันใน `evidence\05b-manifest-identity.txt` → `manifest_equals_generation_id=True`)

**ไฟล์ contract ถูกต้องตามสเปคจริงไหม?** ตรวจด้วย evaluator ตัวจริงของฝั่ง specs
(`axiom-specs\tools\graph_contract.py` — ผม **copy** มาที่ `scripts\graph_contract.py`
เพื่อไม่ให้เขียนอะไรลง axiom-specs เลย):

```powershell
python (Join-Path $PKG 'scripts\check_contract.py') `
  --generation (Join-Path $GW 'live\generations\1d7891525f028ecff06a6b8d7a8ac8a4ee3b31cc8067f1431e900b0cf7cdf6f7') `
  --out (Join-Path $PKG 'evidence\07b-contract-combined.json')
```

**ต้องเห็น:** `"ok": true`, `"nodes_total": 1368`, `"edges_total": 1213`, `"reasons": []`, exit code `0`
(ตัว evaluator ตัวจริง: `axiom-specs\tools\graph_contract.py` `sha256=429d01b8b1311efa87884211b2b1447dc212451beaac16566e3eb5ebe9d90cfb`)

---

## 2. `result.html` : เห็น graph ความสัมพันธ์

```powershell
& $BIN render --solution agmws-license --project agmws-web-service `
  --out (Join-Path $PKG 'evidence\render') --json
```

**ต้องเห็น:** exit `0`, wall ~127-351 ms, แล้วได้ 2 ไฟล์
- `evidence\render\result.html` — **919717 bytes**
  `sha256 = ea3f4bd2dc248c2525eeeea114ca405f0b7d6e9dbe74955d5d60d018dc6c2bee`
- `evidence\render\summary.json` — 1295279 bytes

**เปิดดู:**

```powershell
Invoke-Item (Join-Path $PKG 'evidence\render\result.html')
```

ข้างใน `summary.json` มี banner บอกความน่าเชื่อถือของภาพ:
`coverage.status=complete_for_profile` (`input_files=156`, `processed_files=156`,
`unresolved_references=0`) และ `freshness.status=fresh` (`dirty_files=0`,
`verification=inventory_hash`), counts `nodes=1368 edges=1213 shards=3 records=2582`

---

## 3. ตัวอย่างการใช้งานจริง: "ถาม AI แล้ว AI ไปถาม graph ผ่าน MCP"

### 3.1 ความจริงที่ต้องบอกก่อน (สำคัญ)

`axiom-mcp` ที่ revision นี้ **ไม่มี entry point ที่ประกอบ MCP server ให้พร้อมใช้**
(`axiom_mcp.stdio.build_stdio_server()` คืน `FastMCP` ที่ **ไม่มี tool เลย** และไม่มีโมดูลไหน
เอา `TOOL_SPECS` มาติดตั้งลง server) ผมจึงเขียน `scripts\mcp_stdio_host.py` ที่ทำหน้าที่นั้น
โดย**ใช้ของจริงจาก package**: catalog descriptors (`axiom_mcp.tools.catalog.TOOL_SPECS`),
handler ที่ ship มา (`axiom_mcp.tools.*`), และ transport ที่ ship มา (`stdio.serve_stdio`)

> แปลว่า: graph data plane + tool handlers เป็นของจริงทั้งหมดที่มีใน `axiom-mcp`
> แต่ "ตัวประกอบ server" เป็นโค้ดของเลนนี้ ~120 บรรทัด **อย่าเขียนรายงานว่า
> 'ไบนารี MCP ที่ ship อยู่ตอบ graph_query ได้เอง'** เพราะยังไม่จริง

### 3.2 รัน demo (สร้าง home + ยิงคำถามจริง 3 ข้อ)

```powershell
python (Join-Path $PKG 'scripts\make_homemcp.py') --home (Join-Path $PKG 'home-mcp') --repo $REPO --project-path '.'
# คาดหวัง JSON มี lane_root_exists: true

python (Join-Path $PKG 'scripts\mcp_stdio_client.py') `
  --host-script (Join-Path $PKG 'scripts\mcp_stdio_host.py') `
  --mcp-src (Join-Path $MCP 'src') `
  --home (Join-Path $PKG 'home-mcp') `
  --calls (Join-Path $PKG 'scripts\demo-calls.json') `
  --transcript (Join-Path $PKG 'evidence\06-mcp-transcript.txt') `
  --results (Join-Path $PKG 'evidence\06-mcp-results.json') `
  --pretty-results (Join-Path $PKG 'evidence\06-mcp-answers.txt')
```

**ต้องเห็น:** exit `0` และใน `evidence\06-mcp-answers.txt`:

- server โฆษณา 2 tools พร้อม annotation read-only:
  `graph_status` และ `graph_query`
  `annotations={"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}`
- **call 1** `graph_status` → `lane=live`,
  `generation_id=1d7891525f...df6f7`, `records=2582`,
  `coverage=complete_for_profile`, `verification=manifest_hash`,
  `catalog_generation_id=4869b499eb6ef4328c5e61f53149b7278b9a3f7a6930cfa209bc76742dcdca55`,
  `capabilities={read:true, reconcile:false, checkpoint:false}`, `freshness=unknown`
- **call 2** `graph_query operation=context target=...DateTimeExtensions`
  → **7 nodes / 6 edges** และมี symbol จริงนี้อยู่ข้างใน:

```
"kind": "Method",
"name": "ToUnixTimeStamp",
"qualified_name": "AgriMap.Web.Service.Shared.Extensions.DateTimeExtensions.ToUnixTimeStamp",
"language": "csharp",
"identity_quality": "semantic_key",
"source": { "file": "Src/Shared/Extensions/DateTimeExtensions.cs", "start_line": 26, "end_line": 26 }
```

  พร้อม edge ชนิด `CONTAINS` ที่มี `rule_id=declaration-contains-v1`,
  `analyzer_id=csharp-declarations-v1`, `resolution=exact_static`
  → คือ **typed relationship จริง + file:line จริง** ไม่ใช่ text hit
- **call 3** `graph_query operation=neighbors target=...ToUnixTimeStamp` → 7 nodes / 6 edges

เทียบกับเลนไม่มี graph: `evidence\10-baseline-scan.out` สแกน 156 ไฟล์ ได้แค่
`member_count=5` เป็น text ล้วน — **ไม่มี node id, kind, edge, resolution, evidence**

> หมายเหตุความแม่นของเวลา: `mcp_stdio_client.py` เก็บผลด้วย poll ทุก 20 ms
> เวลาต่อคำถามจึงถูกปัดเป็นช่วง ~20 ms (เห็น 60.8 กับ 81.5 ต่างกันหนึ่ง tick)
> ให้ถือว่าแม่นประมาณ ±20 ms

---

## 4. พิสูจน์ว่า "แก้ไฟล์แล้ว analysis อัปเดตจริง" (เล่นเองได้)

สคริปต์เดียวทำครบ + **คืนไฟล์กลับแบบ byte-for-byte**:

```powershell
pwsh -NoProfile -File (Join-Path $PKG 'scripts\run_edit_proof.ps1')
```

**ขั้นตอนที่สคริปต์ทำ (และสิ่งที่คุณจะเห็น):**

| # | การกระทำ | หลักฐาน + ผลที่ต้องเห็น |
|---|---|---|
| 1 | จำ bytes เดิมของ `Src\Shared\Extensions\DateTimeExtensions.cs` | `evidence\12-edit-before.txt` → `before_sha256=1d7480e92bf8a1ad73c2070f32ab77043b93ef9852dfdf5aa5d9c127e85de7f7 bytes=886` |
| 2 | จำ generation ก่อนแก้ | `preedit_generation_id=1d7891525f...df6f7` |
| 3 | **แก้ไฟล์จริง** เพิ่ม 1 เมธอด `ToUnixTimeTicks` | `12-edit-after.txt` → `after_edit_sha256=05139048db434c8b8838f75299529183ea68b292368fd99725e79ced41511aa6 bytes=1039` |
| 4 | `serve` ใหม่ (re-analyze + publish) | `12-serve-after-edit.txt` → `exit=0 wall_ms=402`, **`generation_changed=True`**, generation ใหม่ = `8b632b5da319dbf03de49f3370d391a5b0f8711d4890d480eb860a3abcfc91f2`, `nodes 1369 / edges 1214` (จาก 1368/1213 → **+1/+1**) |
| 5 | ถาม MCP ถึง symbol ที่เพิ่งเกิด | `13-mcp-after-edit-answers.txt` → เจอ `ToUnixTimeTicks` `Src/Shared/Extensions/DateTimeExtensions.cs:30` `kind=Method`, ตอบใน ~61 ms, `graph_status.records=2584` (+2) |
| 6 | **คืนไฟล์เดิมแบบ byte-for-byte** | `14-restore.txt` → `restored_sha256=1d7480e9...` **`matches_original=True`** และ `repo_status=?? .axiom/` (สะอาด) |
| 7 | `serve` อีกครั้ง พิสูจน์ว่า publish กลับ generation เดิมเป๊ะ | `15-serve-restored.txt` → `restored_generation_id=1d7891525f...df6f7` **`equals_preedit=True`** |

**สิ่งที่พิสูจน์ได้จากข้อนี้:**
- แก้ไฟล์ → generation id เปลี่ยนจริง, nodes/edges เพิ่มจริง, MCP เห็น symbol ใหม่จริง
- คืนไฟล์ → publish กลับ **generation เดิมเป๊ะ** (deterministic) ⇒ pipeline เชื่อถือได้
- re-serve หลังแก้ไฟล์เดียวใช้เวลา **~0.3-0.5 วินาที** (402 / 411 ms) เทียบกับ cold build 16.7 วินาที

**หมายเหตุ:** generation ของ after-edit (`8b632b5da3...`) จะยังค้างอยู่ใน
`live\generations\` — pointer ชี้ที่ตัวเดิมอยู่แล้ว ลบทิ้งได้ไม่กระทบอะไร

---

## 5. หลักฐานก่อน/หลัง ว่า graphd ลดการ re-read ได้กี่ ms

รันครบชุด + วัดซ้ำ:

```powershell
pwsh -NoProfile -File (Join-Path $PKG 'scripts\run_e2e.ps1')        # 1 รอบเต็ม
pwsh -NoProfile -File (Join-Path $PKG 'scripts\repeat_bench.ps1')   # bench ซ้ำอีก 3 รอบ
python (Join-Path $PKG 'scripts\aggregate_bench.py')
```

**นิยามที่วัด:** คำถาม 1 ข้อ = "หาชนิดของ symbol นี้ + ความสัมพันธ์ที่ติดกับมัน"
- **ไม่มี graphd**: อ่าน `.cs` ทั้ง 156 ไฟล์ต่อคำถาม แล้วอ่านไฟล์ที่ประกาศซ้ำเพื่อดู members (ไม่ cache)
- **มี graphd**: `serve` สร้าง graph ครั้งเดียว แล้วแต่ละคำถาม = `graph_query` 1 ครั้งใน MCP session จริง

**ผลจริง 4 รอบของสคริปต์เดียวกัน** (`evidence\22-bench-repeats-summary.out`):

| run | without_ms | without/คำถาม | with_ms | with/คำถาม | delta/คำถาม |
|---|---|---|---|---|---|
| e2e | 2467.3 | 123.4 | 2352.5 | 117.6 | **+5.7** |
| run1 | 1161.9 | 58.1 | 1165.3 | 58.3 | **-0.2** |
| run2 | 1986.2 | 99.3 | 1512.2 | 75.6 | **+23.7** |
| run3 | 2359.3 | 118.0 | 2005.9 | 100.3 | **+17.7** |

- delta: mean **+11.7 ms** , stdev **10.9** , min **-0.2** , max **+23.7**
- **เครื่องหมายสลับ** ระหว่างรอบ (มีทั้งบวกและลบ) และส่วนเบี่ยงเบนระหว่างรอบ (10.9)
  พอ ๆ กับผลต่างของสองเลนเอง

> **สรุปที่ซื่อสัตย์: ที่ขนาดโปรเจกต์นี้ (156 ไฟล์) สองวิธีนี้ "แยกไม่ออก" ทางเวลา (statistically indistinguishable) — อย่าอ้างว่าชนะเรื่องความเร็วต่อคำถาม**
> ที่ทั้งสองเลนขยับขึ้นลงพร้อมกัน (58 → 123 ms/คำถาม) คือ cache ของ OS กับ load ของเครื่อง ไม่ใช่ผลของ graphd

### 5.1 แก้ตัวเลขของเลนก่อนหน้า (ต้องรายงาน)

| | เลนก่อนหน้า | วัดซ้ำที่ `51782bb` (release) |
|---|---|---|
| ไม่มี graphd | 1864.4 ms / 93.2 ms ต่อคำถาม | ดูตารางบน (mean 99.7 ms, min 58.1, max 123.4) |
| มี graphd | 1217.3 ms / 60.9 ms ต่อคำถาม | ดูตารางบน (mean 87.9 ms, min 58.3, max 117.6) |
| ผลต่าง | **+32.3 ms ต่อคำถาม** | **mean +11.7 ms, stdev 10.9, เครื่องหมายสลับ ⇒ ยืนยันไม่ได้** |

**`+32.3 ms/คำถาม` ไม่ reproduce — ห้ามยกมาอ้าง** สาเหตุที่เป็นไปได้: baseline ของเลนก่อนหน้า
เป็นรอบแรกที่ cache ยังเย็น และเลนก่อนหน้าใช้ **DEBUG build** (`sha 2c499f81...`)
ขณะที่ทุกตัวเลขในนี้มาจาก **RELEASE build** ที่ `51782bb`
(ส่วนที่ **reproduce ตรงเป๊ะ**: generation id, nodes/edges 1368/1213, `result.html` 919717 bytes)

### 5.2 ต้นทุนครั้งเดียว (ไม่ซ่อนในการเทียบต่อคำถาม)

- cold `serve` ครั้งแรกสุด (analyze 473 ไฟล์, publish) = **16720 ms**
- warm `serve` บน tree เดิม = **9227 ms**
- incremental `serve` หลังแก้ 1 ไฟล์ = **445 ms** / หลังคืนไฟล์ = **313 ms**

### 5.3 แล้ว graphd ชนะตรงไหน (วัด slope + บอกชัดว่าเป็นการ extrapolate)

เลนไม่มี graph เป็น full text scan → ต้นทุนเป็น **เส้นตรงกับจำนวนไฟล์**
วัดจากไฟล์จริง (`evidence\21-scan-scaling-r{1,2}.out`):

- r1: slope `0.228` ms/ไฟล์ → break-even **386 ไฟล์**
- r2: slope `0.437` ms/ไฟล์ → break-even **201 ไฟล์**
- (รอบก่อนหน้า: `0.372` ms/ไฟล์ → **186 ไฟล์**)

⇒ break-even อยู่ที่ประมาณ **200-390 ไฟล์** ซึ่ง **สูงกว่า 156 ไฟล์ของโปรเจกต์นี้ทุกครั้ง**
นั่นคือเหตุผลตรง ๆ ว่าทำไมสองเลนถึงเสมอกันที่ขนาดนี้
โปรเจกต์ที่ใหญ่กว่านี้ scan จะแพงขึ้นเรื่อย ๆ แต่ graph_query ยังคงที่ ⇒ graphd เริ่มชนะ

> **หมายเหตุ:** `break_even_files` เป็น **การคำนวณต่อยอด** จาก slope ที่วัดได้
> ไม่ใช่การสแกน tree 200+ ไฟล์จริง — ห้ามรายงานเหมือนวัดตรง

### 5.4 สิ่งที่ graphd "ประหยัด" จริงที่ขนาดนี้

ไม่ใช่วินาทีของ latency แต่คือ **ขั้นตอนทำงานของ agent**: เลน text ทำได้แค่ list members
ตอบ "มีอะไรขึ้นกับ symbol นี้" ไม่ได้ ไม่มี node identity/kind/resolution/evidence
ถ้าจะตอบต้อง grep ทั้ง tree อีกรอบ ส่วน graphd ตอบได้ใน **1 call ~58-118 ms**
จาก graph ที่เก็บไว้ + refresh หลังแก้ไฟล์แค่ **0.3-0.5 วินาที**

---

## 6. รันทั้งหมดรวดเดียว (replay)

```powershell
pwsh -NoProfile -File (Join-Path $PKG 'scripts\run_e2e.ps1')        # ข้อ 1, 2, 3, 5
pwsh -NoProfile -File (Join-Path $PKG 'scripts\run_edit_proof.ps1') # ข้อ 4
pwsh -NoProfile -File (Join-Path $PKG 'scripts\repeat_bench.ps1')   # bench ซ้ำ 3 รอบ
python (Join-Path $PKG 'scripts\aggregate_bench.py')                # สรุป spread
```

> ⚠️ `run_e2e.ps1` จะ **ลบและสร้างใหม่** เฉพาะ lane ของ `agmws-license\agmws-web-service`
> (เป็น scratch) ภายใต้ `$GW` โดยมีการตรวจว่า path อยู่ใน repo ก่อนลบทุกครั้ง
> lane อื่น (`h007-solution`, `t5-license`) **ไม่ถูกแตะ**

## 7. ยังไม่ได้ทำ (NOT_RUN) — ต้องรายงานตรง ๆ

- macOS: ไม่มีเครื่องทดสอบ
- Linux (WSL2/Ubuntu): **ยังไม่ได้รันเลนนี้บน Linux** (ทำเฉพาะ Windows 11 x64)
- ทดสอบกับ Docker image `linux/amd64`: ยังไม่ได้รัน
- activation ของ running image บน Windows native: ยังไม่ได้ทดสอบ
- signed archive / notarisation: ยังไม่ได้ทดสอบ
- multi-bucket shard (โปรเจกต์ใหญ่เกิน 1 shard 16 MiB): ยังไม่มีเคสจริง

## 8. ดัชนีหลักฐาน

ดู `00-manifest.txt` (รายการทุกไฟล์ + bytes + sha256)
จุดเริ่มอ่านที่แนะนำ: `evidence\20-bench-verdict.txt`, `evidence\06-mcp-answers.txt`,
`evidence\12-serve-after-edit.txt`, `evidence\14-restore.txt`, `evidence\15-serve-restored.txt`

## 9. ล้างของ (ถ้าต้องการ)

```powershell
# ลบ home/registry ชั่วคราวของเลนนี้ (สร้างใหม่ได้ด้วย run_e2e.ps1)
Remove-Item -Recurse -Force (Join-Path $PKG 'home-e2e'), (Join-Path $PKG 'home-mcp')
# ลบ scratch ของโปรเจกต์เป้าหมาย (จะต้อง serve ใหม่ถ้าจะใช้ graph อีก)
Remove-Item -Recurse -Force (Join-Path $REPO '.axiom')
```
