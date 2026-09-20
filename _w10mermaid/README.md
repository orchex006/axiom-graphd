# graph-mermaid-view : Mermaid + lane canvas สำหรับ `render`

**lane:** `graph-mermaid-view`  **branch:** `feature/graph-mermaid-view`
**ฐาน:** `main` = `51782bb`  **code revision ที่วัด:** `09cd648613e0e111d9d262b98d52d6dbeecc9a12`
**ไบนารีที่ใช้:** `target\release\axiom-graphd.exe`
`bytes=3805184` `sha256=d90514441eb4ff86a0c1106e98fcd28acc9057f03d0ca4d74fa9d947023ce688`
(build ซ้ำจาก tree เดิมแล้วได้ hash เดิมเป๊ะ - ดูข้อ 4)
**โปรเจกต์ทดสอบ:** `D:\SP-Billy\axiom\agmws-license-management-netcore` branch `feature/graphd` @ `24410f36`
**generation ที่ render:** `1d7891525f028ecff06a6b8d7a8ac8a4ee3b31cc8067f1431e900b0cf7cdf6f7`
(`nodes=1368` `edges=1213` `shards=3` `records=2582`)

> ทุกตัวเลขในนี้มาจากไฟล์ใน `evidence\` ที่รันจริง ไม่ได้ปั้นขึ้นมา
> คำสั่งที่ให้ไว้ copy ไปวางได้เลย และบอก "ต้องเห็นอะไร" กำกับทุกขั้น

---

## 0. ปัญหาที่แก้

`render` เดิมวาดทุก node/edge ของ generation ลง canvas เดียวแบบไม่แบ่งอะไรเลย
บน generation จริง (`1368` nodes / `1213` edges) อ่านไม่ออกว่าใครเกี่ยวกับใคร
และไม่มี artifact ตัวไหนเอาไปวางใน renderer ที่คนใช้อยู่แล้วได้

## 1. สิ่งที่เปลี่ยน (เพิ่มอย่างเดียว ไม่แก้ของเดิม)

**ก. artifact ตัวที่สาม `graph.mmd`** - Mermaid flowchart ของ summary เดียวกัน

**ข. `result.html`** มีสองส่วนใหม่
- `## mermaid overview` : `<figure id="axiom-mermaid">` ที่ฝัง source ไว้ **สองที่**
  (`<pre class="mermaid" id="axiom-mermaid-live">` ไว้เรนเดอร์ + `<details id="axiom-mermaid-source">` ไว้ copy)
  ตัวเรนเดอร์โหลดจาก CDN **เฉพาะตอน `navigator.onLine`** และ `.catch(() => {})` เงียบ ๆ
  → ออฟไลน์ก็ยังเห็น/copy source ได้ และ byte ของไฟล์ไม่แกว่ง
- canvas เดิม แยก **หนึ่งเลนต่อหนึ่ง kind** (`<g id="axiom-bands">`) เรียงตาม frozen legend order
  สลับสีพื้นเลน + แถบสี kind 6px + หัวเลน `"{kind} · {count}"` + เลนเทาสำหรับ kind ที่ไม่มี legend row
  node = `fill:tint(color)` / `stroke:color` มุมโค้ง, ยังคง dash + `?` ของ placeholder,
  ยังคง marker `axiom-arrow-<i>`, hover title และ id `axiom-bands`/`axiom-edges`/`axiom-nodes` เดิม

**Mermaid projection ถูกจำกัดขนาดและบอกตัวเองตรง ๆ** : เรียงตาม frozen kind order,
หยุดที่ `MERMAID_NODE_LIMIT = 160`, เก็บเฉพาะ edge ที่ปลายทั้งสองรอด,
จัด node เป็น `subgraph` ต่อโปรเจกต์, ออก `classDef` ต่อ kind + `classDef ph` (placeholder = hexagon)
และ **header ของตัวเองบอกว่าไม่ได้วาดอะไร** :

```text
%% projection: 160 of 1368 node(s) and 3 of 1213 edge(s); kind order is the priority order and the projection stops at 160 node(s)
```

**ชื่อที่มากจากโค้ดจริงเปลี่ยนรูปกราฟไม่ได้** : `mermaid_text` *แทนที่* (ไม่ใช่ escape)
ทุกตัวอักษรที่เป็น markup / เปิด shape / คั่น link / เปิด entity / ขึ้นบรรทัดใหม่ แล้วยุบช่องว่างและตัดที่ 48 ตัวอักษร

---

## 2. เปิดดูของจริง

```powershell
$PKG = 'D:\SP-Billy\axiom-worktrees\axiom-graphd-mermaid\_w10mermaid'
Invoke-Item (Join-Path $PKG 'evidence\render-a\result.html')
```

- ออนไลน์ → เห็นกราฟ Mermaid วาดจริงในหน้า + ด้านล่างเป็น canvas แยกเลนตาม kind
- ออฟไลน์ → เห็น source ใน `<details>` ให้ copy ไปวางที่อื่นได้

ไฟล์ที่ได้ (render-a กับ render-b เหมือนกันทุก byte) :

| ไฟล์ | bytes | sha256 |
|---|---|---|
| `result.html` | 947928 | `98567f86d29173573f1b1f19b8bbfb6b0477175eead8408be589c19912085380` |
| `summary.json` | 1295180 | `af0e1a77eedfe9d7326d50efe35ae3831b72d942c33ab253d27d3c0b478b1f71` |
| `graph.mmd` | 11328 | `bf58e92f2109a7b1fbcf22bb6ac6a33f33ae4778fd8d2e1df3564215e7a2fd7c` |

> เทียบของเดิมที่ pin ไว้บน `feature/w10-deliverables` : `result.html` = 919717 bytes
> (`sha256=ea3f4bd2dc248c2525eeeea114ca405f0b7d6e9dbe74955d5d60d018dc6c2bee`)
> ของใหม่ = 947928 bytes **ไฟล์เดิมยังอยู่ครบ ไม่ถูกแตะ** เลือกได้ว่าจะเอาอันไหน

---

## 3. เล่นซ้ำเอง (ทำได้ทั้งหมดจากเครื่องนี้)

### 3.1 render ใหม่ 2 รอบ + ตรวจ determinism

```powershell
pwsh -NoProfile -File D:\SP-Billy\axiom-worktrees\axiom-graphd-mermaid\_w10mermaid\scripts\run_render.ps1
```

ทำอะไร: สร้าง scratch `AXIOM_HOME` ใหม่ทุกครั้ง (ลบเฉพาะ `_w10mermaid\home` ที่มี path guard)
→ `solution register` → `render` สองรอบ (`render-a`, `render-b`) → เขียน hash ลง `evidence\`

**ต้องเห็น:** `01-register.txt` = `exit=0`, `02-render-a.txt`/`02-render-b.txt` = `exit=0` (~40-50 ms)
และ `04-determinism.txt` ขึ้น `byte_identical ... True` ทั้ง 3 บรรทัด
สคริปต์ **ไม่ publish/แก้/ลบอะไรในโปรเจกต์เป้าหมาย** แค่อ่าน graph root

### 3.2 พิสูจน์ว่า `graph.mmd` เป็น Mermaid ที่ถูกจริง ไม่ใช่แค่หน้าตาคล้าย

```powershell
$d = "$env:TEMP\axmermaid2"
New-Item -ItemType Directory -Force -Path $d | Out-Null
Set-Content -Path (Join-Path $d 'package.json') -Value '{"name":"axmermaid","private":true,"version":"1.0.0","type":"module"}' -Encoding utf8NoBOM
cd $d; npm i --no-audit --no-fund mermaid@10.9.1 jsdom
Copy-Item D:\SP-Billy\axiom-worktrees\axiom-graphd-mermaid\_w10mermaid\scripts\mermaid_probe.mjs $d -Force
node probe.mjs D:\SP-Billy\axiom-worktrees\axiom-graphd-mermaid\_w10mermaid\evidence\render-a\graph.mmd
```

**ต้องเห็น** (นี่คือ `evidence\05-mermaid-parse-probe.txt` ที่บันทึกไว้) :

```text
PARSE_OK return=true
RENDER_OK bytes=82357
svg_nodes=160
svg_subgraphs=1
svg_edgePaths=3
source_header=%% projection: 160 of 1368 node(s) and 3 of 1213 edge(s); ...
```

คือใช้ parser + dagre ตัวจริงของ mermaid@10.9.1 (ตัวเดียวกับที่ CDN ในหน้ารุ่น `mermaid@10` โหลด)
**parse ผ่าน** และเรนเดอร์ออกมาได้ **160 node / 1 subgraph / 3 edge ตรงกับ header ที่ source ประกาศเองเป๊ะ**
(ไบนารี SVG ที่เรนเดอร์แล้วอยู่ที่ `evidence\06-mermaid-rendered.svg` เปิดดูได้)
สิ่งที่ต้อง stub คือ geometry ของ jsdom (`getBBox`) เพราะ jsdom ไม่มี SVG layout engine

### 3.3 เอาไปวางใน renderer ที่คุณใช้จริง

เปิด https://mermaid.live แล้ววางเนื้อไฟล์ `evidence\render-a\graph.mmd` ทั้งไฟล์
หรือวางลง Markdown preview ของ editor ที่รองรับ Mermaid / GitHub issue ก็ได้

---

## 4. determinism และ revision

- `evidence\00-env.txt` บันทึกไว้ตรง ๆ ว่า `binary_sha256` / `graphd_revision` / สถานะ worktree ตอนรัน
- build release ซ้ำจาก tree เดียวกัน (`cargo build --release --locked -p axiom-graphd`) แล้วได้
  sha256 **เดิม** `d9051444...` → ไบนารีที่วัดตรงกับ revision `09cd648` จริง ไม่ใช่ debug หรือ build ค้าง
- ตอนรันหลักฐาน worktree dirty อยู่ **เพียงเพราะไฟล์ของ package นี้เอง** ซึ่งถูก commit ต่อทันที
  (`graphd_status_porcelain` ในไฟล์ env เขียนไว้ตรง ๆ ไม่ได้ซ่อน)

---

## 5. ยังไม่ได้พิสูจน์ / ข้อจำกัด (รายงานตรง ๆ ไม่ปั้น)

- **ไม่ได้รัน `serve` ใน home นี้** จึงอ่าน generation ที่ publish ไว้แล้วเท่านั้น
  ผลคือ `freshness.status = unknown` ใน banner (`coverage = complete_for_profile`, `input_files=156`)
  ถ้าอยากเห็น `fresh: true` ให้รัน `serve` ด้วย `AXIOM_HOME` เดียวกันก่อน แล้ว render ใหม่
  (graph ที่ได้เป็น generation เดียวกัน : `1d7891525f...df6f7`)
- **ไม่มีเครื่อง macOS** ในสภาพแวดล้อมนี้ และ branch นี้ยังไม่ถูกรันบน Linux/WSL
- `result.html` ยังเป็นไฟล์ที่เขียนลงดิสก์แล้วเปิดดูเอง **ไม่มี interactive viewer** (เหมือนเดิม)
- branch นี้ **ใหม่จาก `main`** และไม่ได้ merge อะไร ; package ที่ pin ไว้บน
  `feature/w10-deliverables` (`_w10final`) **ไม่ถูกแตะเลย** เพื่อให้เทียบสองไฟล์ก่อนเลือก
- ตัวเลข 160 node ที่ Mermaid วาด **ไม่ใช่ทั้ง graph** : อีก `1208` node / `1210` edge
  อยู่ใน `result.html` canvas และ `summary.json` (Mermaid ตั้งใจจำกัดเพื่อให้อ่านออก)

---

## 6. โครงไฟล์

```text
_w10mermaid/
  README.md                  <- เอกสารนี้
  scripts/run_render.ps1     <- register + render 2 รอบ + hash
  scripts/mermaid_probe.mjs  <- parse + render graph.mmd ด้วย mermaid จริง
  evidence/
    00-env.txt               <- ไบนารี/revision/สถานะ repo ตอนวัด
    01-register.*            <- solution register (exit 0)
    02-render-a.* / 02-render-b.*
    03-artifacts.txt         <- 3 artifact × 2 รอบ + bytes + sha256
    04-determinism.txt       <- เทียบ byte ต่อ artifact
    05-mermaid-parse-probe.txt
    06-mermaid-rendered.svg  <- กราฟที่ Mermaid เรนเดอร์จริงจาก graph.mmd
    render-a/ , render-b/    <- result.html + summary.json + graph.mmd
```
