# W10-DELIVERABLES - independent verification addendum

ไฟล์ชุดนี้เป็น **ผลตรวจสอบซ้ำแบบอิสระ** ของแพ็ก `_w10final/` (deliverables 1-5)
ไม่ได้อยู่ใน `_w10final/00-manifest.txt` เพราะ manifest นั้นครอบเฉพาะไฟล์ใต้ `_w10final/`
ดังนั้นการเพิ่มโฟลเดอร์นี้ **ไม่ทำให้ manifest เดิมเสีย**

## มีอะไร

| ไฟล์ (path สัมพัทธ์จากโฟลเดอร์นี้) | คืออะไร |
|---|---|
| `VERIFY.md` | รายงานตรวจสอบทั้ง 5 deliverables ของเลนอิสระ พร้อมคำสั่งที่รันจริงและ sha256 ที่จับได้ |
| `04-bench5-run.txt` | transcript ของการรัน bench5 (deliverable 5) |
| `evidence/bench5/bench5-report.json` | ตัวเลขสรุป N=20 คำถาม x R=8 รอบ |
| `evidence/bench5/rep{1..8}-calls.json` | request/response ของแต่ละรอบ (ใช้เล่นซ้ำได้) |
| `evidence/bench5/rep{1..8}-results.json` | ผลต่อคำถามของแต่ละรอบ |
| `evidence/bench5/rep{1..8}-pretty.txt` | ผลแบบอ่านง่ายของแต่ละรอบ |
| `evidence/bench5/rep{1..8}-transcript.txt` | transcript ของ MCP session จริงของแต่ละรอบ |

## ข้อสรุปของ deliverable 5 ที่ต้องอ่านก่อน

**ที่ขนาดโปรเจกต์นี้ graphd ยังไม่ชนะเรื่องเวลาแบบมีนัยสำคัญ** และ **ไม่ได้ลดการ RAN ลงเป็นวินาที**

- สแกนเอง (156 ไฟล์ `.cs` ต่อคำถาม) : เฉลี่ย **44.4 ms/คำถาม** (stdev ของค่าเฉลี่ย 22.6)
- ผ่าน graphd (หนึ่ง `graph_query` ใน MCP stdio session จริง) : เฉลี่ย **86.4 ms/คำถาม** (stdev 31.2)
- ผลต่าง mean **-42.0 ms**, stdev **34.7**, เป็นบวกแค่ **1 จาก 8 รอบ** -> **เครื่องหมายสลับ**
- MCP client poll ด้วย `time.sleep(0.02)` ทำให้เลขต่อ call ถูกจัดกลุ่มเป็นขั้น ~20 ms -> **±20 ms เป็น artefact ของเครื่องมือ**
- แพ็ก `_w10final/evidence/20-bench-verdict.txt` รันสคริปต์เดียวกันแบบ 4 รอบ ได้ mean **+11.7 ms** (คนละเครื่องหมาย)
  -> **สองการทดลองอิสระให้เครื่องหมายตรงข้ามกันเอง** = หลักฐานว่า ณ ขนาดนี้มันคือ noise ไม่ใช่ชัยชนะ

**จุดที่ graphd ชนะจริง (วัดได้ ไม่ใช่คาดเดา)**

- หลังแก้ไฟล์ 1 ไฟล์: `serve` แบบ incremental **474 ms** เทียบ full analyse **8194 ms** (แคชอุ่น) = ถูกกว่าประมาณ 17 เท่า
- break-even ที่วัดได้จาก slope จริง (**0.228** และ **0.437 ms/ไฟล์**): ประมาณ **200-390 ไฟล์**
  โปรเจกต์นี้มี **156** ไฟล์ จึงยังอยู่ต่ำกว่า break-even
- สิ่งที่ประหยัดคือ **ความสามารถในการตอบ** ("ใคร depends on อันนี้") ซึ่งการ grep ทั้ง tree ทำไม่ได้ใน call เดียว

**ข้อจำกัดที่บันทึกไว้ ไม่ได้กลบ**

- `16720 ms` (cold) ของเลนก่อนหน้า **ทำซ้ำไม่ได้** เพราะบังคับ cold page cache ไม่ได้
- ตัวเลขเดิมของเลนก่อนหน้า `+32.3 ms/คำถาม` **ไม่ reproduce** และรอบนั้นวัดจากบิลด์ **debug**

## วิธีเล่นซ้ำ (สรุป)

```powershell
cd <worktree ของ axiom-graphd ที่มี _w10final>
# 1) เตรียม AXIOM_HOME ขั้นต่ำ
#    AXIOM_HOME/config/registry.json = {"storage":{"journalMode":"DELETE"}}
#    AXIOM_HOME/config/bindings.json = {"status":"ok","bindings":{"agmws":"D:\\SP-Billy\\axiom"}}
# 2) รันแพ็ก
pwsh -File _w10final/scripts/run_e2e.ps1
pwsh -File _w10final/scripts/run_edit_proof.ps1
pwsh -File _w10final/scripts/repeat_bench.ps1
```

รายละเอียดเต็มอยู่ใน `_w10final/README.md` (ภาษาไทย) และ `VERIFY.md`
