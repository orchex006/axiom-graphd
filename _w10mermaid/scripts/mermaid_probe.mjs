// Prove the emitted graph.mmd is valid Mermaid, not just plausible-looking:
// parse it AND render it with the real mermaid package, headless.
//
//   cd <a scratch dir>; npm i mermaid@10.9.1 jsdom
//   node mermaid_probe.mjs <graph.mmd> [out.svg]
//
// jsdom has no SVG layout engine, so the geometry Mermaid asks for is stubbed;
// that is enough for Mermaid's own parser and dagre layout to run. The node and
// edge counts it reports are compared against the source's own
// `%% projection:` header.
import { JSDOM } from "jsdom";
import fs from "node:fs";

const src = fs.readFileSync(process.argv[2], "utf8");
const dom = new JSDOM("<!DOCTYPE html><body></body>", { pretendToBeVisual: true });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, "navigator", { value: dom.window.navigator, configurable: true });

const stub = () => ({ x: 0, y: 0, width: 120, height: 24, top: 0, left: 0, right: 120, bottom: 24 });
for (const proto of [dom.window.SVGElement.prototype, dom.window.Element.prototype]) {
  proto.getBBox = stub;
  proto.getComputedTextLength = () => 120;
  proto.getScreenCTM = () => ({ a: 1, b: 0, c: 0, d: 1, e: 0, f: 0, inverse: () => ({ a: 1, b: 0, c: 0, d: 1, e: 0, f: 0 }) });
}

const mermaid = (await import("mermaid")).default;
mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "base", flowchart: { htmlLabels: false } });

console.log("PARSE_OK return=" + JSON.stringify(await mermaid.parse(src)));
const { svg } = await mermaid.render("probeGraph", src);
console.log("RENDER_OK bytes=" + svg.length);
for (const [label, re] of [["nodes", /class="node default/g], ["edgePaths", /class="edge-thickness/g]]) {
  console.log("svg_" + label + "=" + (svg.match(re) || []).length);
}
const header = src.split("\n").find((line) => line.startsWith("%% projection:")) || "";
console.log("source_header=" + header);
if (process.argv[3]) {
  fs.writeFileSync(process.argv[3], svg);
  console.log("svg_written=" + process.argv[3]);
}
