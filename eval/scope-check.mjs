// Scripts loaded by the same page (or the background) share one global scope:
// a name declared twice with const/let stops the later script from running at all.
// Compiles each page's scripts together, without running them.
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const dir = path.join(path.dirname(new URL(import.meta.url).pathname), "../extension");
const groups = {};
const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
groups["background"] = manifest.background?.scripts || [];
for (const [i, cs] of (manifest.content_scripts || []).entries()) groups[`content script ${i + 1}`] = cs.js || [];
for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".html"))) {
  const html = fs.readFileSync(path.join(dir, file), "utf8");
  groups[file] = [...html.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map(m => m[1]);
}
let failed = 0;
for (const [name, scripts] of Object.entries(groups)) {
  if (!scripts.length) continue;
  const source = scripts.map(s => fs.readFileSync(path.join(dir, s), "utf8")).join("\n;\n");
  try { new vm.Script(source, {filename: name}); console.log(`ok    ${name}: ${scripts.join(", ")}`); }
  catch (e) { failed++; console.log(`FAIL  ${name}: ${scripts.join(", ")}: ${e.message}`); }
}
process.exit(failed ? 1 : 0);
