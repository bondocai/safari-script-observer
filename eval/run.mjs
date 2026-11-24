// Accuracy test: sends each case in cases.mjs to a model server using the
// extension's own instructions (extension/models.js) and prints a scorecard.
//
//   node eval/run.mjs --render          # render screenshot sources once (macOS)
//   MODEL_URL=https://host/v1 MODEL=qwen3.8-27b-abliterated node eval/run.mjs
//
// MODEL_KIND=ollama uses Ollama's API (MODEL_URL=http://localhost:11434);
// API_KEY is sent as a bearer token if set.
import {readFileSync, existsSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {cases} from "./cases.mjs";

const here = new URL(".", import.meta.url).pathname;

if (process.argv.includes("--render")) {
  for (const name of ["paypal-login", "microsoft-login"]) {
    // The brand look-alike pages aren't in the public repository; add your own here.
    if (!existsSync(here + "shots/" + name + ".html")) { console.log("(skipped " + name + ": no " + name + ".html)"); continue; }
    execFileSync("qlmanage", ["-t", "-s", "1024", "-o", here + "shots", here + "shots/" + name + ".html"], {stdio: "ignore"});
    execFileSync("sips", ["-s", "format", "jpeg", here + "shots/" + name + ".html.png", "--out", here + "shots/" + name + ".jpg"], {stdio: "ignore"});
  }
  console.log("Rendered screenshots into eval/shots/.");
  process.exit(0);
}

const {MODEL_URL, MODEL, MODEL_KIND = "custom", API_KEY = ""} = process.env;
if (!MODEL_URL || !MODEL) {
  console.error("Set MODEL_URL and MODEL, e.g.\n  MODEL_URL=https://your-server/v1 MODEL=your-model node eval/run.mjs");
  process.exit(1);
}

// Load the extension's model code with its settings pointed at this server; the
// "native app" is replaced by a direct fetch.
globalThis.browser = {
  storage: {local: {get: async () => ({settings: {llm: {kind: MODEL_KIND, customUrl: MODEL_URL, customModel: MODEL,
    ollamaUrl: MODEL_URL, ollamaModel: MODEL, apiKey: API_KEY}}})}, onChanged: {addListener() {}}},
  runtime: {sendNativeMessage: async (_, m) => {
    const started = Date.now();
    const response = await fetch(m.url, {method: m.method || "POST", headers: m.headers, body: m.body,
                                         signal: AbortSignal.timeout(m.timeoutMs || 60000)});
    return {status: response.status, body: await response.text(), seconds: (Date.now() - started) / 1000};
  }}
};
const models = new Function(["psl.js", "models.js", "investigate.js"]
  .map(f => readFileSync(here + "../extension/" + f, "utf8")).join("\n") +
  "; return {tasks, serverDecide, loadSettings, shouldInvestigate, settleInvestigation, domainFacts};")();
await models.loadSettings();

function shot(name) {
  const file = here + "shots/" + name + ".jpg";
  if (!existsSync(file)) return null;
  return "data:image/jpeg;base64," + readFileSync(file).toString("base64");
}

// Cases are written as raw page signals; send them the way inspector.js does
// (digits masked, long numbers masked, payment fields marked).
const paymentWords = /card|cvv|cvc|security code|expir|iban|routing|account number|ssn|social security/i;
const maskDigits = text => (text || "").replace(/\d/g, "#");
const maskLongNumbers = text => (text || "").replace(/\d{4,}/g, "####");
function asSent(signals) {
  const s = structuredClone(signals);
  if (s.page) Object.assign(s.page, {title: maskDigits(s.page.title), path: maskLongNumbers(s.page.path)});
  if (typeof s.text === "string") s.text = maskDigits(s.text);
  for (const form of s.forms || []) {
    for (const field of form.fields || []) Object.assign(field, {label: maskDigits(field.label), name: maskLongNumbers(field.name)});
    form.asksForPayment ??= (form.fields || []).some(f => paymentWords.test((f.label || "") + " " + (f.name || "")));
  }
  for (const script of s.scripts?.inline || []) script.excerpt = maskLongNumbers(script.excerpt);
  for (const image of s.images || []) Object.assign(image, {alt: maskDigits(image.alt), file: maskLongNumbers(image.file)});
  return s;
}
for (const c of cases) {
  c.signals = asSent(c.signals);
  // Domain facts come from the extension's own code (background script), as in Safari.
  const host = new URL(c.signals.page.origin).hostname;
  c.signals.identity = {...models.domainFacts(host), faviconHost: c.signals.identity.faviconHost,
                        previousVisits: c.signals.identity.previousVisits};
}

// A held action: the model's gate decision, as in gateAction().
async function decideGate(c) {
  return (await models.serverDecide(models.tasks.gate, {action: c.gate, signals: c.signals, pageVerdict: null})).decision;
}

// A page check, with the investigation step for cases that carry its facts.
async function decidePage(c, image) {
  let result = await models.serverDecide(models.tasks.assess, {signals: c.signals}, image);
  if (c.investigation && models.shouldInvestigate(result, c.signals, {asksForSecrets: c.asksForSecrets})) {
    const first = result;
    let second;
    try {
      second = await models.serverDecide(models.tasks.investigate, {signals: c.signals, investigation: c.investigation}, image);
    } catch (error) {
      second = {error: error.message};
    }
    result = models.settleInvestigation(first, second, c.investigation);
    result.note = "first " + first.verdict + " -> investigated";
  }
  return result.verdict + (result.note ? " (" + result.note + ")" : "");
}

const rows = [];
for (const c of cases) {
  const image = c.screenshot ? shot(c.screenshot) : null;
  if (c.screenshot && !image) console.warn("(no screenshot for " + c.name + "; run with --render first)");
  const started = Date.now();
  let verdict;
  try {
    verdict = c.gate ? await decideGate(c) : await decidePage(c, image);
  } catch (error) {
    verdict = "error: " + error.message.slice(0, 60);
  }
  const ok = c.expect.includes(verdict.split(" ")[0]);
  rows.push({name: c.name, expect: c.expect.join("/"), verdict, ok, seconds: (Date.now() - started) / 1000,
             shouldFlag: !c.expect.includes("safe") && !c.expect.includes("allow")});
  console.log((ok ? "  ok   " : "  MISS ") + c.name.padEnd(38) + ("expected " + c.expect.join("/")).padEnd(30) +
              ("got " + verdict).padEnd(48) + rows.at(-1).seconds.toFixed(1) + " s");
}

const bad = rows.filter(r => r.shouldFlag), good = rows.filter(r => !r.shouldFlag);
const caught = bad.filter(r => r.ok).length, falseAlarms = good.filter(r => !r.ok).length;
const avg = rows.reduce((sum, r) => sum + r.seconds, 0) / rows.length;
console.log("\nModel: " + MODEL);
console.log("Harmful pages caught:   " + caught + " / " + bad.length);
console.log("False alarms on normal: " + falseAlarms + " / " + good.length);
console.log("Average time per check: " + avg.toFixed(1) + " s");
