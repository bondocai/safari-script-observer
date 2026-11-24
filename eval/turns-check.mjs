// Checks the model-call queue (tabs take turns, page checks before frame checks,
// waiting checks replaced by newer ones) and whose fault a failed check is.
// No model or browser needed:  node eval/turns-check.mjs
import {readFileSync} from "node:fs";

const ext = new URL("../extension/", import.meta.url).pathname;
let serverUp = true;
globalThis.browser = {
  storage: {local: {get: async () => ({settings: {llm: {kind: "custom", customUrl: "http://model.test/v1", customModel: "m"}}})},
            onChanged: {addListener() {}}},
  runtime: {sendNativeMessage: async (_, m) => m.method === "GET"
    ? (serverUp ? {status: 200, body: JSON.stringify({data: [{id: "m"}]})} : {error: "down", code: -1004})
    : {status: 500, body: "{}"}}
};
const api = new Function(readFileSync(ext + "models.js", "utf8") +
  "; return {inTurn, failedBecauseOfPage, turns, settingsReady, resetHealth: () => { serverHealth = {at: 0, ok: false}; }};")();
await api.settingsReady;

let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${detail ? " (" + detail + ")" : ""}`);
};

// One model call takes 20 ms; record the order calls actually run in.
const order = [];
const call = (label, lane) => api.inTurn(lane, async () => { order.push(label); await new Promise(r => setTimeout(r, 20)); return label; });

// 1. A flooding tab (30 frame checks) and a victim tab arriving just after.
api.turns.parallel = 1;
const flood = Array.from({length: 30}, (_, i) => call("flood-frame-" + i, {tab: 1, replaces: "assess:" + (i + 1)}));
await new Promise(r => setTimeout(r, 5));
const victim = call("victim-page", {tab: 2, urgent: true, replaces: "assess:0"});
await Promise.all([...flood, victim]);
const victimTurn = order.indexOf("victim-page");
check("victim page check is served next, ahead of a 30-call frame flood", victimTurn <= 1, "served at position " + (victimTurn + 1));

// 1b. Tabs still take turns among urgent calls (e.g. a tab spamming held actions).
order.length = 0;
const spam = Array.from({length: 20}, (_, i) => call("spam-gate-" + i, {tab: 5, urgent: true}));
await new Promise(r => setTimeout(r, 5));
const victimGate = call("victim-gate", {tab: 6, urgent: true});
await Promise.all([...spam, victimGate]);
check("victim's held action is served within 3 calls of a 20-call urgent spam", order.indexOf("victim-gate") <= 2,
      "served at position " + (order.indexOf("victim-gate") + 1));

// 2. In one tab, the page's own check goes before its frames' checks.
order.length = 0;
const frames = Array.from({length: 10}, (_, i) => call("frame-" + i, {tab: 3, replaces: "assess:" + (i + 1)}));
const page = call("page", {tab: 3, urgent: true, replaces: "assess:0"});
await Promise.all([...frames, page]);
check("page check jumps ahead of waiting frame checks", order.indexOf("page") <= 1, "position " + (order.indexOf("page") + 1));

// 3. Repeated checks of the same frame while it waits collapse into the newest one.
order.length = 0;
const blocker = call("busy", {tab: 4});
const repeats = Array.from({length: 20}, (_, i) => call("frame-v" + i, {tab: 4, replaces: "assess:7"}));
const answers = await Promise.all([blocker, ...repeats]);
check("20 waiting re-checks of one frame cost one model call", order.length === 2, order.length + " calls");
check("every caller gets the newest answer", answers.slice(1).every(a => a === "frame-v19"));

// 4. Whose fault a failed check is.
serverUp = true; api.resetHealth();
check("model error while the server works: the page's doing", await api.failedBecauseOfPage({error: "x", cause: "status"}));
api.resetHealth();
check("unusable answer while the server works: the page's doing", await api.failedBecauseOfPage({error: "x", cause: "answer"}));
api.resetHealth();
check("timeout while the server works: the page's doing", await api.failedBecauseOfPage({error: "x", cause: "timeout"}));
check("server unreachable: not the page's doing", !(await api.failedBecauseOfPage({error: "x", cause: "network"})));
check("wrong key/address: not the page's doing", !(await api.failedBecauseOfPage({error: "x", cause: "setup"})));
serverUp = false; api.resetHealth();
check("timeout while the server is down: not the page's doing", !(await api.failedBecauseOfPage({error: "x", cause: "timeout"})));

console.log(failures ? `\n${failures} check(s) failed.` : "\nAll checks passed.");
process.exit(failures ? 1 : 0);
