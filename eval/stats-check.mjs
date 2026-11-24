// Checks the local stats (extension/stats.js): recording, 30-day pruning, caps,
// what is kept about sites, and the summary Settings shows. No model or browser:
//   node eval/stats-check.mjs
import {readFileSync} from "node:fs";

const store = {};
globalThis.browser = {storage: {local: {
  get: async key => (key in store ? {[key]: structuredClone(store[key])} : {}),
  set: async values => Object.assign(store, structuredClone(values))
}}};
const api = new Function(readFileSync(new URL("../extension/stats.js", import.meta.url), "utf8") +
  "; return {statsRecord, statsCheck, flushStats, summarizeStats, percentile};")();

let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${detail ? " (" + detail + ")" : ""}`);
};

// Percentiles: nearest-rank.
check("median of 1..10 is 5", api.percentile([...Array(10)].map((_, i) => i + 1), 50) === 5);
check("95th percentile of 1..100 is 95", api.percentile([...Array(100)].map((_, i) => i + 1), 95) === 95);
check("no values: no percentile", api.percentile([], 50) === null);

// A day of browsing.
const t0 = Date.now() - 1000;
for (let i = 0; i < 40; i++) api.statsCheck("page", t0 - i * 50, {verdict: "safe", decidedBy: "server"}, "https://news.example/a" + i);
for (let i = 0; i < 10; i++) api.statsCheck("page", t0, {verdict: "safe", decidedBy: "memory"}, "https://news.example/");
api.statsCheck("page", t0 - 3000, {verdict: "malicious", decidedBy: "server"}, "https://evil-login.example/x?y");
api.statsCheck("page", t0, {verdict: "malicious", decidedBy: "memory"}, "https://evil-login.example/x");
api.statsCheck("page", t0, {needScreenshot: true}, "https://bank.example/");
api.statsCheck("page", t0, {verdict: "suspicious", decidedBy: "rules", checkFailed: true, failure: "timeout"}, "https://slow.example/");
api.statsCheck("action", t0 - 2000, {decision: "allow", decidedBy: "server"}, "https://bank.example/login", "submit");
api.statsCheck("action", t0 - 4000, {decision: "block", decidedBy: "server"}, "https://fix.example/", "clipboard");
api.statsCheck("page", t0, {verdict: "suspicious", decidedBy: "rules", checkFailed: true, failure: "timeout"}, "https://slow.example/");
api.statsRecord("waits", {kind: "typing", ms: 1800, outcome: "open"});
api.statsRecord("events", {host: "county-tax.example", event: "override", detail: "typed on a suspicious page"});
await api.flushStats();

const saved = store.stats;
const s = api.summarizeStats(saved);
check("pages counted, screenshot round-trips not", s.pages.count === 54, String(s.pages.count));
check("a re-flagged site within 10 minutes is listed once", s.flagged.filter(e => e.host === "slow.example").length === 1);
check("remembered pages counted separately", s.pages.remembered === 11, String(s.pages.remembered));
check("model time only from model answers", s.modelTime.pages.count === 41, String(s.modelTime.pages.count));
check("held actions by kind", s.actions.submit?.count === 1 && s.actions.clipboard?.outcomes.block === 1);
check("typing waits", s.typingWaits.count === 1 && s.typingWaits.median === 1800);
check("failed checks by cause", s.failures.timeout === 2, JSON.stringify(s.failures));
check("flagged: once when decided, not again from memory",
      s.flagged.filter(e => e.host === "evil-login.example").length === 1);
check("blocked action listed", s.flagged.some(e => e.event === "action blocked" && e.outcome === "clipboard"));
check("override listed", s.overrides.length === 1 && s.overrides[0].host === "county-tax.example");
const text = JSON.stringify(saved);
check("safe pages leave no site names", !text.includes("news.example"));
check("only host names are kept, never paths or queries", !text.includes("/x") && !text.includes("?y"));

// 30-day pruning and caps.
saved.checks.unshift({at: Date.now() - 31 * 86400e3, kind: "page", ms: 1, by: "server", outcome: "safe"});
store.stats = saved;
for (let i = 0; i < 20005; i++) api.statsRecord("checks", {kind: "frame", ms: 1, by: "server", outcome: "safe"});
await api.flushStats();
check("entries older than 30 days dropped", store.stats.checks.every(c => c.at > Date.now() - 30 * 86400e3));
check("check list capped at 20,000", store.stats.checks.length === 20000, String(store.stats.checks.length));

console.log(failures ? `\n${failures} check(s) failed.` : "\nAll checks passed.");
process.exit(failures ? 1 : 0);
