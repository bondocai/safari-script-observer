// Real-world test: does the extension catch live phishing pages that Safari's
// built-in protection (Google Safe Browsing) does not flag yet?
//
//   cd eval/phish && npm install          # once (HTML parser for the investigation step)
//   MODEL_URL=https://host/v1 MODEL=qwen3.8-27b-abliterated node eval/phish/run.mjs [--limit 40] [--no-controls]
//   MODEL_URL=... MODEL=... node eval/phish/run.mjs --rejudge eval/phish/results/<run>   # re-ask the model only
//
// Steps:
//   1. Download the newest OpenPhish reports (one address per site).
//   2. Ask Google's Safe Browsing status page whether each is flagged right now
//      (Safari's warning list comes from Google Safe Browsing; Safari's local copy
//      can lag a little, so this slightly favours Safari).
//   3. Visit each page in headless Chromium inside a locked-down Docker container,
//      with the extension's real content script injected; nothing is typed or clicked.
//   4. Ask the model, through the extension's own code (models.js, investigate.js),
//      including the investigation step. The OpenPhish lookup is switched off here,
//      since every test page comes from that list; the test simulates the hours
//      before a page is reported anywhere.
//   5. Re-check Google's status, then write report.md and results.json.
//
// Control set: well-known real sign-in pages, judged the same way, as if visited
// for the first time. They measure false alarms on the real web.
//
// Results (including screenshots of phishing pages) stay in eval/phish/results/,
// which git ignores.
import {readFileSync, writeFileSync, existsSync, mkdirSync} from "node:fs";
import {execFileSync, spawnSync} from "node:child_process";
import {DOMParser} from "linkedom";

const here = new URL(".", import.meta.url).pathname;
const extension = here + "../../extension/";
const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
};
const limit = Number(arg("--limit", 40));
const withControls = !argv.includes("--no-controls");
const rejudge = arg("--rejudge", null);

const {MODEL_URL, MODEL, MODEL_KIND = "custom", API_KEY = ""} = process.env;
if (!MODEL_URL || !MODEL) {
  console.error("Set MODEL_URL and MODEL, e.g.\n  MODEL_URL=https://your-server/v1 MODEL=your-model node eval/phish/run.mjs");
  process.exit(1);
}

const controls = [
  "https://accounts.google.com/signin", "https://login.microsoftonline.com/", "https://github.com/login",
  "https://account.apple.com/sign-in", "https://www.paypal.com/signin", "https://www.amazon.com/ap/signin",
  "https://secure.chase.com/web/auth/dashboard", "https://www.wellsfargo.com/", "https://www.facebook.com/login/",
  "https://www.linkedin.com/login", "https://www.dropbox.com/login", "https://www.netflix.com/login",
  "https://login.coinbase.com/signin", "https://dashboard.stripe.com/login", "https://zoom.us/signin",
  "https://www.instagram.com/accounts/login/", "https://login.yahoo.com/", "https://auth.services.adobe.com/",
  "https://app.docusign.com/", "https://www.dhl.com/us-en/home.html"
];

// Sites phishing kits send unwanted visitors (scanners) to instead of the phishing page.
const cloakDestinations = /(^|\.)(google|bing|microsoft|live|office|outlook|apple|amazon|yahoo|wikipedia|youtube|facebook|example)\.(com|org|net)$/;

// ---- Google Safe Browsing status (what Safari's warning list is built from) ----
async function googleStatus(url) {
  try {
    const response = await fetch("https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=" +
      encodeURIComponent(url), {signal: AbortSignal.timeout(10000)});
    const row = JSON.parse((await response.text()).replace(/^\)\]\}'\s*/, ""))[0];
    // row[1]: 1 no unsafe content, 2 unsafe, 3 partly unsafe, 4 check a specific URL, 6 no data.
    // row[2..6]: malware / unwanted software / social engineering / ... flags.
    const flagged = row[1] === 2 || row[1] === 3 || row.slice(2, 7).some(v => v === true);
    return {flagged, code: row[1]};
  } catch (error) {
    return {flagged: null, error: error.message.slice(0, 80)};
  }
}

async function mapLimited(items, n, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({length: n}, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }));
  return results;
}

// ---- 1-3: pick addresses, check Google, capture in the sandbox ----------------
let dir;
if (rejudge) {
  dir = rejudge.replace(/\/$/, "");
} else {
  dir = here + "results/" + new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  mkdirSync(dir, {recursive: true});

  const feed = await (await fetch("https://openphish.com/feed.txt", {signal: AbortSignal.timeout(20000)})).text();
  const seenHosts = new Set();
  const phish = [];
  for (const line of feed.split("\n").map(l => l.trim())) {
    if (!/^https?:\/\//.test(line)) continue;
    let host;
    try { host = new URL(line).hostname; } catch { continue; }
    if (seenHosts.has(host)) continue;
    seenHosts.add(host);
    phish.push(line);
    if (phish.length >= limit) break;
  }
  const items = [
    ...phish.map((url, i) => ({id: "p" + String(i + 1).padStart(3, "0"), url, kind: "phishing"})),
    ...(withControls ? controls.map((url, i) => ({id: "c" + String(i + 1).padStart(3, "0"), url, kind: "control"})) : [])
  ];
  console.log(`Checking ${phish.length} phishing reports and ${withControls ? controls.length : 0} real sign-in pages with Google...`);
  await mapLimited(items, 4, async item => { item.googleBefore = await googleStatus(item.url); });
  writeFileSync(dir + "/urls.json", JSON.stringify(items, null, 1));

  console.log("Building the sandbox image (first time only takes a while)...");
  execFileSync("docker", ["build", "-q", "-t", "sso-phish-capture", here], {stdio: ["ignore", "ignore", "inherit"]});
  console.log("Visiting pages inside the sandbox...");
  const run = spawnSync("docker", ["run", "--rm", "--init", "--ipc=host",
    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=3g", "--cpus=2", "--pids-limit=1024",
    // The Docker host is not reachable from the container (pages are also blocked from private addresses).
    "--add-host=host.docker.internal:127.0.0.1", "--add-host=gateway.docker.internal:127.0.0.1",
    "-v", dir + ":/work", "-v", extension + "inspector.js:/harness/inspector.js:ro",
    "sso-phish-capture"], {stdio: "inherit"});
  if (run.status !== 0) {
    console.error("Capture failed (docker exit " + run.status + ").");
    process.exit(1);
  }
}
const items = JSON.parse(readFileSync(dir + "/urls.json", "utf8"));

// ---- 4: the model, through the extension's own code ---------------------------
const storage = new Map([["settings", {llm: {kind: MODEL_KIND, customUrl: MODEL_URL, customModel: MODEL,
  ollamaUrl: MODEL_URL, ollamaModel: MODEL, apiKey: API_KEY}}]]);
globalThis.DOMParser = DOMParser;
globalThis.browser = {
  storage: {
    local: {
      get: async keys => Object.fromEntries([keys].flat().filter(k => storage.has(k)).map(k => [k, storage.get(k)])),
      set: async values => { for (const [k, v] of Object.entries(values)) storage.set(k, v); }
    },
    onChanged: {addListener() {}}
  },
  // Stand-in for the native app: a plain request, no cookies, body capped at 2 MB.
  runtime: {sendNativeMessage: async (_, m) => {
    const started = Date.now();
    try {
      const response = await fetch(m.url, {method: m.method || "POST", headers: m.headers, body: m.body,
                                           redirect: "follow", signal: AbortSignal.timeout(m.timeoutMs || 60000)});
      const body = (await response.text()).slice(0, 2_000_000);
      return {status: response.status, body, finalUrl: response.url, seconds: (Date.now() - started) / 1000};
    } catch (error) {
      return {error: error.message};
    }
  }}
};
const ext = new Function(
  "const scriptHashes = new Map();\n" +
  readFileSync(extension + "models.js", "utf8") + "\n" + readFileSync(extension + "investigate.js", "utf8") +
  // Every test page comes from OpenPhish, so that lookup would give the answer away.
  "\nopenPhishMatch = async () => 'not checked in this test';\n" +
  "; return {tasks, serverDecide, loadSettings, shouldInvestigate, settleInvestigation, investigate, " +
  "isPrivateHost, exfilIndicators, scriptHashes};")();
await ext.loadSettings();

// What the extension's background script records about external scripts.
async function hashScripts(urls) {
  await Promise.all(urls.slice(0, 25).map(async src => {
    try {
      if (ext.isPrivateHost(new URL(src).hostname)) return;
      const response = await fetch(src, {signal: AbortSignal.timeout(5000)});
      ext.scriptHashes.set(src, {indicators: ext.exfilIndicators((await response.text()).slice(0, 2_000_000))});
    } catch {}
  }));
}

function registrable(host) {
  return host.split(".").slice(-2).join(".");
}

function testable(capture) {
  if (!capture || capture.loadError) return "did not load: " + (capture?.loadError || "no capture");
  if (capture.status >= 400) return "page gone (HTTP " + capture.status + ")";
  const last = capture.messages.at(-1);
  if (!last) return "nothing to check (content script saw no page)";
  const s = last.signals;
  if ((s.text || "").length < 30 && !s.forms.length && !s.images.length) return "blank page (taken down or hiding from scanners)";
  const finalHost = new URL(capture.finalUrl).hostname;
  if (registrable(finalHost) !== registrable(new URL(capture.url).hostname) && cloakDestinations.test(finalHost)) {
    return "sent scanners away to " + finalHost;
  }
  return null;
}

const results = [];
for (const item of items) {
  const file = `${dir}/capture/${item.id}.json`;
  const capture = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  const row = {...item, finalUrl: capture?.finalUrl, status: capture?.status};
  row.skipped = testable(capture);
  if (!row.skipped) {
    const message = capture.messages.at(-1);
    const signals = message.signals;
    signals.identity.previousVisits = 0;
    const imageFile = `${dir}/capture/${item.id}.jpg`;
    const image = message.screenshotTaken && existsSync(imageFile)
      ? "data:image/jpeg;base64," + readFileSync(imageFile).toString("base64") : null;
    const started = Date.now();
    try {
      await hashScripts(message.scriptUrls || []);
      let result = await ext.serverDecide(ext.tasks.assess, {signals}, image);
      row.firstVerdict = result.verdict;
      const context = {asksForSecrets: message.asksForSecrets};
      if (ext.shouldInvestigate(result, signals, context)) {
        const facts = await ext.investigate(signals, capture.finalUrl, message.scriptUrls || [])
          .catch(error => ({failed: error.message}));
        let second;
        try {
          second = await ext.serverDecide(ext.tasks.investigate, {signals, investigation: facts}, image);
        } catch (error) {
          second = {error: error.message};
        }
        result = ext.settleInvestigation(result, second, facts);
        row.investigation = result.investigation;
      }
      row.verdict = result.verdict;
    } catch (error) {
      row.verdict = "error";
      row.error = error.message.slice(0, 120);
    }
    row.seconds = (Date.now() - started) / 1000;
    row.asksForSecrets = message.asksForSecrets;
    row.screenshot = !!image;
  }
  results.push(row);
  const google = row.googleBefore?.flagged === true ? "Google: flagged " : row.googleBefore?.flagged === false ? "Google: clean   " : "Google: ?       ";
  console.log(`  ${row.id}  ${google} ${(row.skipped ? "skipped (" + row.skipped + ")" : "model: " + row.verdict +
    (row.firstVerdict && row.firstVerdict !== row.verdict ? " (first " + row.firstVerdict + ")" : "")).padEnd(60)} ${row.url.slice(0, 70)}`);
}

// ---- 5: Google again, then the report ------------------------------------------
console.log("Re-checking Google...");
await mapLimited(results.filter(r => !r.skipped), 4, async r => { r.googleAfter = await googleStatus(r.url); });
writeFileSync(dir + "/results.json", JSON.stringify(results, null, 1));

const tested = results.filter(r => !r.skipped && r.verdict !== "error");
const phishing = tested.filter(r => r.kind === "phishing");
const unflagged = phishing.filter(r => r.googleBefore?.flagged === false);
const flagged = phishing.filter(r => r.googleBefore?.flagged === true);
const realSites = tested.filter(r => r.kind === "control");
const count = (rows, v) => rows.filter(r => r.verdict === v).length;
const line = (label, rows) => `| ${label} | ${rows.length} | ${count(rows, "malicious")} | ${count(rows, "suspicious")} | ${count(rows, "safe")} |`;
const pct = (a, b) => b ? Math.round(100 * a / b) + "%" : "n/a";

const report = `# Live phishing test

Run: ${dir.split("/").pop()} · model: ${MODEL}

- Phishing reports taken from OpenPhish: ${results.filter(r => r.kind === "phishing").length}
- Testable (page still up and shown to the sandbox): ${phishing.length}
- Skipped: ${results.filter(r => r.kind === "phishing" && r.skipped).length} (gone, blank, or sent scanners elsewhere)
- Errors: ${results.filter(r => r.verdict === "error").length}

## Results

Blocked = the extension replaces the page with its block page. Warned = a warning banner, submits still held.

| Group | Pages | Blocked | Warned | Missed (safe) |
|---|---|---|---|---|
${line("Phishing that Google did **not** flag yet", unflagged)}
${line("Phishing Google already flags", flagged)}
${line("All testable phishing", phishing)}
${line("Real sign-in pages (false-alarm check)", realSites)}

- **Caught where Safari would likely not warn:** ${unflagged.length - count(unflagged, "safe")} of ${unflagged.length} (${pct(unflagged.length - count(unflagged, "safe"), unflagged.length)}), blocked outright: ${count(unflagged, "malicious")}
- Of those, Google flagged by the end of the run: ${unflagged.filter(r => r.googleAfter?.flagged).length}
- **False alarms on real sign-in pages:** ${realSites.length - count(realSites, "safe")} of ${realSites.length}
- Average time per check: ${(tested.reduce((s, r) => s + r.seconds, 0) / (tested.length || 1)).toFixed(1)} s

## Every page

| ID | Kind | Google before | Model | First verdict | Address |
|---|---|---|---|---|---|
${results.map(r => `| ${r.id} | ${r.kind} | ${r.googleBefore?.flagged === true ? "flagged" : r.googleBefore?.flagged === false ? "clean" : "?"} | ${r.skipped ? "skipped: " + r.skipped : r.verdict} | ${r.firstVerdict || ""} | \`${r.url.slice(0, 80).replace(/\|/g, "%7C")}\` |`).join("\n")}

Screenshots: capture/<ID>-view.jpg (what the sandbox saw) and capture/<ID>.jpg (what the model saw).
`;
writeFileSync(dir + "/report.md", report);
console.log("\n" + report.split("## Every page")[0]);
console.log("Full report: " + dir + "/report.md");
