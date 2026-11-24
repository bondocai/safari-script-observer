// Red-team test: runs each scenario in test-site/redteam/ end to end against the
// extension's real code and your real model, offline.
//
//   cd eval/redteam && npm install      # once (Playwright; uses its cached Chromium)
//   MODEL_URL=https://host/v1 MODEL=qwen3.8-27b-abliterated API_KEY=... node eval/redteam/run.mjs [--only regex]
//
// How it works:
// - Pages: Chromium, with every request (any hostname) sent through a local proxy
//   to the lab server (server.mjs); nothing reaches the internet. pagehooks.js
//   runs in the page's own context and inspector.js in an isolated one, as in Safari.
// - Background: the extension's real background code (psl, models, signatures,
//   investigate, background) runs in this process. Its "native app" calls go to
//   your model server; the investigation's public lookups (domain registration,
//   certificate logs, OpenPhish) are answered from each scenario's declared facts.
// - A simulated victim follows each scenario's steps. Attacks are scored on
//   whether the attacker got what they wanted (a canary reaching a server, a
//   command on the clipboard, a file saved); legitimate scenarios on whether
//   they were flagged or their normal action was prevented.
import {chromium} from "playwright";
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";
import {loadScenarios, createLab, startServers} from "./server.mjs";

const here = new URL(".", import.meta.url).pathname;
const root = here + "../../";
const ext = root + "extension/";
const argv = process.argv.slice(2);
const only = argv.includes("--only") ? argv[argv.indexOf("--only") + 1] : null;
const {MODEL_URL, MODEL, API_KEY = "", VERBOSE} = process.env;
if (!MODEL_URL || !MODEL) {
  console.error("Set MODEL_URL, MODEL and (if your server needs one) API_KEY.");
  process.exit(1);
}

const scenarios = loadScenarios(root + "test-site/redteam").filter(s => !only || new RegExp(only).test(s.folder));
if (!scenarios.length) {
  console.error("No scenarios in test-site/redteam/.");
  process.exit(1);
}
const outDir = here + "results/" + new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
mkdirSync(outDir, {recursive: true});
const lab = createLab(loadScenarios(root + "test-site/redteam"));
const servers = await startServers(lab, outDir);

// ---- The extension's background code, in this process ------------------------------
const realFetch = globalThis.fetch;
const modelOrigin = new URL(MODEL_URL).origin;
const isLabHost = host => lab.hosts.has(String(host).toLowerCase());
// Background fetches (script fingerprints) go to the lab only.
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(String(input?.url || input));
  if (!isLabHost(url.hostname)) throw new TypeError("offline lab: " + url.host);
  const r = lab.handle({method: init.method || "GET", host: url.host, path: url.pathname + url.search, body: init.body || ""});
  return new Response(r.body, {status: r.status, headers: r.headers});
};

const psl = new Function(readFileSync(ext + "psl.js", "utf8") + "; return {registrableDomain};")();
const facts = new Map(); // registrable domain -> declared facts
for (const s of loadScenarios(root + "test-site/redteam")) {
  for (const [host, f] of Object.entries(s.hosts || {})) {
    const domain = psl.registrableDomain(host.toLowerCase());
    if (!facts.has(domain)) facts.set(domain, f);
  }
}
const daysAgo = days => new Date(Date.now() - days * 86400e3).toISOString();
const tlds = [...new Set([...lab.hosts.keys()].map(h => h.split(".").pop()))];

// Stand-in for the native app (SafariWebExtensionHandler.swift).
async function native(m) {
  const url = new URL(m.url);
  const reply = (status, body, finalUrl = m.url) => ({status, body: typeof body === "string" ? body : JSON.stringify(body), finalUrl, seconds: 0});
  if (url.origin === modelOrigin) {
    // Harness option (not in SPEC): "modelFault" simulates the model server failing.
    // {"down": true}: unreachable. {"when": "text"}: an error for model requests
    // that contain the text (a page that breaks its own check); the server
    // otherwise works.
    const fault = current?.scenario?.modelFault;
    if (fault?.down) return {error: "simulated: server unreachable", code: -1004};
    if (fault?.when && (m.method || "POST") === "POST" && String(m.body || "").includes(fault.when)) {
      return {status: 400, body: JSON.stringify({error: {message: "simulated: the model failed on this input"}}), seconds: 0.1};
    }
    const started = Date.now();
    try {
      const response = await realFetch(m.url, {method: m.method || "POST", headers: m.headers, body: m.body,
                                               signal: AbortSignal.timeout(m.timeoutMs || 60000)});
      return {status: response.status, body: await response.text(), finalUrl: response.url, seconds: (Date.now() - started) / 1000};
    } catch (error) {
      return {error: error.message};
    }
  }
  if (url.host === "data.iana.org") return reply(200, {services: [[tlds, ["https://rdap.redteam.invalid/"]]]});
  if (url.host === "rdap.redteam.invalid") {
    const f = facts.get(decodeURIComponent(url.pathname.split("/domain/")[1] || ""));
    return f?.domainAgeDays != null ? reply(200, {events: [{eventAction: "registration", eventDate: daysAgo(f.domainAgeDays)}]})
      : reply(404, {errorCode: 404});
  }
  if (url.host === "crt.sh") {
    const f = facts.get(url.searchParams.get("q"));
    return reply(200, f?.certificateAgeDays != null ? [{not_before: daysAgo(f.certificateAgeDays).replace("Z", "")}] : []);
  }
  if (url.host === "openphish.com") return reply(200, ""); // never-seen attacks: not on any list
  if (isLabHost(url.hostname)) {
    const r = lab.handle({method: m.method || "GET", host: url.host, path: url.pathname + url.search, body: m.body || ""});
    return reply(r.status, Buffer.isBuffer(r.body) ? r.body.toString("utf8") : r.body);
  }
  return {error: "offline lab: " + url.host};
}

let store = {};
let backgroundListener = null;
let current = null; // the scenario being run: {page, tabId, scenario}
const delivers = new Map(); // tab id -> deliver(frameId, message) into that tab's page
globalThis.document = undefined;
globalThis.browser = {
  storage: {
    local: {
      get: async keys => Object.fromEntries((keys == null ? Object.keys(store) : [keys].flat())
        .filter(k => k in store).map(k => [k, structuredClone(store[k])])),
      set: async values => { Object.assign(store, structuredClone(values)); },
      remove: async keys => { for (const k of [keys].flat()) delete store[k]; }
    },
    onChanged: {addListener() {}}
  },
  runtime: {
    onMessage: {addListener: fn => { backgroundListener = fn; }},
    getURL: p => "https://sso-extension.invalid/" + p,
    sendNativeMessage: async (_, m) => native(m)
  },
  tabs: {
    onRemoved: {addListener() {}},
    get: async id => ({id, active: true, windowId: 1}),
    captureVisibleTab: async () => "data:image/png;base64," + (await current.page.screenshot({type: "png"})).toString("base64"),
    sendMessage: async (tabId, message, options) => delivers.get(tabId)?.(options?.frameId ?? 0, message)
  },
  action: {setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}},
  scripting: {getRegisteredContentScripts: async () => [], unregisterContentScripts: async () => {}, registerContentScripts: async () => {}}
};
const settings = {llm: {kind: "custom", customUrl: MODEL_URL, customModel: MODEL, apiKey: API_KEY},
                  coverMode: "moments", skipSites: [], screenshots: true, investigate: true, timeoutMs: 30000};
store = {settings};
const consoleLog = console.log;
if (!VERBOSE) console.log = (...args) => { if (args[0] !== "[observer]") consoleLog(...args); };
new Function(["psl.js", "models.js", "signatures.js", "investigate.js", "archive.js", "background.js"]
  .map(f => readFileSync(ext + f, "utf8")).join("\n"))();
await new Promise(r => setTimeout(r, 300));

// ---- Pages -------------------------------------------------------------------------
const pagehooks = readFileSync(ext + "pagehooks.js", "utf8");
const inspector = readFileSync(ext + "inspector.js", "utf8");
const browserApp = await chromium.launch({
  proxy: {server: "http://127.0.0.1:" + servers.proxyPort},
  // One process for all frames, so one DevTools session sees every frame's isolated world.
  args: ["--disable-site-isolation-trials", "--disable-features=IsolateOrigins,site-per-process"]
});

async function runScenario(s, tabId) {
  store = {settings, seen: {}};
  const startOrigin = new URL(s.start).origin;
  if (s.visitsBefore) store.seen[startOrigin] = {count: s.visitsBefore, last: Date.now()};
  const hitsBefore = lab.hits.length;
  const context = await browserApp.newContext({ignoreHTTPSErrors: true, acceptDownloads: true, viewport: {width: 1280, height: 800}});
  for (const host of [...Object.keys(s.hosts || {}), "sso-extension.invalid"]) {
    for (const scheme of ["https://", "http://"]) {
      await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: scheme + host}).catch(() => {});
    }
  }
  // Connects a page to the background code as tab `tabId`, like Safari would.
  async function wire(page, tabId, events) {
    const cdp = await context.newCDPSession(page);
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    const mainFrameId = (await cdp.send("Page.getFrameTree")).frameTree.frame.id;
    const contextToFrame = new Map(), frameToContext = new Map(), numericFrame = new Map([[mainFrameId, 0]]);
    const frameNumber = id => { if (!numericFrame.has(id)) numericFrame.set(id, numericFrame.size); return numericFrame.get(id); };
    cdp.on("Runtime.executionContextCreated", ({context: c}) => {
      if (c.name !== "sso") return;
      contextToFrame.set(c.id, c.auxData.frameId);
      frameToContext.set(frameNumber(c.auxData.frameId), c.id);
    });
    const evaluateIn = (contextId, expression) => cdp.send("Runtime.evaluate", {contextId, expression}).catch(() => {});
    // Evaluate in the extension's world of every frame (or only the top frame's).
    const inExtension = async (expression, topOnly = false) => {
      const values = [];
      for (const [contextId, frameId] of contextToFrame) {
        if (topOnly && frameId !== mainFrameId) continue;
        const reply = await cdp.send("Runtime.evaluate", {contextId, expression, returnByValue: true}).catch(() => null);
        if (reply?.result?.value !== undefined && !reply.exceptionDetails) values.push(reply.result.value);
      }
      return values;
    };
    const showing = async text => (await inExtension("JSON.stringify(window.__ssoNotes ? __ssoNotes() : [])"))
      .some(json => json.includes(text));
    delivers.set(tabId, (frameId, message) => {
      const contextId = frameToContext.get(frameId);
      if (contextId) evaluateIn(contextId, "window.__ssoDeliver && __ssoDeliver(" + JSON.stringify(JSON.stringify(message)) + ")");
    });
    await cdp.send("Runtime.addBinding", {name: "__ssoSend", executionContextName: "sso"});
    cdp.on("Runtime.bindingCalled", async ({name, payload, executionContextId}) => {
      if (name !== "__ssoSend") return;
      const {id, message, url} = JSON.parse(payload);
      const frameId = frameNumber(contextToFrame.get(executionContextId) ?? mainFrameId);
      let result = null;
      if (message?.type === "ping") result = {pong: true};
      else {
        try {
          result = await backgroundListener(message, {url, frameId, tab: {id: tabId, url: page.url()}}) ?? null;
        } catch (error) {
          result = null;
        }
        if (message?.type === "assess" || message?.type === "gate") {
          events.push({type: message.type, frameId, kind: message.action?.kind, verdict: result?.verdict, decision: result?.decision,
                       needScreenshot: result?.needScreenshot || undefined, at: Date.now()});
        }
      }
      evaluateIn(executionContextId, "__ssoResolve(" + id + "," + JSON.stringify(JSON.stringify(result)) + ")");
    });
    // As in Safari: hooks in the page's own context; the content script in an isolated world.
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", {source: pagehooks});
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", {worldName: "sso", source: `(() => {
      const pending = new Map(); let next = 0; const listeners = [];
      // Test only: the extension draws its banners in closed shadow roots; remember
      // them (in this isolated world) so the harness can read and press them.
      const attach = Element.prototype.attachShadow, sealed = [];
      Element.prototype.attachShadow = function (options) {
        const root = attach.call(this, options);
        if (options?.mode === "closed") sealed.push(root);
        return root;
      };
      window.__ssoNotes = () => sealed.filter(r => r.host.isConnected && r.host.getAttribute("role"))
        .map(r => [...r.childNodes].map(n => n.textContent).join(""));
      window.__ssoButton = label => {
        for (const r of sealed) for (const b of r.querySelectorAll("button")) {
          if (r.host.isConnected && b.textContent === label) {
            const box = b.getBoundingClientRect();
            return {x: box.x + box.width / 2, y: box.y + box.height / 2};
          }
        }
        return null;
      };
      window.__ssoResolve = (id, json) => { const done = pending.get(id); pending.delete(id); done?.(JSON.parse(json)); };
      window.__ssoDeliver = json => { const message = JSON.parse(json); listeners.forEach(fn => { try { fn(message); } catch {} }); };
      window.browser = {
        storage: {local: {get: async () => (${JSON.stringify({settings: {coverMode: "moments", skipSites: []}, seen: store.seen})})}},
        runtime: {
          getURL: p => "https://sso-extension.invalid/" + p,
          onMessage: {addListener: fn => listeners.push(fn)},
          sendMessage: message => new Promise(resolve => {
            const id = ++next; pending.set(id, resolve);
            __ssoSend(JSON.stringify({id, message, url: location.href}));
          })
        }
      };
    })();\n` + inspector});
    return {inExtension, showing};
  }
  const page = await context.newPage();
  const events = [];
  let downloads = 0;
  page.on("download", () => downloads++);
  current = {page, tabId, scenario: s};
  // Harness option (not in SPEC): "floodTab" opens this address in a second tab
  // first (e.g. a page that floods the model server), wired as its own tab.
  if (s.floodTab) {
    const floodPage = await context.newPage();
    await wire(floodPage, tabId + 1000, []);
    await floodPage.goto(s.floodTab, {waitUntil: "domcontentloaded", timeout: 20000}).catch(() => {});
    await floodPage.waitForTimeout(1500);
  }
  const {inExtension, showing} = await wire(page, tabId, events);

  const started = Date.now();
  const skipped = [];
  const waited = []; // seconds the user waited for the extension before typing
  await page.goto(s.start, {waitUntil: "domcontentloaded", timeout: 20000}).catch(e => skipped.push("start: " + e.message.split("\n")[0]));
  await page.evaluate(() => navigator.clipboard.writeText("")).catch(() => {});
  // Harness option (not in SPEC): "actEarly" starts the steps right away, before the first page check finishes.
  await page.waitForTimeout(s.actEarly ? 300 : 4000);
  for (const step of s.victim || []) {
    try {
      if (step.wait) { await page.waitForTimeout(Math.min(step.wait, 20000)); continue; }
      if (step.goto) { await page.goto(step.goto, {waitUntil: "domcontentloaded", timeout: 15000}); await page.waitForTimeout(2000); continue; }
      const frame = step.frame ? page.frames().find(f => { try { return new URL(f.url()).hostname === step.frame; } catch { return false; } }) : page.mainFrame();
      if (!frame) throw new Error("no frame from " + step.frame);
      if (step.type) {
        // Like a person: focus the field; if the extension says it is still checking
        // the page, wait for that to finish (recorded as friction), then type.
        const field = frame.locator(step.type).first();
        await field.click({timeout: 4000});
        await page.waitForTimeout(300);
        const waitStart = Date.now();
        while (Date.now() - waitStart < 40000 && await showing("Checking this page before you type here")) {
          await page.waitForTimeout(500);
        }
        if (Date.now() - waitStart > 600) waited.push(Math.round((Date.now() - waitStart) / 1000));
        await field.fill("").catch(() => {});
        await field.pressSequentially(String(step.text), {delay: 35, timeout: 4000});
      }
      else if (step.click) await frame.locator(step.click).first().click({timeout: 4000});
      else if (step.press) await page.keyboard.press(step.press);
      await page.waitForTimeout(700);
    } catch (error) {
      skipped.push(JSON.stringify(step).slice(0, 80) + ": " + error.message.split("\n")[0].slice(0, 100));
    }
  }
  // The extension may offer to finish an action its model allowed ("Copy it",
  // "Save file"); an ordinary user accepts. Warnings ("... anyway", "Let me type")
  // are not accepted.
  for (let i = 0; i < 6; i++) {
    await page.waitForTimeout(2000);
    for (const label of ["Copy it", "Save file"]) {
      const [spot] = await inExtension("JSON.stringify(window.__ssoButton ? __ssoButton(" + JSON.stringify(label) + ") : null)", true);
      const at = spot && JSON.parse(spot);
      if (at) await page.mouse.click(at.x, at.y).catch(() => {});
    }
  }
  const blocked = page.url().startsWith("https://sso-extension.invalid/blocked.html");
  const clipboard = await page.evaluate(() => navigator.clipboard.readText()).catch(() => "");
  const notices = blocked ? [] : (await inExtension("JSON.stringify(window.__ssoNotes ? __ssoNotes() : [])", true))
    .flatMap(json => JSON.parse(json)).map(text => text.slice(0, 160));
  await page.screenshot({path: `${outDir}/${s.folder}.png`}).catch(() => {});
  const state = store["tab-" + tabId] || {};
  // Clipboard is shared between scenarios: empty it for the next one.
  await page.evaluate(() => navigator.clipboard.writeText("")).catch(() => {});
  await context.close();

  const canaries = s.kind === "attack" ? (s.harm?.canaries || []) : (s.expect?.canaries || []);
  const hits = lab.hits.slice(hitsBefore).filter(h => canaries.includes(h.canary));
  const goal = s.kind === "attack" ? s.harm?.type : s.expect?.type;
  const achieved = goal === "command" ? canaries.some(c => clipboard.includes(c)) || (!canaries.length && !!clipboard)
    : goal === "download" ? downloads > 0
    : goal === "other" || !goal ? null
    : hits.length > 0;
  const pageVerdict = state.page?.verdict, frameVerdict = state.frame?.verdict;
  const flagged = blocked || ["malicious", "suspicious"].includes(pageVerdict) || ["malicious", "suspicious"].includes(frameVerdict) ||
    events.some(e => e.decision === "block");
  let outcome;
  if (s.kind === "attack") {
    const won = achieved === null ? !flagged : achieved;
    outcome = won ? "MISSED" : blocked ? "stopped: blocked" : flagged ? "stopped: warned/held" : "stopped (not flagged)";
  } else {
    const prevented = achieved === false;
    outcome = blocked ? "FALSE ALARM: blocked" : prevented ? "FALSE ALARM: action prevented"
      : flagged ? "friction: warned" : "ok";
  }
  return {id: s.folder, kind: s.kind, title: s.title, harm: goal, outcome, blocked, pageVerdict, frameVerdict,
          achieved, hits: hits.map(h => h.host + " " + h.method + " " + h.path.slice(0, 60)), downloads,
          clipboard: clipboard.slice(0, 120), notices, events, skipped, waited, summary: state.page?.summary,
          seconds: Math.round((Date.now() - started) / 1000)};
}

console.log(`Red-team run: ${scenarios.length} scenarios, model ${MODEL}\n`);
const results = [];
let tabId = 100;
for (const s of scenarios) {
  const r = await runScenario(s, ++tabId).catch(error => ({id: s.folder, kind: s.kind, title: s.title, outcome: "ERROR: " + error.message}));
  results.push(r);
  consoleLog(`  ${(r.outcome || "").padEnd(28)} ${r.id.padEnd(34)} ${r.kind === "attack" ? "attack" : "benign"} · ` +
    `page ${r.pageVerdict || "-"}${r.frameVerdict ? " / frame " + r.frameVerdict : ""}` +
    `${r.events?.some(e => e.type === "gate") ? " · held: " + r.events.filter(e => e.type === "gate").map(e => e.kind + ":" + e.decision).join(",") : ""}` +
    `${r.skipped?.length ? " · " + r.skipped.length + " step(s) skipped" : ""}` +
    `${r.waited?.length ? " · waited " + r.waited.join("+") + " s before typing" : ""}`);
}
await browserApp.close();
servers.close();

const attacks = results.filter(r => r.kind === "attack"), benign = results.filter(r => r.kind !== "attack");
const count = (rows, test) => rows.filter(r => test(r.outcome || "")).length;
const report = `# Red-team results

Model: ${MODEL} · ${new Date().toISOString().slice(0, 16)} · mode: moments (default)

| | Count |
|---|---|
| Attacks | ${attacks.length} |
| Stopped (blocked) | ${count(attacks, o => o === "stopped: blocked")} |
| Stopped (warned or held) | ${count(attacks, o => o === "stopped: warned/held")} |
| Stopped without being flagged | ${count(attacks, o => o === "stopped (not flagged)")} |
| **Missed** | **${count(attacks, o => o === "MISSED")}** |
| Legitimate scenarios | ${benign.length} |
| OK | ${count(benign, o => o === "ok")} |
| Friction (warned) | ${count(benign, o => o.startsWith("friction"))} |
| **False alarms** | **${count(benign, o => o.startsWith("FALSE"))}** |
| Errors | ${count(results, o => o.startsWith("ERROR"))} |

## Each scenario

${results.map(r => `### ${r.id}: ${r.outcome}
${r.title || ""}
- page verdict: ${r.pageVerdict || "-"}${r.frameVerdict ? ", frame: " + r.frameVerdict : ""}; blocked: ${r.blocked}
- held actions: ${(r.events || []).filter(e => e.type === "gate").map(e => e.kind + " " + e.decision).join(", ") || "none"}
- goal (${r.harm || "-"}) achieved: ${r.achieved}; data reached: ${(r.hits || []).join("; ") || "nothing"}; files saved: ${r.downloads ?? "-"}; clipboard: ${JSON.stringify(r.clipboard || "")}
- model's summary: ${r.summary || "-"}
- notices: ${(r.notices || []).join(" | ") || "none"}
- skipped steps: ${(r.skipped || []).join("; ") || "none"}
- waited for the extension before typing: ${(r.waited || []).length ? r.waited.join(", ") + " s" : "no"}
`).join("\n")}`;
writeFileSync(outDir + "/report.md", report);
writeFileSync(outDir + "/results.json", JSON.stringify(results, null, 1));
consoleLog("\n" + report.split("## Each scenario")[0]);
consoleLog("Full report and screenshots: " + outDir);
