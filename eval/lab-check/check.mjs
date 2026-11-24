// Runs INSIDE the sandbox container (see run.mjs), with no network. Tests the
// extension's page scripts (pagehooks.js, cover-now.js, inspector.js) against
// evasion techniques: does the evidence reach the background script, and is the
// harmful moment stopped?
//
// The background script is replaced by a stand-in with a "perfect model": it
// flags a page as malicious when the signals it receives show a password or
// card field on a site other than examplebank, tech-support-scam text, or a
// clipboard command; it blocks clipboard commands except on the install-docs
// control, and blocks HTML files the page built itself. So a failure here means
// the evidence never reached the model, not that a model misjudged it.
//
// Limitation: Playwright runs all of these scripts in the page's own context,
// while Safari runs inspector.js in an isolated one. Paths where the extension
// copies or saves something itself after the model allows it are therefore only
// checked up to the offer (the banner), not the copy or save itself.
import {chromium} from "/harness/node_modules/playwright/index.mjs";
import {readFileSync} from "node:fs";
import {spawn} from "node:child_process";
import {inflateSync} from "node:zlib";

const manifest = JSON.parse(readFileSync("/ext/manifest.json", "utf8"));
const inspectorEntry = manifest.content_scripts.find(c => c.js.includes("inspector.js"));
const allFrames = inspectorEntry?.all_frames === true;
const hasHooks = manifest.content_scripts.some(c => c.js.includes("pagehooks.js"));
const read = file => { try { return readFileSync("/ext/" + file, "utf8"); } catch { return ""; } };
const inspector = read("inspector.js"), pagehooks = hasHooks ? read("pagehooks.js") : "", coverNow = read("cover-now.js");
const lab = name => `http://${name}.localhost:8765/`;

const server = spawn("node", ["/site/server.mjs"], {stdio: "ignore"});
await new Promise(resolve => setTimeout(resolve, 800));
const get = async path => (await fetch("http://127.0.0.1:8765" + path)).json();

// What the stand-in model concludes from the signals it was sent.
function judge(message) {
  const s = message.signals || {};
  const secretFields = (s.forms || []).some(f => f.hasPassword || f.asksForPayment) || (s.secretFields || []).length > 0;
  const host = new URL(s.page?.origin || "http://none").hostname;
  if (host === "install-docs.localhost") return "safe";
  if (secretFields && host !== "examplebank.localhost") return "malicious";
  if ((s.clipboardCommands || []).length) return "malicious";
  if (/infected|call .*support/i.test((s.text || "") + " " + (s.page?.title || ""))) return "malicious";
  return "safe";
}
function gate(message, forced) {
  const action = message.action || {};
  const host = new URL(message.signals?.page?.origin || "http://none").hostname;
  if (action.kind === "clipboard") return host === "install-docs.localhost" ? "allow" : "block";
  if (action.kind === "download") return /\.html?$/i.test(action.file?.name || action.url || "") ? "block" : "allow";
  return (forced || judge(message)) === "safe" ? "allow" : "block";
}

async function run(browser, {name, site, mode = "moments", wait = 6000, typeInto, typeFrame, verdict: forced, click, probeTop,
                             pressBanner, saveFile, refuseBlockPage, urlSuffix = "", openedAnyway, breakStart}) {
  await get("/lab/received/clear");
  const context = await browser.newContext({viewport: {width: 1024, height: 768}, acceptDownloads: true});
  await context.grantPermissions(["clipboard-read", "clipboard-write"], {origin: lab(site).slice(0, -1)});
  const log = [];
  const started = Date.now();
  // A navigation answered with 204 is cancelled: the page stays, as when Safari refuses.
  if (refuseBlockPage) await context.route("http://ext-refused.invalid/**", route => route.fulfill({status: 204}));
  const page = await context.newPage();
  let downloads = 0;
  page.on("download", () => downloads++);

  // Background stand-in. Mirrors the real protocol: a malicious verdict for a
  // frame is relayed to the top frame as a "frame-verdict" message.
  await context.exposeBinding("__ssoBackground", async ({frame}, json) => {
    const message = JSON.parse(json);
    const entry = {type: message.type, kind: message.action?.kind, at: Date.now() - started, top: message.top,
                   fileSize: message.action?.file?.size};
    log.push(entry);
    if (message.type !== "assess" && message.type !== "gate") return "null";
    await new Promise(resolve => setTimeout(resolve, 1200)); // model time
    if (message.type === "gate") {
      entry.decision = gate(message, forced);
      return JSON.stringify({decision: entry.decision});
    }
    if (message.asksForSecrets && !message.screenshotTaken && !message.trusted) return JSON.stringify({needScreenshot: true});
    // "no-answer": the check fails (the model timed out or errored).
    if (forced === "no-answer") { entry.verdict = "none"; return "null"; }
    const verdict = forced || judge(message);
    const result = {verdict, summary: "stand-in model", ...(openedAnyway ? {allowedByUser: true} : {}), source: "lab check", bypassToken: "00000000-0000-0000-0000-000000000000"};
    entry.verdict = verdict;
    if (!message.top && verdict === "malicious") {
      await page.mainFrame().evaluate(m => (window.__ssoListeners || []).forEach(fn => fn(m)),
        {type: "frame-verdict", result: {...result, frameUrl: message.frameUrl}}).catch(() => {});
    }
    return JSON.stringify(result);
  });
  // Order as in Safari: page-context hooks, then (in "all" mode) the early cover, then inspector.js.
  if (pagehooks) await context.addInitScript(pagehooks);
  await context.addInitScript(`(() => {
    const top = window === window.top;
    if (!top && !${allFrames}) return;
    // Test only: remember the extension's closed shadow roots (banners) so this
    // check can read what it showed. Nothing in the page uses this.
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
    window.browser = {
      // breakStart: settings that make the page script throw while starting.
      storage: {local: {get: async () => ({settings: {coverMode: "${mode}", skipSites: ${breakStart ? 42 : "[]"}}, seen: {}})}},
      runtime: {
        // refuseBlockPage: the block page can't be opened (as when Safari refuses to
        // leave a page the user reached through its own warning).
        getURL: p => ${refuseBlockPage ? '"http://ext-refused.invalid/" + p' : '"about:blank#ext-" + p'},
        onMessage: {addListener(fn) { (window.__ssoListeners ||= []).push(fn); }},
        sendMessage: async m => {
          if (m.type === "ping") return {pong: true};
          if (m.type === "capture") return {ok: true};
          return JSON.parse(await window.__ssoBackground(JSON.stringify({...m, top, frameUrl: location.href})));
        }
      }
    };
    ${mode === "all" ? coverNow : ""}
    ${inspector}
  })();`);

  await page.goto(lab(site) + urlSuffix, {waitUntil: "domcontentloaded"}).catch(() => {});
  // Is the extension's cover the topmost thing on screen (while the check is pending)?
  let coverOnTop = null;
  if (probeTop) {
    await page.waitForTimeout(400);
    // By pixel colour near the corner: the cover is light grey; cover-race's fake
    // login dialog has a dark blue backdrop. (Hit-testing can't tell: a modal dialog
    // makes everything else inert, even what is drawn above it.)
    const png = await page.screenshot({clip: {x: 8, y: 8, width: 1, height: 1}});
    const [r, g, b] = pixel(png);
    coverOnTop = r > 200 && g > 200 && b > 200;
  }
  // Type into a secret field early (while the check is pending) and again later.
  const typeOnce = async () => {
    try {
      const frame = typeFrame ? page.frames().find(f => f.url().includes(typeFrame)) : page.mainFrame();
      // Like a person coming back to the field: leave it, then click into it again.
      await frame?.locator(typeInto).evaluate(field => field.blur()).catch(() => {});
      await frame?.locator(typeInto).click({timeout: 1500}).catch(() => {});
      await page.waitForTimeout(300);
      await frame?.locator(typeInto).pressSequentially("secret", {delay: 20, timeout: 1500});
    } catch {}
  };
  if (typeInto) {
    await page.waitForTimeout(500);
    await typeOnce();
  }
  await page.waitForTimeout(wait / 2);
  // A person pressing one of the extension's own buttons (a real mouse click).
  if (pressBanner) {
    await page.locator(typeInto).evaluate(field => field.blur()).catch(() => {});
    await page.locator(typeInto).click({timeout: 1500}).catch(() => {});
    await page.waitForTimeout(300);
    const spot = await page.evaluate(label => window.__ssoButton?.(label), pressBanner).catch(() => null);
    if (spot) await page.mouse.click(spot.x, spot.y);
    await page.waitForTimeout(300);
  }
  if (typeInto) await typeOnce();
  if (click) await page.locator(click).click({timeout: 1500}).catch(() => {});
  // A person accepting the extension's "Save file" once the check is done.
  if (saveFile) {
    await page.waitForTimeout(2500);
    const spot = await page.evaluate(() => window.__ssoButton?.("Save file")).catch(() => null);
    if (spot) await page.mouse.click(spot.x, spot.y);
  }
  await page.waitForTimeout(wait / 2);

  // A red full-page cover instead of the block page (the fallback): probe a corner pixel.
  let redCover = false;
  if (refuseBlockPage) {
    const [r, g, b] = pixel(await page.screenshot({clip: {x: 8, y: 8, width: 1, height: 1}}));
    redCover = r > 150 && g < 80 && b < 80;
  }
  const blocked = page.url().startsWith("about:blank#ext-blocked");
  const clipboard = blocked ? "" : await page.evaluate(() => navigator.clipboard.readText()).catch(() => "");
  const offered = blocked ? [] : await page.evaluate(() =>
    window.__ssoNotes ? window.__ssoNotes() : []).catch(() => []);
  const leaked = (await get("/lab/received")).filter(r => r.path === "/keys" || r.path === "/collect").length;
  await context.close();
  return {name, blocked, redCover, leaked, failedReported: log.some(m => m.type === "failed"), downloads, clipboard, offered, coverOnTop,
          gates: log.filter(m => m.type === "gate").map(m => m.kind + ":" + m.decision + (process.env.VERBOSE && m.fileSize !== undefined ? "(" + m.fileSize + " bytes)" : "")),
          checks: log.filter(m => m.type === "assess").length,
          frameChecks: log.filter(m => m.type === "assess" && m.top === false).length};
}

const has = (list, text) => list.some(item => item.includes(text));

// RGB of a 1x1 PNG screenshot.
function pixel(png) {
  let offset = 8, data = [];
  while (offset < png.length) {
    const length = png.readUInt32BE(offset), type = png.toString("ascii", offset + 4, offset + 8);
    if (type === "IDAT") data.push(png.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
  }
  const raw = inflateSync(Buffer.concat(data));
  return [raw[1], raw[2], raw[3]]; // after the row's filter byte
}
const scenarios = [
  // Step 1: evasion of the page scan.
  {name: "Login inside a full-page frame", site: "shared-doc", ok: r => r.blocked},
  {name: "Login without a form, keystrokes sent", site: "formless-login", typeInto: "#p", ok: r => r.blocked && !r.leaked},
  {name: "Page turns into a scam later", site: "late-swap", wait: 15000, ok: r => r.blocked},
  {name: "One malformed link on the page", site: "bad-link", ok: r => r.blocked},
  {name: "Suspicious page: password typing locked", site: "formless-login", typeInto: "#p", verdict: "suspicious",
   ok: r => !r.blocked && !r.leaked},
  {name: "Page can't press 'Let me type' itself", site: "self-unlock", typeInto: "#p", verdict: "suspicious",
   ok: r => !r.blocked && !r.leaked},
  {name: "A person can still choose 'Let me type'", site: "formless-login", typeInto: "#p", verdict: "suspicious",
   pressBanner: "Let me type", ok: r => !r.blocked && r.leaked > 0},
  {name: "Check fails: password typing locked", site: "formless-login", typeInto: "#p", verdict: "no-answer",
   ok: r => !r.blocked && !r.leaked && has(r.offered, "could not check")},
  {name: "Model unreachable: password typing locked", site: "formless-login", typeInto: "#p", verdict: "unchecked",
   ok: r => !r.blocked && !r.leaked},
  {name: "Check fails: a person can still choose to type", site: "formless-login", typeInto: "#p", verdict: "no-answer",
   pressBanner: "Let me type", ok: r => !r.blocked && r.leaked > 0},
  {name: "Script-sent login: click held for a check", site: "formless-login", typeInto: "#p", click: "#go",
   verdict: "safe", ok: r => has(r.gates, "submit:")},
  // Step 2: moments of harm.
  {name: "ClickFix: clipboard API", site: "clickfix", click: "#verify",
   ok: r => !/curl/.test(r.clipboard) && has(r.gates, "clipboard:block") && r.blocked},
  {name: "ClickFix: hidden textarea + copy", site: "clickfix", click: "#verify2",
   ok: r => !/base64/.test(r.clipboard) && has(r.gates, "clipboard:block") && r.blocked},
  {name: "HTML smuggling: file built by the page", site: "smuggle", ok: r => r.downloads === 0 && has(r.gates, "download:block")},
  {name: "Cover can't be beaten (check-every-page mode)", site: "cover-race", mode: "all", probeTop: true, typeInto: "#p",
   ok: r => r.coverOnTop && !r.leaked && r.blocked},
  // Controls: nothing legitimate breaks.
  {name: "Block page refused: page covered instead", site: "formless-login", typeInto: "#p", verdict: "malicious",
   refuseBlockPage: true, ok: r => !r.blocked && r.redCover && !r.leaked},
  // A "//" path plus a bypass code in the link once crashed the page script before
  // any check (found on a live phishing page); a crafted link could do it on purpose.
  {name: "Double-slash path + bypass code: still checked", site: "formless-login", verdict: "malicious",
   urlSuffix: "/index.html#sso-bypass=00000000-0000-0000-0000-000000000000", ok: r => r.blocked},
  {name: "Opened anyway: page can't remove the warning bar", site: "bar-remover", verdict: "malicious", openedAnyway: true,
   ok: r => !r.blocked && has(r.offered, "You chose to open it anyway")},
  {name: "Script can't start: page says it isn't protected", site: "formless-login", breakStart: true,
   ok: r => has(r.offered, "could not check this page") && r.failedReported},
  {name: "Control: install docs copy button", site: "install-docs", click: "#copy",
   ok: r => !r.blocked && has(r.gates, "clipboard:allow") && has(r.offered, "found no problem")},
  {name: "Control: real bank login", site: "examplebank", typeInto: "#p", ok: r => !r.blocked}
];

const browser = await chromium.launch();
console.log(`inspector.js runs in frames: ${allFrames ? "yes" : "no"} · page-context hooks: ${hasHooks ? "yes" : "no"}\n`);
let failures = 0;
// ONLY=<regex>: run just the matching scenarios.
for (const scenario of scenarios.filter(s => !process.env.ONLY || new RegExp(process.env.ONLY, "i").test(s.name + " " + s.site))) {
  const r = await run(browser, scenario);
  if (process.env.VERBOSE) console.log("   offered:", JSON.stringify(r.offered));
  const ok = !!scenario.ok(r);
  if (!ok) failures++;
  const details = [
    "checks: " + r.checks + (r.frameChecks ? " (" + r.frameChecks + " from frames)" : ""),
    "page " + (r.blocked ? "BLOCKED" : "not blocked"),
    r.leaked && "data sent out " + r.leaked + "x",
    r.gates.length && "held: " + r.gates.join(", "),
    r.downloads && "files saved: " + r.downloads,
    r.clipboard && "clipboard: " + JSON.stringify(r.clipboard.slice(0, 30)),
    r.coverOnTop !== null && "cover on top: " + (r.coverOnTop ? "yes" : "NO")
  ].filter(Boolean).join(" · ");
  console.log(`${ok ? "  PASS" : "  FAIL"}  ${r.name.padEnd(46)} ${details}`);
}
await browser.close();
server.kill();
console.log(`\n${scenarios.length - failures} of ${scenarios.length} passed`);
process.exit(failures ? 1 : 0);
