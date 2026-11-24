// Runs INSIDE the Docker container (see Dockerfile). Opens each address in headless
// Chromium with the extension's real content script (inspector.js) injected, and
// records exactly what the extension would send to the model, plus the screenshot
// it would take. Nothing is typed, clicked or submitted.
//
//   input:  /work/urls.json   [{id, url}]
//   output: /work/capture/<id>.json, <id>.jpg (model screenshot, if the page asks
//           for secrets), <id>-view.jpg (what the page looked like, for review)
import {chromium} from "playwright";
import {readFileSync, writeFileSync, mkdirSync} from "node:fs";

const work = "/work";
const inspector = readFileSync("/harness/inspector.js", "utf8");
const urls = JSON.parse(readFileSync(work + "/urls.json", "utf8"));
mkdirSync(work + "/capture", {recursive: true});

const safariUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";

// Never let a page reach this machine's network or the Docker host.
function privateHost(host) {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") ||
      h.endsWith(".ts.net") || (!h.includes(".") && !h.includes(":"))) return true;
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  return h.includes(":");
}

// Stand-in for the extension's background script: answers pings, asks for a
// screenshot when the page wants secrets (as the real one does), records every
// assessment, and otherwise answers "safe" so the cover lifts.
const mockBrowser = `
  window.browser = {
    storage: {local: {get: async () => ({settings: {coverMode: "all", skipSites: []}, seen: {}})}},
    runtime: {
      getURL: p => "about:blank#" + p,
      onMessage: {addListener() {}},
      sendMessage: async message => {
        if (message.type === "ping") return {pong: true};
        if (message.type === "capture") { await window.__ssoShot(); return {ok: true}; }
        if (message.type === "assess") {
          await window.__ssoRecord(JSON.stringify(message));
          if (message.asksForSecrets && !message.screenshotTaken) return {needScreenshot: true};
          return {verdict: "safe", summary: "harness"};
        }
        return null;
      }
    }
  };
`;

async function captureOne(browser, {id, url}) {
  const out = {id, url, messages: [], startedAt: new Date().toISOString()};
  const context = await browser.newContext({
    userAgent: safariUA, viewport: {width: 1024, height: 768}, locale: "en-US",
    acceptDownloads: false, serviceWorkers: "block", ignoreHTTPSErrors: false
  });
  const page = await context.newPage();
  let shotTaken = false;
  await context.route("**/*", route => {
    try {
      const u = new URL(route.request().url());
      if (/^https?:$/.test(u.protocol) && privateHost(u.hostname)) return route.abort("blockedbyclient");
    } catch {}
    return route.continue();
  });
  await page.exposeFunction("__ssoRecord", json => { out.messages.push(JSON.parse(json)); });
  await page.exposeFunction("__ssoShot", async () => {
    await page.screenshot({path: `${work}/capture/${id}.jpg`, type: "jpeg", quality: 70});
    shotTaken = true;
  });
  await page.addInitScript(mockBrowser + "\n" + inspector);
  page.on("dialog", dialog => dialog.dismiss().catch(() => {}));
  try {
    const response = await page.goto(url, {waitUntil: "load", timeout: 30000});
    out.status = response?.status() ?? null;
  } catch (error) {
    out.loadError = error.message.split("\n")[0].slice(0, 200);
  }
  // Let late scripts, redirects and the content script's re-checks settle.
  await page.waitForTimeout(8000);
  out.finalUrl = page.url();
  out.screenshotTaken = shotTaken;
  try {
    await page.screenshot({path: `${work}/capture/${id}-view.jpg`, type: "jpeg", quality: 60});
  } catch {}
  await context.close().catch(() => {});
  out.finishedAt = new Date().toISOString();
  writeFileSync(`${work}/capture/${id}.json`, JSON.stringify(out));
  return out;
}

const browser = await chromium.launch();
const queue = [...urls];
const parallel = Number(process.env.PARALLEL || 3);
await Promise.all(Array.from({length: parallel}, async () => {
  while (queue.length) {
    const item = queue.shift();
    const result = await Promise.race([
      captureOne(browser, item),
      new Promise(resolve => setTimeout(() => resolve({id: item.id, url: item.url, loadError: "capture timed out"}), 75000))
    ]).catch(error => ({id: item.id, url: item.url, loadError: error.message.slice(0, 200)}));
    if (result.loadError === "capture timed out") writeFileSync(`${work}/capture/${item.id}.json`, JSON.stringify(result));
    console.log((result.loadError ? "  failed  " : "  ok      ") + item.id + "  " + item.url.slice(0, 90));
  }
}));
await browser.close();
