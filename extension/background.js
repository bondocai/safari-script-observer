// Decides what to do with page signals and held actions, using the models the
// user enabled in Settings (see models.js):
//   page check and action gate: the user's model server; local rules only
//   when no server is configured or it cannot be reached
// The local test site and its lab (http://<name>.localhost:8765): the only
// private addresses the scanners may fetch.
function isTestSite(url) {
  return url.port === "8765" && (url.hostname === "localhost" || url.hostname.endsWith(".localhost"));
}
const sequence = new Map();

const log = (...args) => console.log("[observer]", new Date().toISOString().slice(11, 23), ...args);
log("background started");

// "Check every page" mode: cover-now.js is registered to run at document start,
// so pages are covered before they draw (no settings read in the page first).
// Trusted sites are excluded. Re-synced whenever settings change.
async function syncEarlyCover() {
  await settingsReady;
  const id = "early-cover";
  try {
    const existing = await browser.scripting.getRegisteredContentScripts({ids: [id]});
    if (existing.length) await browser.scripting.unregisterContentScripts({ids: [id]});
    if (settings.coverMode !== "all") return;
    const excludeMatches = (settings.skipSites || []).filter(d => /^[a-z0-9.-]+$/i.test(d))
      .flatMap(d => ["*://" + d + "/*", "*://*." + d + "/*"]);
    await browser.scripting.registerContentScripts([{id, js: ["cover-now.js"], matches: ["http://*/*", "https://*/*"],
      ...(excludeMatches.length ? {excludeMatches} : {}), runAt: "document_start", allFrames: false}]);
  } catch (error) {
    log("early cover registration failed:", error?.message || error);
  }
}
syncEarlyCover();
browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) setTimeout(syncEarlyCover, 50);
});

browser.runtime.onMessage.addListener((message, sender) => {
  // The options page (an extension page) can ask for status and model lists.
  if (sender.url?.startsWith(browser.runtime.getURL(""))) return handleSettingsMessage(message);

  log("message", message?.type, "from", sender.url, "tab", sender.tab?.id);
  const pageUrl = pageAddress(sender.url);
  if (!pageUrl) return;
  if (message.type === "ping") return Promise.resolve({pong: true});
  if (message.type === "bypass") return redeemBypass(sender.tab?.id ?? -1, pageUrl, message.token);
  if (message.type === "capture") return captureTab(sender.tab, pageUrl).catch(error => {
    log("screenshot failed:", error?.message || error);
    return {ok: false};
  });
  const tabId = sender.tab?.id ?? -1;
  // The page script couldn't start: the page is unprotected, so say so.
  if (message.type === "failed") {
    if ((sender.frameId ?? 0) === 0) {
      const url = new URL(pageUrl);
      updateTab(tabId, {page: {verdict: "unchecked", origin: url.origin, path: url.pathname,
        summary: "Safari Script Observer could not start on this page, so it was not checked." +
          (message.error ? " (" + String(message.error).slice(0, 120) + ")" : "")}});
      browser.action.setBadgeText({tabId, text: "?"}).catch(() => {});
      browser.action.setBadgeBackgroundColor({tabId, color: "#b54708"}).catch(() => {});
    }
    return;
  }
  // Frames inside a page (frameId > 0) are checked separately; see assessFrame.
  const frameId = sender.frameId ?? 0;
  const context = message.type === "assess" && {
    asksForSecrets: message.asksForSecrets, screenshotTaken: message.screenshotTaken, url: pageUrl,
    trusted: message.trusted === true, textChanged: message.textChanged === true, frameId,
    scriptUrls: Array.isArray(message.scriptUrls) ? message.scriptUrls.slice(0, 25) : []};
  const work = message.type === "assess"
    ? (frameId === 0
        ? assessPage(tabId, message.signals, message.newPage, message.fp, context)
            .then(result => afterVerdict(tabId, pageUrl, result))
        : assessFrame(tabId, message.signals, message.fp, context, pageAddress(sender.tab?.url) || ""))
    : message.type === "gate" ? gateAction(tabId, message.action, message.signals, pageUrl, frameId)
    : null;
  if (!work) return;
  return work.then(result => {
    log(message.type, "done:", result.verdict || result.decision, "by", result.source);
    return result;
  }, error => {
    log(message.type, "error:", error);
    throw error;
  });
});

// The address a page is checked under. A page a site builds in the browser
// itself (blob:https://site/<id>, e.g. HTML smuggling) belongs to that site.
function pageAddress(raw) {
  try {
    let url = new URL(raw);
    if (url.protocol === "blob:") url = new URL(url.pathname);
    return /^https?:$/.test(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

// ---- First-run setup ------------------------------------------------------------
// The welcome page opens on install, and again once per version while the
// extension still can't see every website (e.g. after Safari reset its access).
// Until then the toolbar icon shows "!" and the popup offers to finish setup.
const allSites = {origins: ["http://*/*", "https://*/*"]};

async function hasAllSites() {
  try {
    return await browser.permissions.contains(allSites);
  } catch {
    return true; // can't tell: don't nag
  }
}

// The setup page, at most once per version (and never twice at once: on a fresh
// install both the install event and the startup check get here).
let welcomeOpening = false;
async function openWelcomeOnce() {
  if (welcomeOpening) return;
  welcomeOpening = true;
  const version = browser.runtime.getManifest().version;
  const {welcomeShownFor} = await browser.storage.local.get("welcomeShownFor");
  if (welcomeShownFor === version) return;
  await browser.storage.local.set({welcomeShownFor: version});
  browser.tabs.create({url: browser.runtime.getURL("welcome.html")}).catch(() => {});
}

// Setup is unfinished while the extension can't see every website or has no
// model server: "!" on the toolbar icon, and (when asked) the setup page.
async function checkSetup(openIfUnfinished) {
  const ok = await hasAllSites();
  browser.action.setBadgeText({text: ok ? "" : "!"}).catch(() => {});
  if (!ok) browser.action.setBadgeBackgroundColor({color: "#b54708"}).catch(() => {});
  await settingsReady;
  if (openIfUnfinished && (!ok || !llmEnabled())) await openWelcomeOnce();
}

// Turning the extension on starts this script: a first-time user lands on the
// setup page right away (the app's window closes at the same moment).
browser.runtime.onInstalled?.addListener(() => checkSetup(true));
browser.permissions?.onAdded?.addListener(() => checkSetup(false));
browser.permissions?.onRemoved?.addListener(() => checkSetup(false));
if (browser.permissions) checkSetup(true);

// A tab loading a new page starts without the last page's badge (e.g. a "!" left
// over when the next page is one of Safari's own error pages, which aren't checked).
browser.tabs.onUpdated?.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading") return;
  // null: back to the toolbar-wide badge (the setup "!"), where supported.
  browser.action.setBadgeText({tabId, text: null})
    .catch(() => browser.action.setBadgeText({tabId, text: ""}).catch(() => {}));
});

browser.tabs.onRemoved.addListener(tabId => {
  tabs.delete(tabId);
  secretFrames.delete(tabId);
  screenshots.delete(tabId);
  browser.storage.local.remove("tab-" + tabId).catch(() => {});
  forgetBypasses(tabId).catch(() => {});
  browser.storage.local.get("lastSafe").then(({lastSafe = {}}) => {
    delete lastSafe[tabId];
    return browser.storage.local.set({lastSafe});
  }).catch(() => {});
});

// After a verdict: remember the tab's last page that was not blocked (for "Go
// back to safety"), and for a block, hand out a one-time code that the block
// page's "Visit this unsafe page" link carries back to this tab and page.
async function afterVerdict(tabId, url, result) {
  const page = url.split("#")[0];
  const store = await browser.storage.local.get(["lastSafe", "bypassTokens"]);
  const lastSafe = store.lastSafe || {};
  const allowedByUser = result.verdict === "malicious" && await bypassedHere(tabId, page);
  if (result.verdict !== "malicious" || allowedByUser) {
    lastSafe[tabId] = page;
    await browser.storage.local.set({lastSafe});
    return {...result, tabId, allowedByUser};
  }
  const tokens = Object.fromEntries(Object.entries(store.bypassTokens || {})
    .filter(([, t]) => Date.now() - t.at < 30 * 60 * 1000));
  const token = crypto.randomUUID();
  tokens[token] = {tab: tabId, url: page, at: Date.now()};
  await browser.storage.local.set({bypassTokens: tokens});
  return {...result, tabId, allowedByUser: false, bypassToken: token, backUrl: lastSafe[tabId] || null};
}

// The page script reports a one-time code from the block page. It only counts
// for the same tab and page it was issued for, and only once.
async function redeemBypass(tabId, url, token) {
  const {bypassTokens = {}, bypassed = {}} = await browser.storage.local.get(["bypassTokens", "bypassed"]);
  const issued = bypassTokens[token];
  delete bypassTokens[token];
  const page = url.split("#")[0];
  // The code is random, single-use, and tied to one page, so it is not also tied
  // to the tab ID: Safari may give a tab a new ID after it shows an extension page.
  // The bypass is then recorded under the tab's current ID.
  const valid = !!issued && issued.url === page && Date.now() - issued.at < 30 * 60 * 1000;
  if (valid) bypassed[tabId + "|" + page] = Date.now();
  await browser.storage.local.set({bypassTokens, bypassed});
  log("bypass", valid ? "accepted" : "rejected", "for", page, "| issued for tab", issued?.tab,
      "| redeemed in tab", tabId, issued ? "" : "| unknown or already used code");
  return {ok: valid};
}

// "Visit this unsafe page" on the block page: remembered in storage (so it
// survives Safari suspending this script) for that tab and page only, and
// forgotten when the tab closes. The 12-hour cap covers tabs that vanish
// without a close event, e.g. when Safari quits.
async function bypassedHere(tabId, url) {
  const {bypassed = {}} = await browser.storage.local.get("bypassed");
  const at = bypassed[tabId + "|" + url.split("#")[0]];
  return !!at && Date.now() - at < 12 * 60 * 60 * 1000;
}

async function forgetBypasses(tabId) {
  const {bypassed = {}} = await browser.storage.local.get("bypassed");
  const prefix = tabId + "|";
  const kept = Object.fromEntries(Object.entries(bypassed).filter(([key]) => !key.startsWith(prefix)));
  await browser.storage.local.set({bypassed: kept});
}

async function handleSettingsMessage(message) {
  if (message.type === "forget") {
    await browser.storage.local.remove(["verdicts", "allowed", "bypassed", "bypassTokens", "lastSafe", "seen"]);
    return {ok: true};
  }
  if (message.type === "list-models") {
    try {
      return {models: await listServerModels(message.llm)};
    } catch (error) {
      return {error: error.message};
    }
  }
  if (message.type === "test") {
    await loadSettings();
    const input = {signals: {page: {origin: "https://example.com", path: "/", title: "Example Domain", https: true},
      forms: [], scripts: {externalOrigins: [], inline: []}, iframes: [], downloads: [],
      externalLinkOrigins: [], text: "Example Domain. This domain is for use in illustrative examples."}};
    const results = {};
    if (llmEnabled()) results.server = await serverDecide(tasks.assess, input).catch(e => ({error: e.message}));
    return results;
  }
}

// Tab state lives in memory; storage is only how the popup reads it, so the
// decision path never waits on a storage write.
const tabs = new Map();
function updateTab(tabId, changes) {
  const state = {...tabs.get(tabId), ...changes};
  tabs.set(tabId, state);
  browser.storage.local.set({["tab-" + tabId]: state}).catch(error => log("storage error:", error));
}

function setBadge(tabId, verdict) {
  const badges = {malicious: ["!", "#b42318"], suspicious: ["?", "#b54708"]};
  const [text, color] = badges[verdict] || ["", null];
  browser.action.setBadgeText({tabId, text}).catch(error => log("badge error:", error));
  if (color) browser.action.setBadgeBackgroundColor({tabId, color}).catch(() => {});
}

async function attempt(label, fn) {
  try {
    return await fn();
  } catch (error) {
    log(label, "failed:", error.message);
    return {error: error.message, cause: error.cause};
  }
}

// Explanations are fetched after the decision has already been acted on.
async function explainLater(task, input, result, image, apply, lane) {
  const outcome = result[task.key];
  if (!task.values.includes(outcome) || result.decidedBy === "rules" || result.summary) return;
  // Only warnings and blocks get an explanation; explaining every safe page would
  // double the load on the model server for nothing.
  if (outcome === "safe" || outcome === "allow") return;
  const details = await attempt("explanation", () => serverExplain(task, input, outcome, image, lane));
  if (!details.error) apply(details);
}

// ---- Verdict memory -----------------------------------------------------------
// A model verdict is reused for the same page (origin + path) when the page's
// code fingerprint and the model are unchanged, the page still says much the same
// thing, and the verdict is under a day old. Any change to the page's scripts,
// forms, frames, or downloads, a different model, or wording that changed a lot
// since the verdict (a trusted site that now shows a scam, say) means a fresh check.

const verdictTtlMs = 24 * 60 * 60 * 1000;
// Pages that ask for a password or payment details are re-checked sooner.
const secretsVerdictTtlMs = 60 * 60 * 1000;

// What each external script contains, so a file swapped at the same address
// changes the page fingerprint. Fetched from Safari's cache where possible,
// without cookies; private and local addresses are never fetched. Hashes are
// kept in memory for one minute so a page's repeated checks do not refetch.
const scriptHashes = new Map();

async function scriptContentHash(src) {
  const cached = scriptHashes.get(src);
  if (cached && Date.now() - cached.at < 60 * 1000) return cached.hash;
  let hash, indicators = [];
  try {
    const url = new URL(src);
    if (!/^https?:$/.test(url.protocol) || (!isTestSite(url) && isPrivateHost(url.hostname))) {
      hash = "not-fetched";
    } else {
      const response = await fetch(url.href, {credentials: "omit", cache: "force-cache",
                                              signal: AbortSignal.timeout(4000)});
      const bytes = response.ok ? await readCapped(response) : null;
      hash = bytes ? await sha256Hex(bytes) : "unavailable";
      if (bytes) indicators = exfilIndicators(new TextDecoder().decode(bytes.subarray(0, 2000000)));
    }
  } catch {
    hash = "unavailable";
  }
  scriptHashes.set(src, {hash, indicators, at: Date.now()});
  return hash;
}

async function scriptsFingerprint(urls) {
  const hashes = await Promise.all(urls.map(scriptContentHash));
  return urls.map((url, i) => url + "=" + hashes[i]).join("\n");
}
const maxRemembered = 500;

async function sha256Text(text) {
  return sha256Hex(new TextEncoder().encode(text));
}

function modelId() {
  return settings.llm.kind + ":" + (settings.llm.kind === "ollama"
    ? settings.llm.ollamaUrl + "/" + settings.llm.ollamaModel
    : settings.llm.customUrl + "/" + settings.llm.customModel);
}

// A compact sketch of what a page says (MinHash over its words): enough to tell
// whether two versions of a page say roughly the same thing, without storing
// the text itself.
const sketchSize = 32;
const sketchSeeds = Array.from({length: sketchSize}, (_, k) => Math.imul(k + 1, 0x9e3779b9) >>> 0);
function mix32(x) {
  x ^= x >>> 16; x = Math.imul(x, 0x85ebca6b);
  x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35);
  return (x ^ (x >>> 16)) >>> 0;
}
function textSketch(text) {
  const words = new Set(String(text || "").toLowerCase().match(/[\p{L}\p{N}]{2,}/gu) || []);
  const sketch = new Array(sketchSize).fill(0xffffffff);
  for (const word of words) {
    let h = 0x811c9dc5;
    for (let i = 0; i < word.length; i++) h = Math.imul(h ^ word.charCodeAt(i), 0x01000193) >>> 0;
    for (let k = 0; k < sketchSize; k++) {
      const v = mix32(h ^ sketchSeeds[k]);
      if (v < sketch[k]) sketch[k] = v;
    }
  }
  return sketch;
}
// Roughly the share of words two versions have in common (Jaccard similarity).
function sketchSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return 0;
  return a.filter((v, k) => v === b[k]).length / a.length;
}
const sameWordingAt = 0.5;

async function rememberedVerdict(pageKey, fingerprint, sketch) {
  const {verdicts = {}} = await browser.storage.local.get("verdicts");
  const entry = verdicts[pageKey];
  if (!entry || entry.fingerprint !== fingerprint || entry.model !== modelId()) return null;
  if (sketchSimilarity(entry.sketch, sketch) < sameWordingAt) {
    log("wording changed since the remembered verdict:", pageKey);
    return null;
  }
  if (Date.now() - entry.at > (entry.secrets ? secretsVerdictTtlMs : verdictTtlMs)) return null;
  return entry;
}

async function rememberVerdict(pageKey, fingerprint, sketch, result) {
  const {verdicts = {}} = await browser.storage.local.get("verdicts");
  verdicts[pageKey] = {...verdicts[pageKey], fingerprint, sketch, model: modelId(), at: Date.now(), secrets: !!result.secrets,
    verdict: result.verdict, source: result.source, investigation: result.investigation,
    ...(result.summary && {summary: result.summary, reasons: result.reasons})};
  // Keep storage bounded: drop the oldest entries.
  const keys = Object.keys(verdicts);
  if (keys.length > maxRemembered) {
    keys.sort((a, b) => verdicts[a].at - verdicts[b].at).slice(0, keys.length - maxRemembered)
      .forEach(key => delete verdicts[key]);
  }
  await browser.storage.local.set({verdicts});
}

// ---- Screenshots -----------------------------------------------------------------
// Taken only for pages that ask for a password or payment details (and only if
// enabled in Settings), kept in memory for at most 10 minutes, and sent only to the
// user's own model server.

const screenshots = new Map();

async function captureTab(tab, url) {
  if (!settings.screenshots || !tab) return {ok: false};
  const current = await browser.tabs.get(tab.id);
  // captureVisibleTab captures whatever tab is in front, so only capture ours.
  if (!current.active) return {ok: false, reason: "tab not in front"};
  const raw = await browser.tabs.captureVisibleTab(current.windowId, {format: "png"});
  // The user may have switched tabs, or the page navigated, while the capture was
  // taken: then the picture may show another page, so it is thrown away.
  const after = await browser.tabs.get(tab.id).catch(() => null);
  if (!after?.active || after.windowId !== current.windowId || after.url !== current.url) {
    return {ok: false, reason: "tab changed during capture"};
  }
  screenshots.set(tab.id, {url: url.split("#")[0], dataUrl: await shrink(raw, 1024), at: Date.now()});
  forgetOldScreenshots();
  log("screenshot taken for", url);
  return {ok: true};
}

// Retina captures are large; scale to at most `maxWidth` pixels wide as JPEG.
async function shrink(dataUrl, maxWidth) {
  if (typeof document === "undefined") return dataUrl;
  const img = new Image();
  img.src = dataUrl;
  await img.decode();
  const scale = Math.min(1, maxWidth / img.naturalWidth);
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(img.naturalWidth * scale);
  canvas.height = Math.round(img.naturalHeight * scale);
  canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL("image/jpeg", 0.75);
}

// No screenshot is kept longer than it can be used (10 minutes), or after its tab closes.
const screenshotLifetimeMs = 10 * 60 * 1000;
function forgetOldScreenshots() {
  for (const [tabId, shot] of screenshots) if (Date.now() - shot.at >= screenshotLifetimeMs) screenshots.delete(tabId);
}
// (unref: in the Node test harnesses this timer must not keep the process alive.)
setInterval(forgetOldScreenshots, 60 * 1000)?.unref?.();

function screenshotFor(tabId, url, maxAgeMs = 60000) {
  forgetOldScreenshots();
  const shot = screenshots.get(tabId);
  return shot && shot.url === url.split("#")[0] && Date.now() - shot.at < maxAgeMs ? shot.dataUrl : null;
}

// ---- Visit counts -----------------------------------------------------------------
// How many times each site was opened before, so the model can tell a site you
// use from one you have never seen. Stored only in this extension on this Mac.

const visitsBeforeThisPage = new Map();

async function countVisit(tabId, origin) {
  const {seen = {}} = await browser.storage.local.get("seen");
  visitsBeforeThisPage.set(tabId, seen[origin]?.count || 0);
  seen[origin] = {count: (seen[origin]?.count || 0) + 1, last: Date.now()};
  const origins = Object.keys(seen);
  if (origins.length > 2000) {
    origins.sort((a, b) => seen[a].last - seen[b].last).slice(0, origins.length - 2000).forEach(o => delete seen[o]);
  }
  await browser.storage.local.set({seen});
}

// ---- Page assessment ---------------------------------------------------------

// A frame inside a page (only frames that ask for a password or payment details
// are sent). A malicious frame blocks the whole page: the top frame is told to
// show the block page, and "Visit this unsafe page" applies to that page.
// Frames asking for a password or payment details, by tab (cleared when the tab
// opens a new page). Real pages have a few (a card form split into fields); a
// page with many is unusual, and each would cost a model check, so frames past
// the limit are flagged without one.
const secretFrames = new Map();
const maxSecretFrames = 8;

async function assessFrame(tabId, signals, fpSource, context, topUrl) {
  const frames = secretFrames.get(tabId) || new Set();
  secretFrames.set(tabId, frames);
  if (!frames.has(context.frameId) && frames.size >= maxSecretFrames) {
    const result = {verdict: "suspicious", source: "Safety rule", decidedBy: "rules",
      summary: "This page has an unusual number of frames asking for passwords or payment details.",
      reasons: ["More than " + maxSecretFrames + " frames on this page ask for passwords or payment details."]};
    updateTab(tabId, {frame: {...result, origin: signals.page.origin, path: signals.page.path, at: Date.now()}});
    setBadge(tabId, result.verdict);
    return result;
  }
  frames.add(context.frameId);
  let topOrigin = "";
  try { topOrigin = new URL(topUrl).origin; } catch {}
  // The page around the frame: which site, its verdict, and how often you visit it.
  const top = tabs.get(tabId)?.page;
  const embeddedIn = {site: topOrigin, verdict: top?.origin === topOrigin ? top.verdict : "unknown",
                      timesVisitedBefore: Math.max(0, (await visitsTo(topOrigin)) - 1)};
  const result = await assessPage(tabId, {...signals, embeddedIn}, false, fpSource, context);
  if (result.verdict !== "malicious") return result;
  const outcome = await afterVerdict(tabId, topUrl, result);
  if (!outcome.allowedByUser) {
    browser.tabs.sendMessage(tabId, {type: "frame-verdict", result: {...outcome, frameUrl: context.url}}, {frameId: 0})
      .catch(error => log("frame block relay failed:", error?.message || error));
  }
  return outcome;
}

const cameFrom = new Map();

async function visitsTo(origin) {
  const {seen = {}} = await browser.storage.local.get("seen");
  return seen[origin]?.count || 0;
}

// Investigations still running in the background after a first "safe" verdict, by tab.
const investigations = new Map();

async function assessPage(tabId, signals, newPage, fpSource, context = {}) {
  await settingsReady;
  // A frame's checks have their own sequence and their own slot in the tab state.
  const frame = context.frameId > 0;
  const seqKey = frame ? tabId + ":" + context.frameId : tabId;
  const slot = frame ? "frame" : "page";
  const seq = (sequence.get(seqKey) || 0) + 1;
  sequence.set(seqKey, seq);
  const where = {origin: signals.page.origin, path: signals.page.path};
  const current = () => sequence.get(seqKey) === seq;
  // A new page starts with a clean slate, so the popup never shows the last page's actions.
  if (newPage) {
    // Where the user came from in this tab (the previous page, as this script saw
    // it): lets the model tell single sign-on from an app you use from a link in a
    // message. Kept for the page's re-checks.
    const previous = tabs.get(tabId)?.page;
    if (previous?.origin && previous.origin !== signals.page.origin) {
      cameFrom.set(tabId, {site: previous.origin, verdict: previous.verdict,
                           timesVisitedBefore: Math.max(0, (await visitsTo(previous.origin)) - 1)});
    } else if (previous?.origin !== signals.page.origin) {
      cameFrom.delete(tabId);
    }
    tabs.set(tabId, {});
    secretFrames.delete(tabId);
    await countVisit(tabId, signals.page.origin).catch(e => log("visit count failed:", e));
  }
  if (!frame) {
    // A re-check of the same page keeps its last verdict ("settled"), so held
    // actions can use it instead of waiting behind every routine re-check.
    const prior = tabs.get(tabId)?.page;
    const samePage = prior?.origin === where.origin && prior?.path === where.path;
    const settled = samePage ? (prior.verdict !== "checking" ? prior.verdict : prior.settled) : undefined;
    updateTab(tabId, {page: {verdict: "checking", ...where, ...(settled ? {settled} : {})}});
  }

  if (!frame && cameFrom.has(tabId)) signals.navigation = {cameFrom: cameFrom.get(tabId)};
  // Domain facts are computed here (Public Suffix List), not trusted from the page.
  const host = new URL(signals.page.origin).hostname;
  signals.identity = {...domainFacts(host), faviconHost: signals.identity?.faviconHost,
    previousVisits: frame ? await visitsTo(signals.page.origin) : visitsBeforeThisPage.get(tabId) ?? null};
  const image = context.screenshotTaken && context.url ? screenshotFor(tabId, context.url) : null;
  const input = {signals};
  let explainTask = tasks.assess, explainInput = input;
  const pageKey = signals.page.origin + signals.page.path;
  const fingerprint = fpSource
    ? await sha256Text(fpSource + "\n" + await scriptsFingerprint(context.scriptUrls || []))
    : null;
  const sketch = textSketch(signals.text);
  const remember = result => rememberVerdict(pageKey, fingerprint, sketch, result).catch(e => log("remember failed:", e));
  // Model calls for this check take turns with other tabs' (see inTurn): the
  // page's own check goes before its frames', and a newer check of the same
  // page or frame replaces one still waiting.
  const lane = {tab: tabId, urgent: !frame};

  const record = result => {
    if (!current()) return;
    const at = Date.now();
    // A safe frame changes nothing the popup shows; a flagged one is listed.
    if (frame && result.verdict === "safe") return;
    updateTab(tabId, {[slot]: {...result, ...where, at}});
    setBadge(tabId, result.verdict);
    // Attach the explanation only if this decision is still the one shown
    // (a newer check of the same tab may have replaced it meanwhile).
    explainLater(explainTask, explainInput, result, image, details => {
      const page = tabs.get(tabId)?.[slot];
      if (current() && page?.at === at) updateTab(tabId, {[slot]: {...page, ...details}});
      if (fingerprint && result.decidedBy === "server") remember({...result, ...details, secrets: context.asksForSecrets});
    }, {tab: tabId});
  };

  if (llmEnabled()) {
    // Same page, same code, same model, checked recently: reuse the verdict. Not
    // when the page's text or title changed a lot since its last check (the code
    // fingerprint leaves text out, so a page rewritten by its own scripts would
    // otherwise get its old verdict back).
    const remembered = fingerprint && !context.textChanged &&
      await rememberedVerdict(pageKey, fingerprint, sketch).catch(() => null);
    if (remembered) {
      const result = {verdict: remembered.verdict, summary: remembered.summary, reasons: remembered.reasons,
        investigation: remembered.investigation,
        source: remembered.source + " \u00b7 remembered from " + new Date(remembered.at).toLocaleTimeString(),
        decidedBy: "memory"};
      record(result);
      return result;
    }

    // Pages asking for secrets get a screenshot first (the page script takes it and asks again).
    // Never on trusted sites: their pages show your own accounts.
    if (settings.screenshots && context.asksForSecrets && !context.screenshotTaken && !context.trusted) {
      return {needScreenshot: true};
    }

    let server = await attempt("model server",
      () => serverDecide(tasks.assess, input, image, {...lane, replaces: "assess:" + (context.frameId || 0)}));
    if (!server.error && shouldInvestigate(server, signals, context)) {
      if (current() && !frame) updateTab(tabId, {page: {...tabs.get(tabId)?.page, verdict: "checking", ...where, investigating: true}});
      const closerLook = async first => {
        const facts = await investigate(signals, context.url || signals.page.origin, context.scriptUrls || [])
          .catch(error => ({failed: error.message}));
        explainTask = tasks.investigate;
        explainInput = {signals, investigation: facts};
        const second = await attempt("investigation verdict",
          () => serverDecide(tasks.investigate, explainInput, image, lane));
        const settled = settleInvestigation(first, second, facts);
        log("investigated", signals.page.origin, "->", settled.verdict, JSON.stringify(facts).slice(0, 300));
        return settled;
      };
      if (server.verdict === "safe" && !frame) {
        // The first look found nothing wrong: answer now, so the user can start
        // typing, and finish the closer look in the background. Submits on this
        // tab wait for it (gateAction), and a raised verdict is sent to the page.
        const later = closerLook(server).then(async settled => {
          if (!current()) return;
          record(settled);
          if (fingerprint) remember({...settled, secrets: context.asksForSecrets});
          if (settled.verdict !== "safe") {
            const result = await afterVerdict(tabId, context.url || signals.page.origin, settled);
            browser.tabs.sendMessage(tabId, {type: "verdict", result}, {frameId: 0}).catch(() => {});
          }
        }).catch(error => log("investigation failed:", error))
          .finally(() => { if (investigations.get(tabId) === later) investigations.delete(tabId); });
        investigations.set(tabId, later);
        return {...server, investigating: true};
      }
      browser.tabs.sendMessage(tabId, {type: "status", text: "Taking a closer look at this site\u2026",
        detail: "Checking how old the site is, its home page, and where its forms send data."},
        {frameId: context.frameId || 0}).catch(() => {});
      server = await closerLook(server);
    }
    if (!server.error) {
      record(server);
      if (fingerprint) remember({...server, secrets: context.asksForSecrets});
      return server;
    }
    // The server works but couldn't answer for this page: the page's doing.
    const fallback = await failedBecauseOfPage(server)
      ? {verdict: "suspicious", checkFailed: true, source: "Safety rule", decidedBy: "rules",
         summary: "This page could not be checked although your model server is working. Pages can cause " +
           "this on purpose, so it is treated as suspicious.",
         reasons: ["Checking this page failed: " + server.error.slice(0, 160)]}
      : {...rulesAssess(signals), summary: "The model server could not be reached: " + server.error};
    record(fallback);
    return fallback;
  }

  // No model server configured: local rules.
  const rules = rulesAssess(signals);
  record(rules);
  return rules;
}

// ---- Action gating -----------------------------------------------------------

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function onlyWhitespace(bytes) {
  return bytes.every(b => b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d || b === 0x1a);
}

async function matchSignature(bytes) {
  for (const sig of signatures) {
    if (bytes.length < sig.prefixBytes || bytes.length > sig.maxBytes) continue;
    if (!onlyWhitespace(bytes.subarray(sig.prefixBytes))) continue;
    if (await sha256Hex(bytes.subarray(0, sig.prefixBytes)) === sig.sha256) return sig.name;
  }
  return null;
}

async function readCapped(response) {
  const chunks = [];
  let size = 0;
  const reader = response.body.getReader();
  for (;;) {
    const {done, value} = await reader.read();
    if (done) break;
    size += value.length;
    if (size > maxScanBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

// The first bytes as printable ASCII, so the model can see what kind of file it is.
function printableHead(bytes) {
  return String.fromCharCode(...bytes.subarray(0, 160).map(b => (b >= 0x20 && b < 0x7f ? b : 0x2e)));
}

async function describeFile(href) {
  const url = new URL(href);
  const file = {origin: url.origin, name: url.pathname.split("/").pop().slice(0, 80)};
  // The prototype only fetches files from the demo site.
  // Never fetch private or local network addresses: a page could otherwise make
  // the extension read your router or other devices.
  if (!isTestSite(url) && isPrivateHost(url.hostname)) {
    return {...file, scanned: false, note: "on a private or local network address; not fetched"};
  }
  try {
    const response = await fetch(url.href, {credentials: "omit", redirect: "error", cache: "no-store"});
    if (!response.ok) throw new Error("Download request failed");
    file.contentType = response.headers.get("content-type") || "unknown";
    const bytes = await readCapped(response);
    if (!bytes) return {...file, scanned: false, note: "larger than the scan limit"};
    // A zip: what is inside, with signatures checked inside it too.
    const archive = isZip(bytes)
      ? await zipContents(bytes, matchSignature).catch(() => ({notes: ["the archive could not be read"]}))
      : null;
    return {...file, scanned: true, size: bytes.length, sha256: await sha256Hex(bytes),
            signatureMatch: await matchSignature(bytes) || archive?.signatureMatch || null,
            ...(archive ? {archive} : {head: printableHead(bytes)}),
            ...(!archive && readableText(file.name, bytes, 3000) ? {text: readableText(file.name, bytes, 3000)} : {})};
  } catch {
    return {...file, scanned: false, note: "could not be fetched"};
  }
}

// A file the page built itself (blob:/data: link), described by the page script:
// only the first 256 bytes reach this script, which is enough for the known-bad
// signatures (they cover files of at most 128 bytes) and a look at the file type.
async function describeBuiltFile(file) {
  let bytes = new Uint8Array();
  try { bytes = Uint8Array.from(atob(String(file.prefix || "")), c => c.charCodeAt(0)); } catch {}
  const size = Number.isFinite(file.size) ? file.size : null;
  return {origin: String(file.origin || "built by the page").slice(0, 80), name: String(file.name || "").slice(0, 80),
          contentType: String(file.contentType || "unknown").slice(0, 100), size, scanned: bytes.length > 0,
          note: "built by the page's own script in the browser, not downloaded from a server",
          head: printableHead(bytes),
          ...(readableText(String(file.name || ""), bytes, 3000) ? {text: readableText(String(file.name || ""), bytes, 3000)} : {}),
          signatureMatch: size !== null && size === bytes.length ? await matchSignature(bytes) : null};
}

async function gateAction(tabId, action, signals, url, frameId = 0) {
  await settingsReady;
  // The page's own check still running with no earlier verdict (a first visit; a
  // screenshot or a closer look can take several seconds): decide with its
  // verdict, not without one. Re-checks of a page already judged don't make
  // actions wait. Bounded so the user is never left waiting for long.
  const deadline = Date.now() + 15000;
  while (tabs.get(tabId)?.page?.verdict === "checking" && !tabs.get(tabId)?.page?.settled && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  await investigations.get(tabId);
  // For a form inside a frame, the frame's own verdict (if it was flagged) counts.
  const current = (frameId > 0 && tabs.get(tabId)?.frame) || tabs.get(tabId)?.page;
  const pageVerdict = current && (current.verdict === "checking" && current.settled
    ? {...current, verdict: current.settled} : current);
  const request = {action: {kind: action.kind}, signals,
                   pageVerdict: pageVerdict && {verdict: pageVerdict.verdict, summary: pageVerdict.summary}};
  if (action.kind === "download") {
    request.action.file = action.file ? await describeBuiltFile(action.file) : await describeFile(action.url);
  }
  if (action.kind === "submit") request.action.form = action.form;
  if (action.kind === "clipboard") {
    request.action.command = String(action.command || "").slice(0, 2000);
    request.action.via = String(action.via || "").slice(0, 40);
    if (typeof action.shownOnPage === "boolean") {
      request.action.shownOnPage = action.shownOnPage;
      if (!action.shownOnPage) {
        request.action.shownPart = String(action.shownPart || "").slice(0, 300);
        request.action.hiddenPart = String(action.hiddenPart || "").slice(0, 500);
      }
    }
  }

  // The model server decides; local rules only if it is not set up or not reachable.
  // A password or payment submission reuses the page's screenshot (if one was taken in the last 10 minutes).
  const image = action.kind === "submit" && url ? screenshotFor(tabId, url, screenshotLifetimeMs) : null;
  let result = null;
  if (llmEnabled()) {
    const server = await attempt("model server", () => serverDecide(tasks.gate, request, image, {tab: tabId, urgent: true}));
    if (!server.error) result = server;
    else if (await failedBecauseOfPage(server)) {
      result = {decision: "block", checkFailed: true, source: "Safety rule", decidedBy: "rules",
        summary: "Blocked: this could not be checked although your model server is working. Pages can cause " +
          "this on purpose, so it is not allowed."};
    }
  }
  if (!result) result = rulesGate(request);

  // Safety net: a known-bad signature always blocks, whatever a model said.
  const signature = request.action.file?.signatureMatch;
  if (signature && result.decision !== "block") {
    result = {...result, decision: "block", summary: "Matched known-bad signature " + signature + ".",
              overridden: "The model allowed this, but the file matched a known-bad signature."};
  }

  const at = Date.now();
  updateTab(tabId, {action: {...result, kind: action.kind,
    target: request.action.file?.name || request.action.form?.actionOrigin ||
      (action.kind === "clipboard" ? request.action.command.slice(0, 60) : undefined), at}});
  if (!result.summary) {
    explainLater(tasks.gate, request, result, image, details => {
      const current = tabs.get(tabId)?.action;
      if (current?.at === at) updateTab(tabId, {action: {...current, ...details}});
    }, {tab: tabId});
  }
  return result;
}
