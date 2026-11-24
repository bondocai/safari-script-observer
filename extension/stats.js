// Local-only statistics, for measuring how the extension behaves in your real
// browsing: how long checks take, how long held actions and typing wait, what was
// flagged, and when you chose to go ahead anyway (likely false alarms).
//
// Stored in this extension's storage on this Mac, kept 30 days, never sent
// anywhere. Site names are kept only for flagged pages, blocked actions and your
// overrides (the cases worth reviewing); safe pages are only counted.
// Shown and cleared in Settings. Loaded by the background script and Settings.

const statsKeepMs = 30 * 24 * 60 * 60 * 1000;
const statsCaps = {checks: 20000, waits: 5000, events: 2000};

// ---- Recording (background) ------------------------------------------------------
// Entries are buffered and written every few seconds, not on every check.

let statsBuffer = {checks: [], waits: [], events: []};
let statsFlush = null;

function statsRecord(list, entry) {
  statsBuffer[list].push({at: Date.now(), ...entry});
  statsFlush ??= setTimeout(flushStats, 3000);
  // (unref: in the Node test harnesses this timer must not keep the process alive.)
  statsFlush?.unref?.();
}

async function flushStats() {
  statsFlush = null;
  const added = statsBuffer;
  statsBuffer = {checks: [], waits: [], events: []};
  try {
    const {stats} = await browser.storage.local.get("stats");
    const kept = stats?.since ? stats : {since: Date.now(), checks: [], waits: [], events: []};
    const oldest = Date.now() - statsKeepMs;
    for (const list of Object.keys(statsCaps)) {
      kept[list] = [...(kept[list] || []), ...added[list]].filter(e => e.at >= oldest).slice(-statsCaps[list]);
    }
    kept.since = Math.max(kept.since, oldest);
    await browser.storage.local.set({stats: kept});
  } catch {
    // Stats are a convenience: never let them disturb checking.
  }
}

const hostOf = url => { try { return new URL(url).hostname; } catch { return ""; } };

// A finished page, frame or action check, as the background answered it.
function statsCheck(kind, startedAt, result, url, action) {
  if (!result || result.needScreenshot) return;
  const outcome = result.verdict || result.decision || "unknown";
  statsRecord("checks", {kind, ...(action ? {action} : {}), ms: Date.now() - startedAt,
    by: result.decidedBy || "unknown", outcome,
    ...(result.failure ? {failure: result.failure} : {}), ...(result.checkFailed ? {checkFailed: true} : {})});
  // Remembered verdicts repeat an earlier one: listed once, when first decided.
  if (result.decidedBy === "memory") return;
  if (["suspicious", "malicious"].includes(outcome)) {
    statsEvent({host: hostOf(url), event: kind === "frame" ? "frame flagged" : "page flagged", outcome,
      ...(result.checkFailed ? {detail: "check failed"} : {})});
  } else if (outcome === "block") {
    statsEvent({host: hostOf(url), event: "action blocked", outcome: action || "action"});
  }
}

// A flagged page is re-checked as it changes: the same site, event and outcome
// within 10 minutes is listed once.
const statsLastEvent = new Map();
function statsEvent(entry) {
  const key = [entry.host, entry.event, entry.outcome, entry.detail].join("|");
  const last = statsLastEvent.get(key);
  if (last && Date.now() - last < 10 * 60 * 1000) return;
  statsLastEvent.set(key, Date.now());
  if (statsLastEvent.size > 500) statsLastEvent.delete(statsLastEvent.keys().next().value);
  statsRecord("events", entry);
}

// ---- Summary (Settings) ------------------------------------------------------------

function percentile(values, p) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(p / 100 * sorted.length) - 1)];
}

function summarizeStats(stats) {
  const checks = stats?.checks || [], waits = stats?.waits || [], events = stats?.events || [];
  const timing = list => ({count: list.length, median: percentile(list.map(e => e.ms), 50), p95: percentile(list.map(e => e.ms), 95)});
  const byModel = checks.filter(c => c.by === "server");
  const count = (list, key) => list.reduce((m, e) => (m[e[key]] = (m[e[key]] || 0) + 1, m), {});
  const pages = checks.filter(c => c.kind === "page");
  const actions = checks.filter(c => c.kind === "action");
  return {
    since: stats?.since || null,
    pages: {count: pages.length, outcomes: count(pages, "outcome"), remembered: pages.filter(c => c.by === "memory").length},
    frames: {count: checks.filter(c => c.kind === "frame").length},
    modelTime: {
      pages: timing(byModel.filter(c => c.kind === "page")),
      frames: timing(byModel.filter(c => c.kind === "frame")),
      actions: timing(byModel.filter(c => c.kind === "action"))
    },
    actions: Object.fromEntries(Object.entries(Object.groupBy(actions, c => c.action || "other"))
      .map(([kind, list]) => [kind, {...timing(list), outcomes: count(list, "outcome")}])),
    typingWaits: timing(waits.filter(w => w.kind === "typing")),
    failures: count(checks.filter(c => c.failure || c.checkFailed), "failure"),
    overrides: events.filter(e => e.event === "override"),
    flagged: events.filter(e => e.event !== "override")
  };
}
