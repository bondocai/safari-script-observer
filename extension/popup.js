const colors = {malicious: "#b42318", suspicious: "#b54708", safe: "#067647", block: "#b42318", allow: "#067647"};

function line(text, style = "") {
  const p = document.createElement("p");
  p.textContent = text;
  p.style.cssText = "margin:4px 0;" + style;
  return p;
}

function section(title, verdict, item) {
  const box = document.createElement("div");
  box.style.cssText = "margin-top:10px;padding-top:8px;border-top:1px solid #8884";
  box.append(line(title + ": " + verdict, "font-weight:600;color:" + (colors[verdict] || "inherit")));
  if (item.summary) box.append(line(item.summary));
  else if (verdict === "safe" || verdict === "allow") box.append(line("No problems found."));
  else if (verdict !== "checking") box.append(line("Getting the model's explanation\u2026", "opacity:.7;font-style:italic"));
  for (const reason of item.reasons || []) box.append(line("\u2022 " + reason, "font-size:13px"));
  if (item.overridden) box.append(line(item.overridden, "font-size:13px;color:#b42318"));
  if (item.investigating) box.append(line("Investigating this site\u2026", "font-size:13px;opacity:.7;font-style:italic"));
  if (item.investigation?.length) {
    box.append(line("Investigation", "font-size:13px;font-weight:600;margin-top:8px"));
    for (const fact of item.investigation) box.append(line("\u2013 " + fact, "font-size:12px"));
  }
  const timing = [item.source && "decided by " + item.source, item.explainedIn && "explained in " + item.explainedIn];
  if (item.source) box.append(line(timing.filter(Boolean).join(" \u00b7 "), "font-size:12px;opacity:.7"));
  return box;
}

// Google Safe Browsing's report form, with the site and path filled in (no query
// string or fragment: in phishing links they often identify the recipient).
// Nothing is sent until the user submits the form.
let reportable = null;
function reportButton(url) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Report to Google";
  button.style.cssText = "font:inherit;margin-top:6px";
  button.onclick = () => {
    browser.tabs.create({url: "https://safebrowsing.google.com/safebrowsing/report_phish/?url=" +
      encodeURIComponent(url) + "&hl=en"});
    window.close();
  };
  return button;
}

function render(state) {
  const root = document.querySelector("#state");
  root.replaceChildren();
  if (!state?.page && !state?.frame && !state?.action) {
    root.append(line("Nothing checked on this page yet. If it was open before Safari Script Observer started (for example, a tab Safari reopened at launch), reload it. Pages on your trusted list and non-web pages are not checked."));
    return;
  }
  if (state.page) {
    const box = section("Page " + (state.page.path || ""), state.page.verdict, state.page);
    if (["malicious", "suspicious"].includes(state.page.verdict) && reportable) box.append(reportButton(reportable));
    root.append(box);
  }
  if (state.frame) {
    root.append(section("Frame from " + (state.frame.origin || "another site"), state.frame.verdict, state.frame));
  }
  if (state.action) {
    const what = state.action.kind === "download" ? "Download " : state.action.kind === "clipboard" ? "Clipboard command " : "Form submit to ";
    root.append(section(what + (state.action.target || ""), state.action.decision, state.action));
  }
}

// On the block page, show what was blocked from the block page's own address
// (the tab's stored record may not be found while an extension page is showing).
function renderBlocked(url) {
  const params = new URL(url).searchParams;
  let reasons = [];
  try {
    reasons = JSON.parse(params.get("reasons") || "[]");
  } catch {
    reasons = [];
  }
  const root = document.querySelector("#state");
  root.replaceChildren(section("Blocked " + (params.get("url") || "page"), "malicious", {
    summary: params.get("summary") || "Your model judged this page malicious.",
    reasons: Array.isArray(reasons) ? reasons : [],
    source: params.get("source") || ""
  }));
}

browser.tabs.query({active: true, currentWindow: true}).then(([tab]) => {
  if (tab.url?.startsWith(browser.runtime.getURL("blocked.html"))) return renderBlocked(tab.url);
  try {
    const url = new URL(tab.url);
    if (/^https?:$/.test(url.protocol)) reportable = url.origin + url.pathname;
  } catch {}
  const key = "tab-" + tab.id;
  browser.storage.local.get(key).then(stored => render(stored[key]));
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[key]) render(changes[key].newValue);
  });
});

document.querySelector("#settings").onclick = () => browser.runtime.openOptionsPage();

// Setup not finished (no access to every website): say so above everything else.
browser.permissions?.contains({origins: ["http://*/*", "https://*/*"]}).then(ok => {
  if (ok) return;
  const note = document.createElement("div");
  note.style.cssText = "margin-top:10px;padding:8px 10px;border-radius:8px;background:#b5470822;";
  note.append(line("Setup isn't finished: Safari Script Observer can't check every website yet.", "font-weight:600"));
  const finish = document.createElement("button");
  finish.type = "button";
  finish.textContent = "Finish setup";
  finish.style.font = "inherit";
  finish.onclick = () => { browser.tabs.create({url: browser.runtime.getURL("welcome.html")}); window.close(); };
  note.append(finish);
  document.querySelector("#state").before(note);
}).catch(() => {});
