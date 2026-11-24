// Everything this page needs arrives in its address (set by the page script),
// because Safari may not give a page opened from a website access to the
// extension's storage.
const params = new URLSearchParams(location.search);
const httpUrl = value => {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url : null;
  } catch {
    return null;
  }
};
const target = httpUrl(params.get("url"));
const back = httpUrl(params.get("back"));
const token = /^[0-9a-f-]{36}$/.test(params.get("token") || "") ? params.get("token") : null;

document.getElementById("site").textContent = target ? target.href : "Unknown page";

function render(summary, reasons, source) {
  if (summary) document.getElementById("summary").textContent = summary;
  if (reasons?.length) {
    document.getElementById("reasons").replaceChildren(...reasons.slice(0, 3).map(reason => {
      const item = document.createElement("li");
      item.textContent = String(reason);
      return item;
    }));
  }
  if (source) document.getElementById("source").textContent = "Decided by " + source;
}

let reasons = [];
try {
  reasons = JSON.parse(params.get("reasons") || "[]");
} catch {
  reasons = [];
}
render(params.get("summary"), Array.isArray(reasons) ? reasons : [], params.get("source"));

// If the model's explanation was still being written, pick it up when it lands.
// Best effort: this works only if Safari gives this page storage access.
try {
  browser.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    for (const change of Object.values(changes)) {
      const page = change.newValue?.page;
      if (page?.summary && target && page.origin + page.path === target.origin + target.pathname) {
        render(page.summary, page.reasons, page.source);
      }
    }
  });
} catch {
  // No storage access: the details in the address are all we show.
}

// Go straight to the last page in this tab that was not blocked, instead of
// walking back through history (which may hold more copies of this page).
document.getElementById("back").onclick = () => location.replace(back ? back.href : "about:blank");

const toggle = document.getElementById("showDetails");
toggle.onclick = () => {
  const details = document.getElementById("details");
  details.hidden = !details.hidden;
  toggle.setAttribute("aria-expanded", String(!details.hidden));
};

// Reopen the page with the one-time code. The page script hands it to the
// background script, which accepts it once, only for this page, and records the
// bypass for the tab it arrives in.
const proceed = document.getElementById("continue");
proceed.disabled = !target || !token;
if (proceed.disabled) proceed.textContent = "Visit this unsafe page (unavailable: no bypass code was issued)";
proceed.onclick = () => location.replace(target.href + "#sso-bypass=" + token);

// Report the page to Google Safe Browsing: opens Google's form with the address
// filled in; nothing is sent until the user submits it there. Only the site and
// path: query strings and fragments in phishing links often identify the
// person they were sent to.
const report = document.getElementById("report");
report.hidden = !target;
report.onclick = () => {
  const page = target.origin + target.pathname;
  window.open("https://safebrowsing.google.com/safebrowsing/report_phish/?url=" + encodeURIComponent(page) + "&hl=en",
              "_blank", "noopener");
};
