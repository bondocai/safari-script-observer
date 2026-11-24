// Investigation of pages the model is unsure about. Code, not the model, decides
// what is looked up, so a malicious page cannot steer the extension into
// fetching addresses of its choosing. The checks run in parallel; the model then
// reads the facts and makes the final call.
//
// What leaves this Mac:
//   - the registrable domain name, to the public registration records of its
//     registry (found via IANA's published registry list), and,
//     for young domains, to public certificate logs (crt.sh);
//   - plain GET requests (no cookies, no scripts run) to the site's home page and
//     to the home page of any other site its forms send data to;
//   - a periodic download of the OpenPhish public phishing list, which is then
//     checked locally (no browsing data is sent for it).

// Facts about the page's domain, computed here (with the Public Suffix List in
// psl.js) rather than in the page script. A user site on shared hosting
// ("phish.pages.dev") is its own domain, not the platform's.
function domainFacts(host) {
  const domain = registrableDomain(host);
  const platform = sharedHostingPlatform(host);
  const name = platform ? host.slice(0, -(platform.length + 1)).split(".").pop() : domain.split(".")[0];
  return {
    host, registrableDomain: domain, punycode: /(^|\.)xn--/.test(host),
    ...(platform ? {sharedHostingPlatform: platform} : {}),
    digitsMixedIntoWord: /[a-z][0-9][a-z]|[a-z][0-9]$|^[0-9][a-z]/i.test(name),
    securityWordsInDomain: (host.match(/login|signin|secure|verify|account|update|support|wallet|auth/gi) || []).map(w => w.toLowerCase()),
    hyphens: (name.match(/-/g) || []).length
  };
}

// Services that phishing kits commonly use to receive stolen form data.
const exfilPatterns = {
  "Telegram bot API": /api\.telegram\.org\/bot/i,
  "Discord webhook": /discord(?:app)?\.com\/api\/webhooks/i,
  "FormSubmit": /formsubmit\.co/i,
  "Getform": /getform\.io/i,
  "EmailJS": /api\.emailjs\.com/i,
  "webhook.site": /webhook\.site/i,
  "ngrok tunnel": /\.ngrok(?:-free)?\.(?:io|app|dev)/i,
  "Pipedream": /\.m\.pipedream\.net/i
};

function exfilIndicators(text) {
  return Object.keys(exfilPatterns).filter(name => exfilPatterns[name].test(text || ""));
}

// A browser-like identity, so sites that show different content to obvious
// scanners are less likely to hide what a visitor sees.
const browserHeaders = {
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
  "Accept": "text/html,application/xhtml+xml"
};

async function nativeGet(url, timeoutMs, headers = {}) {
  const reply = await native({type: "http", method: "GET", url, headers, timeoutMs});
  if (reply?.error) throw new Error(reply.error);
  return reply;
}

// Lookups are cached so repeat investigations of a site are instant.
const lookupCache = new Map();
async function cachedLookup(key, ttlMs, fn) {
  const hit = lookupCache.get(key);
  if (hit && Date.now() - hit.at < ttlMs) return hit.value;
  const value = await fn();
  lookupCache.set(key, {value, at: Date.now()});
  return value;
}

const daysSince = iso => Math.max(0, Math.floor((Date.now() - Date.parse(iso)) / 86400000));

// IANA's list of which registry answers registration queries (RDAP) for each
// domain ending; downloaded at most weekly.
let rdapRegistries = null;
async function rdapBaseFor(domain) {
  if (!rdapRegistries || Date.now() - rdapRegistries.at > 7 * 86400e3) {
    const stored = (await browser.storage.local.get("rdapRegistries")).rdapRegistries;
    if (stored && Date.now() - stored.at < 7 * 86400e3) {
      rdapRegistries = stored;
    } else {
      const reply = await nativeGet("https://data.iana.org/rdap/dns.json", 8000);
      if (reply.status !== 200) throw new Error("IANA registry list returned " + reply.status);
      const map = {};
      for (const [endings, urls] of JSON.parse(reply.body).services) {
        for (const ending of endings) map[ending.toLowerCase()] = urls.find(u => u.startsWith("https:")) || urls[0];
      }
      rdapRegistries = {at: Date.now(), map};
      await browser.storage.local.set({rdapRegistries});
    }
  }
  const labels = domain.split(".");
  for (let i = 1; i < labels.length; i++) {
    const base = rdapRegistries.map[labels.slice(i).join(".")];
    if (base) return base.endsWith("/") ? base : base + "/";
  }
  return null;
}

async function domainAgeDays(domain) {
  return cachedLookup("rdap:" + domain, 24 * 3600e3, async () => {
    const base = await rdapBaseFor(domain);
    if (!base) return null; // this domain ending publishes no registration records
    const reply = await nativeGet(base + "domain/" + encodeURIComponent(domain), 6000,
                                  {Accept: "application/rdap+json"});
    if (reply.status !== 200) return null;
    const registered = (JSON.parse(reply.body).events || []).find(e => e.eventAction === "registration");
    return registered ? daysSince(registered.eventDate) : null;
  });
}

// Only used for young or unknown-age domains: old, busy domains have enormous
// certificate histories, and their age is already known.
async function certificateAgeDays(domain) {
  return cachedLookup("crt:" + domain, 24 * 3600e3, async () => {
    const reply = await nativeGet("https://crt.sh/?q=" + encodeURIComponent(domain) + "&output=json", 8000);
    if (reply.status !== 200) return null;
    const entries = JSON.parse(reply.body);
    if (!Array.isArray(entries) || !entries.length) return null;
    const earliest = entries.reduce((min, e) => (e.not_before < min ? e.not_before : min), entries[0].not_before);
    return daysSince(earliest + "Z");
  });
}

// Facts about a page fetched as raw HTML: nothing on it runs.
async function pageSummary(url) {
  return cachedLookup("page:" + url, 3600e3, async () => {
    const reply = await nativeGet(url, 6000, browserHeaders);
    const doc = new DOMParser().parseFromString(reply.body || "", "text/html");
    const finalUrl = new URL(reply.finalUrl || url);
    const links = [...doc.querySelectorAll("a[href]")].map(a => {
      try { return new URL(a.getAttribute("href"), finalUrl); } catch { return null; }
    }).filter(Boolean);
    const text = (doc.body?.textContent || "").replace(/\s+/g, " ").trim();
    const inline = [...doc.querySelectorAll("script")].filter(s => !s.getAttribute("src")).map(s => s.textContent).join("\n");
    return {
      status: reply.status,
      redirectedTo: finalUrl.origin !== new URL(url).origin ? finalUrl.origin : null,
      title: (doc.title || "").trim().slice(0, 100),
      textExcerpt: text.slice(0, 300),
      textLength: text.length,
      internalLinks: new Set(links.filter(l => l.origin === finalUrl.origin).map(l => l.pathname)).size,
      externalLinkSites: new Set(links.filter(l => l.origin !== finalUrl.origin).map(l => l.hostname)).size,
      passwordForms: doc.querySelectorAll('input[type="password"]').length,
      looksLikeDefaultOrParkedPage: /index of \/|welcome to nginx|apache2? (ubuntu )?default page|it works!|domain (is )?for sale|parked|coming soon|cpanel/i
        .test(doc.title + " " + text.slice(0, 500)),
      dataTheftServicesInScripts: exfilIndicators(inline)
    };
  });
}

// OpenPhish community feed: downloaded at most every 6 hours, checked locally.
let openPhishFeed = null;
async function openPhishList() {
  if (openPhishFeed && Date.now() - openPhishFeed.at < 6 * 3600e3) return openPhishFeed;
  const stored = (await browser.storage.local.get("openPhish")).openPhish;
  if (stored && Date.now() - stored.at < 6 * 3600e3) {
    openPhishFeed = {at: stored.at, urls: new Set(stored.urls), hosts: new Set(stored.hosts)};
    return openPhishFeed;
  }
  const reply = await nativeGet("https://openphish.com/feed.txt", 10000);
  if (reply.status !== 200) throw new Error("OpenPhish feed returned " + reply.status);
  const urls = reply.body.split("\n").map(line => line.trim()).filter(line => /^https?:\/\//.test(line));
  const hosts = urls.map(u => { try { return new URL(u).hostname; } catch { return ""; } }).filter(Boolean);
  openPhishFeed = {at: Date.now(), urls: new Set(urls.map(u => u.replace(/\/$/, ""))), hosts: new Set(hosts)};
  await browser.storage.local.set({openPhish: {at: openPhishFeed.at, urls: [...openPhishFeed.urls], hosts: [...openPhishFeed.hosts]}});
  return openPhishFeed;
}

async function openPhishMatch(pageUrl) {
  const feed = await openPhishList();
  const url = new URL(pageUrl);
  if (feed.urls.has((url.origin + url.pathname).replace(/\/$/, ""))) return "this exact page";
  if (feed.hosts.has(url.hostname)) return "this site (other pages reported)";
  return "not listed";
}

const settle = promise => promise.then(value => value, error => ({lookupFailed: error.message?.slice(0, 80) || "failed"}));

// Runs every check in parallel, bounded to ~12 seconds overall.
async function investigate(signals, pageUrl, scriptUrls) {
  const host = new URL(signals.page.origin).hostname;
  const local = isPrivateHost(host);
  const domain = registrableDomain(host);
  // On shared hosting the registry only knows the platform (pages.dev is years
  // old); that says nothing about a site anyone could have created today.
  const platform = sharedHostingPlatform(host);
  const notApplicable = platform && "not applicable: a user site on " + platform +
    ", where anyone can create a site; the platform's age says nothing about this site";
  const formSites = [...new Set((signals.forms || []).filter(f => f.crossOrigin && /^https?:/.test(f.actionOrigin))
    .map(f => f.actionOrigin))].filter(origin => !isPrivateHost(new URL(origin).hostname)).slice(0, 2);

  const ageLookup = local ? Promise.resolve("local test site")
    : platform ? Promise.resolve(notApplicable) : settle(domainAgeDays(domain));
  const work = {
    domain: Promise.resolve(domain),
    ...(platform ? {sharedHostingPlatform: Promise.resolve(platform)} : {}),
    domainAgeDays: ageLookup,
    certificateAgeDays: local ? Promise.resolve("local test site") : platform ? Promise.resolve(notApplicable) : ageLookup.then(age =>
      typeof age === "number" && age > 365 ? "not needed (domain is old)" : settle(certificateAgeDays(domain))),
    homePage: settle(pageSummary(signals.page.origin + "/")),
    formDestinations: Promise.all(formSites.map(async origin => ({
      site: origin,
      domainAgeDays: sharedHostingPlatform(new URL(origin).hostname)
        ? "not applicable: a user site on " + sharedHostingPlatform(new URL(origin).hostname)
        : await settle(domainAgeDays(registrableDomain(new URL(origin).hostname))),
      homePage: await settle(pageSummary(origin + "/"))
    }))),
    dataTheftServicesInPageScripts: Promise.resolve([...new Set([
      ...(signals.scripts?.inline || []).flatMap(s => exfilIndicators(s.excerpt)),
      ...scriptUrls.flatMap(src => scriptHashes.get(src)?.indicators || [])
    ])]),
    openPhish: local ? Promise.resolve("local test site") : settle(openPhishMatch(pageUrl))
  };

  const deadline = new Promise(resolve => setTimeout(() => resolve("timed out"), 12000));
  const facts = {};
  await Promise.all(Object.entries(work).map(async ([key, promise]) => {
    facts[key] = await Promise.race([promise, deadline]);
  }));
  return facts;
}

// Short, readable lines for the popup.
function describeInvestigation(facts) {
  const age = value => typeof value === "number" ? value + " days" + (value >= 730 ? " (" + Math.floor(value / 365) + " years)" : "")
    : value?.lookupFailed ? "lookup failed" : String(value ?? "unknown");
  const lines = [facts.domainAgeDays === "local test site"
    ? "Domain " + facts.domain + ": local test site (no public records)"
    : facts.sharedHostingPlatform
    ? "Site on shared hosting (" + facts.sharedHostingPlatform + "): anyone can create one, so its age is unknown"
    : "Domain " + facts.domain + " registered " + age(facts.domainAgeDays) + " ago"];
  if (typeof facts.certificateAgeDays === "number") lines.push("First certificate issued " + age(facts.certificateAgeDays) + " ago");
  const home = facts.homePage;
  if (home && !home.lookupFailed && home !== "timed out") {
    lines.push("Home page: " + (home.looksLikeDefaultOrParkedPage ? "default/parked page" :
      home.internalLinks + " internal links, \"" + (home.title || "untitled") + "\"") +
      (home.redirectedTo ? ", redirects to " + home.redirectedTo : ""));
  }
  for (const dest of facts.formDestinations || []) {
    lines.push("Form sends data to " + dest.site + " (registered " + age(dest.domainAgeDays) + " ago)");
  }
  if (facts.dataTheftServicesInPageScripts?.length) {
    lines.push("Scripts contact: " + facts.dataTheftServicesInPageScripts.join(", "));
  }
  if (typeof facts.openPhish === "string" && facts.openPhish !== "local test site") lines.push("OpenPhish list: " + facts.openPhish);
  return lines;
}

// ---- Deciding with the investigation's results -----------------------------------

// Investigate when the model is unsure, or when a never-visited site asks for a
// password or payment details.
function shouldInvestigate(first, signals, context) {
  if (!settings.investigate || first.verdict === "malicious") return false;
  return first.verdict === "suspicious" || (context.asksForSecrets && !(signals.identity?.previousVisits > 0));
}

// The investigation may raise a verdict freely. It may lower "suspicious" to
// "safe" only on hard evidence: a domain over a year old, not on the OpenPhish
// list, with no data-theft services in its scripts.
function settleInvestigation(first, second, facts) {
  const lines = facts.failed ? ["Investigation failed: " + facts.failed] : describeInvestigation(facts);
  if (second.error) return {...first, investigation: lines};
  const rank = {safe: 0, suspicious: 1, malicious: 2};
  const hardEvidenceOfLegitimacy = typeof facts.domainAgeDays === "number" && facts.domainAgeDays > 365 &&
    !/^this/.test(facts.openPhish || "") && !(facts.dataTheftServicesInPageScripts || []).length;
  const lowered = rank[second.verdict] < rank[first.verdict];
  if (lowered && !hardEvidenceOfLegitimacy) {
    return {...first, investigation: lines, source: first.source + " \u00b7 investigated (verdict kept)"};
  }
  return {...second, investigation: lines, firstVerdict: first.verdict,
          source: second.source + " \u00b7 after investigation (first: " + first.verdict + ")"};
}
