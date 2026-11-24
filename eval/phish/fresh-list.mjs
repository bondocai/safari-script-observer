// A fresh list of live phishing pages that this network doesn't block yet, for
// testing the extension by hand on a separate test account (see the rules
// written at the top of the list).
//
//   node eval/phish/fresh-list.mjs            (writes ~/Desktop/phishing-test-<date>.txt)
//   OUT=/path/file.txt node eval/phish/fresh-list.mjs
//
// 1. Downloads the OpenPhish public feed.
// 2. Looks each domain up with this Mac's normal DNS: domains the network's DNS
//    filter already blocks (redirected to a block address, or not found) are
//    left out: the useful pages are the ones nothing has caught yet.
// 3. Requests each remaining page once, as text only (nothing is run), and keeps
//    the ones still serving a page; providers' "suspended" pages are left out.
// The phishing servers see this Mac's IP address, as they would on any visit.
import {lookup} from "node:dns/promises";
import {writeFileSync} from "node:fs";
import {homedir} from "node:os";

const feedUrl = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
// Addresses DNS filters answer with instead of the real one: OpenDNS/Cisco
// Umbrella block pages and "nowhere". Add your own network's block address with
// BLOCK_ADDRESSES="10.0.0.1,10.0.0.2".
const extraBlock = (process.env.BLOCK_ADDRESSES || "").split(",").map(a => a.trim()).filter(Boolean);
const blockAddressPattern = /^(146\.112\.61\.\d+|0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1?)$/;
const blockAddress = {test: address => blockAddressPattern.test(address) || extraBlock.includes(address)};
// Pages providers show once they've caught a phishing site.
const takenDown = /suspected phishing|harmful web site blocked|site not found|page not found|account (has been )?suspended|this site is (blocked|unavailable)|deceptive site|phishing warning/i;
const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";

async function inBatches(items, size, fn) {
  const results = [];
  for (let i = 0; i < items.length; i += size) results.push(...await Promise.all(items.slice(i, i + size).map(fn)));
  return results;
}

async function dnsStatus(host) {
  try {
    // Blocked if any address is a block address: a filter may redirect only the
    // IPv4 answer and leave IPv6 alone.
    const addresses = await lookup(host, {all: true});
    return addresses.some(a => blockAddress.test(a.address)) ? "blocked" : "open";
  } catch {
    return "gone"; // not found: removed, or blocked by answering "no such name"
  }
}

// Status and title of a page, read as text (at most 512 KB), never run.
async function pageStatus(url) {
  try {
    const response = await fetch(url, {redirect: "follow", headers: {"User-Agent": userAgent},
                                       signal: AbortSignal.timeout(12000)});
    const reader = response.body.getReader();
    let text = "", size = 0;
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.length;
      text += new TextDecoder().decode(value, {stream: true});
      if (size > 512 * 1024) { await reader.cancel(); break; }
    }
    const title = (text.match(/<title[^>]*>([^<]*)/i)?.[1] || "").replace(/\s+/g, " ").trim().slice(0, 80);
    return {status: response.status, title, finalUrl: response.url};
  } catch (error) {
    return {status: 0, title: "", error: error.cause?.code || error.name};
  }
}

const feed = await fetch(feedUrl, {signal: AbortSignal.timeout(30000)}).then(r => r.text());
const urls = [...new Set(feed.split("\n").map(line => line.trim()).filter(line => /^https?:\/\//.test(line)))];
// One URL per domain.
const byHost = new Map();
for (const url of urls) {
  try { const host = new URL(url).hostname; if (!byHost.has(host)) byHost.set(host, url); } catch {}
}
console.log(`Feed: ${urls.length} URLs, ${byHost.size} domains. Checking DNS…`);

const dns = await inBatches([...byHost.keys()], 24, async host => [host, await dnsStatus(host)]);
const open = dns.filter(([, state]) => state === "open").map(([host]) => byHost.get(host));
const count = state => dns.filter(([, s]) => s === state).length;
console.log(`DNS: ${count("blocked")} blocked by the network, ${count("gone")} not found, ${open.length} resolving. Checking pages…`);

const pages = await inBatches(open, 12, async url => ({url, ...await pageStatus(url)}));
const live = pages.filter(p => p.status >= 200 && p.status < 400 && !takenDown.test(p.title));
const caught = pages.filter(p => takenDown.test(p.title)).length;
const dead = pages.length - live.length - caught;
console.log(`Pages: ${live.length} live, ${caught} already taken down or flagged by their host, ${dead} dead or refusing.`);

const stamp = new Date().toISOString().slice(0, 16).replace("T", "-").replace(":", "");
const out = process.env.OUT || `${homedir()}/Desktop/phishing-test-${stamp}.txt`;
writeFileSync(out, `LIVE PHISHING PAGES - checked ${new Date().toLocaleString()} from this Mac.
Source: OpenPhish public feed. Not blocked by this network's DNS at the time; still serving a page.

Open ONLY on a separate test account (no saved passwords, AutoFill off, nothing signed in).
Rules: type nothing real; never download or open files; never paste commands; close the tab if a
page asks for permissions. Pages often die within hours: test soon after making this list.
For each, note: blocked by the extension? time? did Safari or the network warn first?
Use "Report to Google" on the block page for pages nothing else had caught.

${live.map(p => p.url + (p.title ? "\n    # " + p.title : "")).join("\n") || "(none live right now: try again later)"}
`);
console.log(`Wrote ${live.length} URLs to ${out}`);
