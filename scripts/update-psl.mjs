// Regenerates extension/psl.js from the official Public Suffix List
// (https://publicsuffix.org). Run occasionally:  node scripts/update-psl.mjs
import {writeFileSync} from "node:fs";
import {domainToASCII} from "node:url";

const text = await (await fetch("https://publicsuffix.org/list/public_suffix_list.dat")).text();
const icann = [], shared = [];
let section = null;
for (const raw of text.split("\n")) {
  const line = raw.trim();
  if (line.includes("===BEGIN ICANN DOMAINS===")) section = icann;
  else if (line.includes("===BEGIN PRIVATE DOMAINS===")) section = shared;
  else if (line.includes("===END")) section = null;
  if (!section || !line || line.startsWith("//")) continue;
  const rule = line.split(/\s/)[0];
  // Rules may be in Unicode; page host names arrive in ASCII (punycode).
  const prefix = rule.match(/^[!*.]*/)[0];
  const ascii = domainToASCII(rule.slice(prefix.length).replace(/^\./, ""));
  if (ascii) section.push((prefix.startsWith("!") ? "!" : prefix.startsWith("*") ? "*." : "") + ascii);
}
const header = `// Public Suffix List (https://publicsuffix.org), ${icann.length} ICANN and ${shared.length} shared-hosting
// rules, generated ${new Date().toISOString().slice(0, 10)} by scripts/update-psl.mjs. Do not edit by hand.
// Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/).
`;
const body = `
const publicSuffixList = (() => {
  const parse = list => {
    const rules = new Set(), wildcards = new Set(), exceptions = new Set();
    for (const rule of list.split(" ")) {
      if (rule.startsWith("!")) exceptions.add(rule.slice(1));
      else if (rule.startsWith("*.")) wildcards.add(rule.slice(2));
      else rules.add(rule);
    }
    return {rules, wildcards, exceptions};
  };
  return {icann: parse(${JSON.stringify(icann.join(" "))}),
          shared: parse(${JSON.stringify(shared.join(" "))})};
})();

// The longest public suffix of a host, and whether it belongs to a shared-hosting
// or website-builder platform (the list's "private" section: pages.dev, github.io, ...).
function publicSuffix(host) {
  const labels = host.toLowerCase().replace(/\\.$/, "").split(".");
  let best = {suffix: labels.at(-1), shared: false, length: 1};
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join(".");
    const parent = labels.slice(i + 1).join(".");
    for (const [kind, list] of [["icann", publicSuffixList.icann], ["shared", publicSuffixList.shared]]) {
      let length = 0;
      if (list.exceptions.has(candidate)) length = labels.length - i - 1;
      else if (list.rules.has(candidate)) length = labels.length - i;
      else if (parent && list.wildcards.has(parent)) length = labels.length - i;
      if (length > best.length || (length === best.length && length > 0 && kind === "shared")) {
        best = {suffix: labels.slice(labels.length - length).join("."), shared: kind === "shared", length};
      }
    }
  }
  return best;
}

// "www.example.co.uk" -> "example.co.uk"; "phish.pages.dev" -> "phish.pages.dev".
function registrableDomain(host) {
  const h = host.toLowerCase().replace(/\\.$/, "");
  if (/^[\\d.]+$/.test(h) || h.includes(":")) return h; // IP addresses
  const {suffix} = publicSuffix(h);
  const labels = h.split("."), suffixLabels = suffix.split(".").length;
  return labels.length > suffixLabels ? labels.slice(-(suffixLabels + 1)).join(".") : h;
}

// The platform a site is hosted on, if it is a user site on shared hosting
// (anyone can create one), e.g. "pages.dev" for "phish.pages.dev"; otherwise null.
function sharedHostingPlatform(host) {
  const {suffix, shared} = publicSuffix(host);
  return shared && host.toLowerCase() !== suffix ? suffix : null;
}
`;
writeFileSync(new URL("../extension/psl.js", import.meta.url), header + body);
console.log("Wrote extension/psl.js:", icann.length, "ICANN rules,", shared.length, "shared-hosting rules");
