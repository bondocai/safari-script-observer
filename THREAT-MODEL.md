# Threat model

What Safari Script Observer protects, against whom, what it trusts, and where it stops.
Statements here describe what the code enforces; where something depends on the model's
judgment, it says so.

## What it is (and isn't)

It is **page risk assessment plus safeguards for selected browser actions**. A model you
run yourself judges each page, and the moments where people actually get hurt are held
until it decides:

- typing into a password, card or recovery-phrase field, and submitting it (by form or script);
- downloads, including files a page builds itself (`blob:`/`data:` links, HTML smuggling)
  and files inside zip archives;
- commands a page puts on the clipboard ("paste this into Terminal", ClickFix).

It is not an antivirus, a network filter or a replacement for Safari's own warnings,
DNS filtering or common sense. It is one layer.

## Assets

1. What you type into sensitive fields: passwords, card numbers, one-time codes, recovery phrases.
2. Your Mac: what you download and what you paste into a terminal.
3. Your browsing privacy: what pages you visit and what is on them.

## Adversaries

### A malicious web page (the main adversary)

Assumed to control everything it serves (HTML, scripts, frames, images, redirects),
to know this extension exists and how it works (the code is public), and to try to
fool, break or exhaust it.

| It may try to | What stops it | Enforced by |
|---|---|---|
| Convince the model it is safe (hidden instructions, fake verdicts, fake end-of-data markers, role play, "authorized training" claims) | Page content is sent as JSON data under instructions to treat it as untrusted; answers must be one of fixed choices (structured output, checked again in code) | Prompt + code. **The judgment itself is the model's**: injection is reduced, not eliminated. Tested: 14/14 blind injection attacks stopped |
| Make its own check fail (errors, refusals, stalls) hoping for "could not be checked, continue anyway" | If the model server passes a fresh health check but this page's check fails or times out, the page is suspicious and its held actions are blocked | Code |
| Flood the model with re-checks so its own or other tabs' checks wait | Model calls queue per tab and take turns; held actions and page checks go first; waiting re-checks are replaced by newer ones; at most two calls at once; more than 8 password/payment frames on a page are flagged without a model call | Code |
| Be judged safe once, then show a scam on a later visit with the same code (cloaking) | A remembered verdict is reused only if the code fingerprint matches and the wording is much the same; pages that change while open are re-checked | Code |
| Press the extension's own buttons, or remove its warnings | Warnings live in closed shadow roots and act only on real (trusted) clicks; the warning bar on a page opened anyway can't be removed by the page | Code |
| Fake a go-ahead for a held action | Hooks in the page's own JavaScript context only block and report; nothing is resumed from there. After the model allows it, the extension's isolated script copies the command or saves the file itself, on your click. Forged reports can only add holds | Code |
| Point the investigation at your Mac or home network (a form "destination" on 192.168.x.x, a name that resolves there, a redirect there) | Investigation requests go only to public internet addresses: names are resolved and checked, redirects are checked, and the address actually connected to is checked afterwards. Responses stop at 2 MB; slow-drip servers are cut off | Code (Mac app) |
| Crash the extension's page script so the page is never checked | A start-up failure is reported and the page shows "not checked", rather than silently running unprotected | Code |
| Hide a malicious file in an archive, or crash the archive reader | Zips are read in memory (never written to disk), 3 levels deep, with limits on size, entry count and time (5 seconds); a known-bad signature (e.g. EICAR) is always blocked, whatever the model says | Code |

### A compromised third-party script on a site you trust (supply chain)

A widget, analytics or chat script on a genuine site is altered to show a fake sign-in
or skim what you type. Every address involved is genuine, so the page looks right.

- Trusted sites still have their code fingerprinted, are re-checked when it changes,
  and have password and payment submissions and downloads held.
- **Known limit:** when a hacked widget on a trusted site asks you to sign in again,
  the model currently has no way to know which script drew the password box, and lets
  it through (red-team scenario e14). This is the closest test to the supply-chain
  case and is an open problem.

### The model server or the model

The model server is yours (on this Mac or your own network), so it is trusted with page
descriptions. But:

- **It can be wrong.** Every verdict is a judgment. Held actions, the block page and
  the fixed answer choices limit what a wrong answer can do; a wrong "safe" lets the
  action through.
- **It can be unreachable or slow.** Then simple local rules run, sensitive fields on
  pages asking for secrets stay locked, and pages show "could not be checked" (a server
  failure is not blamed on the page).
- **Its weights can be untrustworthy** (a model file from an unknown uploader could be
  altered to approve certain pages). Prefer models from their original publisher.
- **The model only chooses among fixed answers.** It cannot make the extension fetch
  anything, run anything or change settings: what the investigation looks up is
  decided by code from the page's own addresses.
- **Its logs** may keep what was sent, including screenshots. Turn request logging off
  on the server if that matters to you.

### Other software on your Mac, and the network

Out of scope: malware already running on your Mac can read Safari's memory or your
files directly. Between the extension and a model server on another machine, use an
encrypted connection (e.g. Tailscale, HTTPS) and the server's API key.

## What leaves the Mac

| To | What | When |
|---|---|---|
| Your model server | A description of the page (address, title, forms and field labels, script and frame origins, up to 1,500 characters of visible text with **every digit masked**); a screenshot of pages asking for a password or payment details | Every check. **Never** form values, passwords, cookies or storage. Trusted sites: structure only, no text, no screenshot |
| Domain registries (via IANA's list), crt.sh | The domain name | Investigation only (pages found suspicious, or never-visited sites asking for secrets) |
| The page's own site and its form destinations | A plain request for their home page, no cookies, nothing run | Investigation only, public addresses only |
| OpenPhish | Nothing about you: the public list is downloaded and checked on this Mac | Investigation |
| Google Safe Browsing | The page address | Only when you click "Report to Google" |

Screenshots and the investigation can each be turned off in Settings. Screenshots are
kept in memory for at most 10 minutes and dropped when their tab closes. Stored on this
Mac only: remembered verdicts (24 hours; 1 hour for pages asking for secrets), with a
numeric sketch of each page's wording rather than the text; "visit anyway" choices per
tab; per-site visit counts; your stats (30 days: timings and outcomes, with site names only
for flagged pages, blocked actions and your overrides; shown and cleared in Settings).

## Non-goals and known limits

- **A perfect copy** of a genuine page, served from an address that is genuinely the
  site's (a hacked site, or a hacked widget on it), may not be caught.
- **Scripts that run while a page loads** have already run before the verdict arrives;
  only actions you take are held.
- **Downloads started by redirects or by sending the page to a file's address** (rather
  than by the page building the file) are not intercepted; Safari and Gatekeeper still check them.
- **Prompt injection** is reduced, not eliminated. Research on LLM phishing detectors
  ("Clouding the Mirror", Koide et al., 2026) found open models of this size fooled in
  roughly a third of attempts even with defenses; your results will depend on your model.
- **A name that resolves to a public address when checked and a private one a moment
  later** (DNS rebinding) can still cause one investigation request to reach the private
  address; its response is then discarded, not used.
- **Results so far come mostly from Chromium**, running the real extension code in a
  test harness, plus hand tests and live phishing pages in Safari. Safari-specific
  behaviour (for example of `blob:` pages) is not fully confirmed.
- **Government services run by vendors** on commercial domains tend to be flagged as
  suspicious (a false alarm).

## Reporting

Found a way past it? Please report it privately; see [SECURITY.md](SECURITY.md).
