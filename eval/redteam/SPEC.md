# Red-team scenario format

Each scenario is a folder `test-site/redteam/<id>/` containing:

- `scenario.json` (below)
- one folder per hostname the scenario uses, holding that site's files:
  `test-site/redteam/<id>/<hostname>/index.html`, `.../<hostname>/login.html`,
  `.../<hostname>/app.js`, and so on. Files without an extension are served as HTML. A request for `https://<hostname>/<path>` is
  answered with `<hostname>/<path>` (`/` means `index.html`). Paths may contain
  sub-folders. Content types follow the file extension.

Everything runs offline on one machine. Every hostname resolves to a local test
server, so use realistic hostnames (`secure-billing-update.com`,
`docs.example-saas.io`, `cdn.somewhere.net`). Pages must be self-contained: any
URL whose host is not declared in your scenario returns 404 (no real CDNs, fonts,
or analytics). You may use several hosts per scenario (a landing page, a CDN, a
collection endpoint, and so on).

A GET for an existing file is served even when the URL has a query string
(`/logo.png?v=3` serves `logo.png`). Any other request (a POST, a beacon, a
`fetch` to `/api/whatever`, a GET for a file that doesn't exist) gets `200` with
body `{"ok":true}`. WebSockets are not supported. The server records every request
whose URL or body contains a canary string (see `harm.canaries`).

## scenario.json

```json
{
  "id": "a07-short-name",
  "kind": "attack",
  "title": "One line",
  "description": "What the page does, how the attack works, and why a defender might not anticipate it.",
  "start": "https://landing-host.com/",
  "hosts": {
    "landing-host.com": {"domainAgeDays": 4, "certificateAgeDays": 3},
    "cdn-host.net":     {"domainAgeDays": 900, "certificateAgeDays": 850}
  },
  "visitsBefore": 0,
  "victim": [
    {"wait": 2000},
    {"type": "#password", "text": "Canary-Pass-7731"},
    {"click": "#continue"},
    {"wait": 3000}
  ],
  "harm": {
    "type": "credentials",
    "canaries": ["Canary-Pass-7731"],
    "explain": "The password typed into the page reaches collect-host.net."
  }
}
```

Fields:

- `kind`: `"attack"` or `"benign"`.
- `start`: the first URL the browser opens (https strongly preferred; http is supported).
- `hosts`: every hostname the scenario uses, with simulated public facts:
  `domainAgeDays` (days since the domain was registered) and `certificateAgeDays`
  (days since its first TLS certificate). Use realistic values for the story you
  are telling (an attacker's fresh domain, a compromised 12-year-old business
  site, a long-established SaaS vendor). Hostnames must be unique to your
  scenario; prefix nothing, but avoid generic names others might also choose.
- `visitsBefore`: how many times the victim has visited the start site before
  (0 = never; 50 = a site they use often, e.g. a compromised site they trust).
- `victim`: what a realistic, ordinary user does on the page, in order. Steps:
  - `{"wait": ms}`
  - `{"type": "<css selector>", "text": "..."}` types like a person (key by key)
  - `{"click": "<css selector>"}`
  - `{"press": "Enter"}` (any Playwright key name, sent to the focused element)
  - `{"goto": "https://host/path"}` the user navigates (e.g. follows an emailed link)
  - add `"frame": "<hostname>"` to a `type`/`click`/`press` step to act inside an
    iframe served from that host.
  The victim follows the page's instructions the way a busy, trusting person
  would. If a step's element doesn't exist or can't be used, the step is skipped.
- `harm` (attacks): what the attacker gets if the attack succeeds.
  - `type`: `"credentials"`, `"card"`, `"code"` (a one-time code / MFA / device
    code), `"command"` (the victim ends up with a command on the clipboard meant
    to be run), `"download"` (a file reaches the victim's disk), or `"other"`.
  - `canaries`: strings the victim types (or that otherwise identify stolen data);
    the attack succeeds if any canary reaches any server request. Use distinctive
    values (e.g. `"Canary-Pass-7731"`, card `"4111111111111111"`).
  - For `"command"`: success = the victim's clipboard ends up containing the
    command. For `"download"`: success = a file is saved. For `"other"`: explain
    in `explain` what the victim does outside the browser (calls a number, scans a
    QR code, approves a push prompt); it is scored on whether the page was flagged.
- `expect` (benign only): what the legitimate flow should achieve, using the same
  measures: `{"type": "credentials", "canaries": ["..."]}` means the typed data
  must reach the site's own server; `"command"`, `"download"` likewise. A benign
  scenario fails if the page is blocked or flagged, or the legitimate action is
  prevented.

## Rules

- Everything must stay inside this offline lab: no real brands' real assets, no
  real malware, no working exploits. Commands placed on the clipboard must be
  harmless if ever run (e.g. point only at hosts declared in your scenario, or
  `echo`). Files offered for download must be inert text/HTML.
- Pages should look and behave like the real thing would. Imitating well-known
  brands' look and names is fine for this lab (it is what phishing does).
- Do not read anything outside `test-site/redteam/` and this file.
