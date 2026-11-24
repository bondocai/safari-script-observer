# Safari Script Observer

A Safari extension that has **your own AI model** judge each page as you browse, and holds the
risky moments (typing a password, card number or crypto recovery phrase, downloads, commands a
page puts on your clipboard) until the model decides. Page contents go only to a model server
you run yourself (Ollama, LM Studio, or any OpenAI-compatible server); nothing goes to a cloud
AI service.

> **Status:** personal project, provided as-is under the MIT license. It is one layer of
> protection, not a replacement for your browser's own warnings, DNS filtering or common sense.
> Built with AI assistance (Claude); the design, testing and security decisions are the author's.

## Results so far

- **Blind red-team testing:** 100 scenarios (56 attacks, 44 legitimate look-alikes) written by
  testers who never saw the code, over four rounds, the last aimed at the AI itself (prompt
  injection). v0.16.0 stopped 55 of 56 attacks and let 42 of 44 legitimate pages through; see
  [`eval/RESULTS.md`](eval/RESULTS.md).
- **Live phishing:** 6 of 6 live phishing pages that reached the extension were blocked, 4 of
  them before any other layer (browser warnings, DNS filtering, hosting takedowns) had caught them.
- Write-up: *(link to the article)*

## Install

1. **Download** `Safari-Script-Observer-<version>.zip` from [Releases](../../releases/latest) and unzip it.
2. **Drag Safari Script Observer.app into Applications**, and open it once (it registers the
   extension with Safari).
3. **Turn it on:** Safari → Settings → **Extensions** → tick **Safari Script Observer**.
4. **Let it check every website:** when Safari asks, choose **Always Allow on Every Website**.
   A setup page in Safari walks you through this.
5. **Connect your model:** click the extension's toolbar icon → **Settings**, then:
   - choose **Local Ollama** (e.g. `http://localhost:11434`) or **My own server** for LM Studio
     and other OpenAI-compatible servers (e.g. `http://localhost:1234/v1`, or your GPU
     machine's address);
   - add an **API key** if your server requires one;
   - click **Load models**, pick a model, and click **Test models**.

That's it. Pages open normally, and the toolbar icon shows what your model found.

**Build it yourself:** see [Run it](#run-it) below. For a notarized build with your own Apple
Developer account, see `scripts/release-app.sh` (set `TEAM` to your team ID). Change the
placeholder bundle identifier (`com.example.SafariScriptObserver`) to your own first.

**You need a model server.** Without one, only simple local rules run. A vision-capable model
(e.g. Qwen 3.8 27B) on a dedicated GPU answers in about 2 seconds; on a Mac it can take 15–20.

## Testing

| What | Command |
|---|---|
| Model accuracy on described pages | `MODEL_URL=… MODEL=… API_KEY=… node eval/run.mjs` |
| Evasion checks in a sandboxed browser (stand-in model) | `node eval/lab-check/run.mjs` |
| Zip handling, incl. zip bombs and crafted archives | `node eval/archive-check.mjs` |
| Model-call queue and failed-check handling | `node eval/turns-check.mjs` |
| End-to-end red team (real model, offline lab) | `node eval/redteam/run.mjs` (scenario format: `eval/redteam/SPEC.md`) |
| Fresh list of live phishing pages for manual testing | `node eval/phish/fresh-list.mjs` |

The blind red-team scenarios themselves (realistic look-alikes of real brands' pages) are not
included in this repository; only the harness, the format and fictional self-tests are. If you
test against live phishing, use a separate account with nothing signed in, and never type real
details or download anything.

## How it works

A Safari extension that uses a language model to judge whether the page you are
on is doing something malicious, and holds downloads and password submissions
until a model decides whether they may go ahead. Password and payment form
submissions are held too.

It runs on every website. By default pages open right away and are checked in
the background; what is held is the moment harm can happen: typing into password
or card fields before the check answers, downloads (including files a page builds
itself, as in HTML smuggling), and commands a page tries to put on the clipboard
("paste this into Terminal" scams). An optional mode also covers every page until
the model answers. Your **trusted sites** (Settings) open without
waiting, but are still fingerprinted, re-checked by the model when their code
changes, and still have downloads and password and payment submissions held.
For trusted sites the model gets only the page's structure: never its text, and
no screenshot. Pages checked in the last 24 hours with unchanged code and much
the same wording are not sent to the model again (a trusted site that starts
showing a scam with the same code is checked afresh). Suspicious pages get a warning (and their password and
card fields take no typing until you choose to type); malicious pages are
replaced by a block page.

With "cover every page" on, the cover is registered to run before the page can
draw, sits in the browser's top layer inside a closed shadow root, and goes back
on top if the page opens its own dialog or removes or hides it.

Clipboard commands and page-built files are caught by `pagehooks.js`, which runs
in the page's own JavaScript context. It only blocks and reports: if your model
allows the command or file, the extension offers to copy or save it itself, so a
page cannot fake the go-ahead.

Pages are scanned in every frame: a frame that shows a password or payment form
is checked on its own, and if it is malicious the whole page is blocked.
Password and card fields are found even outside forms and inside shadow DOM. On
a suspicious page those fields take no typing until you choose to type (a page
can send keystrokes as they are typed), and a button that would send filled-in
secrets by script is held for the model like a form submit. Pages that change
after loading are re-checked when their text, title, images or fields change.

Domains are judged with the Public Suffix List (`extension/psl.js`, regenerate
with `node scripts/update-psl.mjs`), so a user site on shared hosting such as
`something.pages.dev` is never credited with the platform's age.

The download scanner never fetches private or local network addresses (your
router, other devices, Tailscale names), except the local test site.

## How it decides

Your model server decides everything: it rates each page when it loads or
changes, and decides whether held downloads and password submissions may go
ahead. Choose it in **Settings** (extension popup → Settings):

- **Local Ollama** — e.g. `qwen3.8:latest` on this Mac.
- **Your own server** — any OpenAI-compatible server (LM Studio, llama.cpp, vLLM, …)
  with an optional API key, e.g. LM Studio on another machine over Tailscale.

If no server is set, or it cannot be reached, simple local rules warn about
obvious signs (a password form posting to another site, decoded-and-run
scripts, hidden cross-site frames). A known-bad file signature (e.g. EICAR) is
always blocked, whatever the model says.

If the server is working but a page's own check fails or runs out of time, the
page is treated as suspicious and its downloads and clipboard commands are
blocked: pages can be built to make a model error, refuse or stall, hoping for
"could not be checked, continue anyway". Whether the server is working is asked
fresh each time (a quick request for its model list), so a server that just went
down doesn't make pages look guilty.

Model calls take turns: each tab gets its turn, a page's own check and held
actions go before checks of frames and explanations in any tab, a check still
waiting is replaced by a newer check of the same page or frame, and at most two
calls run at once. A page that keeps asking to be checked (churning frames,
constant rewrites) can't hold up other tabs. More than eight frames on one page
asking for passwords or payment details are flagged without a model check.

Model calls are made by the extension's Mac app, so Ollama and LM Studio need no
CORS or `OLLAMA_ORIGINS` changes.

## What is sent to a model

Page origin and path, title, form destinations and field types/labels, inline
script excerpts, external script origins, iframe origins, download links, image
alt text / file names / hosts, up to 1,500 characters of visible text (none for
trusted sites), and
domain facts computed on this Mac (lookalike spelling, punycode, security words
in the domain, and how many times you visited the site before). For downloads:
file name, size, hash, and the first 160 bytes. **Never** form values,
passwords, cookies, or storage.

**Numbers are masked** before anything is sent: every digit in visible text,
titles, field labels and image alt text becomes `#` (so balances, account and
card numbers, and dates never reach the model), and numbers of 4 or more digits
in the address path, field names and script excerpts become `####`. Names and
other words in page text are not masked.

**Screenshots** (on by default, can be turned off in Settings): only for pages
that ask for a password or payment details, and never on trusted sites, so a vision-capable model can see
logos and text drawn as images. Sent only to your model server; kept in memory
for at most 10 minutes. Your model server may log it.

**Investigation** (on by default, can be turned off in Settings): when the model
finds a page suspicious, or a never-visited site asks for a password or payment
details, the extension also looks up the domain's age (sending the domain name
to its registry's public records, found via IANA's list), when its first
certificate was issued (crt.sh, only for young domains), fetches the site's home
page and the home page of any other site its forms send data to (plain requests,
no cookies, no scripts run), and checks the OpenPhish public phishing list
(downloaded and checked on this Mac). Code, not the model, decides what is
fetched. The investigation can raise a verdict freely, but can lower
"suspicious" to "safe" only for a domain over a year old that is not on
OpenPhish and sends no data to known data-theft services.

Stored on this Mac only, in the extension's storage: remembered verdicts (24 h,
with a sketch of each page's wording as numbers, not the text itself),
"Visit this unsafe page" choices (per tab, until it closes), and per-site visit counts. **Forget remembered
verdicts** in Settings clears all three.

## Run it

1. Start the test site:

   ```sh
   node test-site/server.mjs
   ```

2. Build the extension: open `xcode/Safari Script Observer/Safari Script Observer.xcodeproj`
   in Xcode and run the **Safari Script Observer** scheme (or build with `xcodebuild`).
3. In Safari: enable the extension in Settings → Extensions and allow it on every website.
   (A development build needs Develop → Allow Unsigned Extensions after each Safari restart;
   a notarized build doesn't.)
4. Open the extension popup → **Settings**, choose your model server, and click **Test models**.
5. Visit http://localhost:8765/ and try the phishing page, the malicious-script
   page, and the two downloads.

## Test pages

| Page | Expected |
| --- | --- |
| `/` | safe |
| `/phish` | malicious; "Verify account" is blocked |
| `/script` | suspicious or malicious |
| Download `notes.txt` | allowed |
| Download `eicar.com` | blocked |

## Known limits

- Pages built to mislead the model can fool it; some protections deliberately don't depend
  on the model for that reason.

- Scripts that run as a page loads have already run before the verdict arrives;
  only actions you take (downloads, submits) are held.
- Downloads started by redirects or scripts are not intercepted.
- Page text can try to manipulate the model; the prompts treat it as untrusted
  data, but that reduces the risk rather than removing it.

## License and security

MIT: see [LICENSE](LICENSE). To report a security problem, please do so privately: see
[SECURITY.md](SECURITY.md).
