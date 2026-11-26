// Collects page signals for the model and holds risky user actions until it decides.
// Never collects form values, cookies, or storage.
(() => {
  // Web pages, and pages a web page builds in the browser itself (blob:https://site/...,
  // e.g. HTML smuggling), which belong to that site.
  if (!/^https?:$/.test(location.protocol) &&
      !(location.protocol === "blob:" && /^https?:\/\//.test(location.origin))) return;

  // Reports from pagehooks.js (the page's own context): clipboard commands and
  // files the page builds. Listened for right away and queued until start().
  // The page could send fake ones; they only lead to the same check a real one gets.
  // A page that rewrites itself with document.open() erases every event listener on
  // the window, this script's included. Ours go through on()/off() so they can be
  // put back; the page is then checked again as a page built by script.
  const ours = [];
  function on(type, fn, options = false) {
    window.addEventListener(type, fn, options);
    if (!ours.some(l => l.type === type && l.fn === fn)) ours.push({type, fn, options});
  }
  function off(type, fn, options = false) {
    window.removeEventListener(type, fn, options);
    const i = ours.findIndex(l => l.type === type && l.fn === fn);
    if (i >= 0) ours.splice(i, 1);
  }
  let rewrites = 0, rootRemoved = false;
  let onRewrite = () => {};
  new MutationObserver(records => {
    for (const r of records) {
      if ([...r.removedNodes].some(n => n instanceof Element)) rootRemoved = true;
      if (rootRemoved && [...r.addedNodes].some(n => n instanceof Element)) {
        rootRemoved = false;
        rewrites++;
        for (const l of ours) window.addEventListener(l.type, l.fn, l.options);
        onRewrite();
      }
    }
  }).observe(document, {childList: true});

  const hookQueue = [];
  let onHook = detail => hookQueue.push(detail);
  on("__sso_hook", event => {
    try { onHook(JSON.parse(event.detail)); } catch {}
  }, true);

  // Settings (trusted sites, cover mode) and visit history are read from storage.
  // In "check every page" mode the page is already covered by cover-now.js.
  browser.storage.local.get(["settings", "seen"]).then(safeStart, () => safeStart({}));

  // One unexpected error must never leave a page silently unprotected (it once
  // did: a "//" path made one line throw). If this script can't start, the page
  // and the toolbar say so.
  function safeStart(stored) {
    try {
      start(stored);
    } catch (error) {
      startFailed(error);
    }
  }
  function startFailed(error) {
    console.error("[Safari Script Observer] could not start on this page:", error);
    browser.runtime.sendMessage({type: "failed", error: String(error?.message || error).slice(0, 200)}).catch(() => {});
    if (window !== window.top) return;
    try {
      const host = document.createElement("div");
      host.setAttribute("role", "alert");
      host.style.cssText = "all:initial;position:fixed;bottom:16px;left:50%;transform:translateX(-50%);" +
        "z-index:2147483647;display:block";
      const note = document.createElement("div");
      note.textContent = "Safari Script Observer could not check this page, so it is not protected. " +
        "Avoid typing passwords or payment details here.";
      note.style.cssText = "background:#b54708;color:#fff;font:14px system-ui;padding:10px 16px;border-radius:8px;" +
        "box-shadow:0 4px 16px rgba(0,0,0,.3);max-width:560px";
      host.attachShadow({mode: "closed"}).append(note);
      const put = () => document.documentElement?.append(host);
      if (document.documentElement) put(); else document.addEventListener("DOMContentLoaded", put, {once: true});
    } catch {}
  }

  function start(stored) {
    // Trusted sites open without the cover, but are still fingerprinted (and sent
    // to the model only if their code changed), and downloads and password
    // submissions on them are still held.
    const trusted = onSkipList(location.hostname, stored.settings?.skipSites || []);
    // The person's own network: the model server set in Settings when it runs on this
    // Mac, and on Tailscale every device on its tailnet (https only). Pages
    // there (the model server's own web page, a NAS, a router) are not checked and
    // nothing on them is held: there is nothing to protect the person from, and a
    // server that is down or restarting must not lock its own page.
    const own = onOwnNetwork(location, stored.settings?.llm);
    // Default ("moments"): pages open right away and are checked in the
    // background; what is held is the moment harm can happen: typing into password
    // or card fields, downloads, and commands put on the clipboard. Optional
    // "all": also cover every page until the model says it is clean.
    const coverAll = stored.settings?.coverMode === "all";
    // In frames (all_frames), the script stays quiet unless the frame asks for a
    // password or payment details; then the frame is covered and checked, and a
    // malicious verdict blocks the whole page.
    const isTop = window === window.top;

    // Arriving from the block page's "Visit this unsafe page" link: the URL carries
    // a one-time code. Hide it from the address bar and hand it to the background
    // script before the page is assessed.
    const bypassMatch = location.hash.match(/(?:^#|&)sso-bypass=([0-9a-f-]{36})/);
    if (bypassMatch) {
      // From the full URL, not the path: a path starting with "//" would be read as
      // another site, and the error would stop this whole script (no check, no
      // protection) - an attacker could even craft such links on purpose. Hiding
      // the code is cosmetic, so it may fail without consequence.
      try {
        const url = new URL(location.href);
        url.hash = url.hash.replace(/(^#|&)sso-bypass=[0-9a-f-]{36}/, "").replace(/^#&?$/, "");
        history.replaceState(history.state, "", url.href);
      } catch {}
    }
    let bypassReady = Promise.resolve();

    // ---- Shield: cover the page until the model's verdict -------------------------
    // By default raised before every page draws. In "risky pages only" mode: on
    // sites never visited before, and as soon as a password or payment field appears. While it is up, the page
    // cannot be seen or typed into. The page's own scripts still run underneath;
    // a malicious verdict replaces the page entirely (see onVerdict). In "risky
    // pages only" mode, other pages are checked in the background, uncovered.
    // Long enough for a check plus an investigation of a suspicious site.
    const shieldTimeoutMs = 40000;
    const shield = (() => {
      const dark = matchMedia("(prefers-color-scheme: dark)").matches;
      // The cover sits in a closed shadow root (page styles and scripts can't reach
      // inside) and in the browser's top layer as a popover, above anything the page
      // draws. If the page opens its own dialog or popover, or removes the cover, it
      // is put back on top.
      const host = document.createElement("div");
      host.setAttribute("popover", "manual");
      host.style.cssText = "all:initial !important;position:fixed !important;inset:0 !important;display:block !important;" +
        "width:auto !important;height:auto !important;max-width:none !important;max-height:none !important;" +
        "margin:0 !important;padding:0 !important;border:0 !important;z-index:2147483646 !important;" +
        "background:transparent !important";
      const root = host.attachShadow({mode: "closed"});
      const cover = document.createElement("div");
      cover.setAttribute("role", "status");
      cover.style.cssText = "position:fixed;inset:0;display:flex;flex-direction:column;" +
        "align-items:center;justify-content:center;gap:8px;text-align:center;padding:24px;font:16px system-ui;" +
        (dark ? "background:#101828;color:#f2f4f7" : "background:#f9fafb;color:#1d2939");
      const title = document.createElement("strong");
      title.textContent = "Checking this page\u2026";
      const detail = document.createElement("span");
      detail.style.cssText = "font-size:14px;opacity:.7;max-width:480px";
      detail.textContent = "Safari Script Observer is asking your model whether this page is safe.";
      cover.append(title, detail);
      root.append(cover);

      let active = false;
      let timeout;
      // Swallow input while the shield is up, so nothing can be typed or clicked.
      const swallow = event => {
        if (!active) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        if (event.type === "focusin" && event.target instanceof HTMLElement) event.target.blur();
      };
      const events = ["keydown", "keypress", "keyup", "beforeinput", "input", "paste", "drop",
                      "mousedown", "pointerdown", "click", "auxclick", "submit", "focusin"];
      const toTop = () => {
        if (!active) return;
        if (!document.documentElement) return requestAnimationFrame(toTop);
        if (!host.isConnected) document.documentElement.append(host);
        try { host.hidePopover(); } catch {}
        try { host.showPopover(); } catch {}
      };
      // Anything the page puts in the top layer after us, or the cover's removal.
      on("toggle", event => {
        if (active && event.target !== host && event.newState === "open") toTop();
      }, true);
      // The page closing the cover itself (hidePopover): put it straight back.
      host.addEventListener("toggle", event => {
        if (event.newState === "closed") requestAnimationFrame(() => { if (active && !host.matches(":popover-open")) toTop(); });
      });
      new MutationObserver(records => {
        if (!active) return;
        if (!host.isConnected || records.some(r => r.type === "attributes" && r.target !== host)) toTop();
      }).observe(document, {childList: true, subtree: true, attributes: true, attributeFilter: ["open", "popover"]});

      const lift = () => {
        if (!active) return;
        active = false;
        try { host.hidePopover(); } catch {}
        host.remove();
        for (const type of events) off(type, swallow, true);
      };
      const raise = () => {
        if (active) return;
        active = true;
        for (const type of events) on(type, swallow, true);
        if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
        toTop();
        window.__ssoEarlyCover?.remove();
        timeout = setTimeout(() => {
          if (!active) return;
          lift();
          banner("Your model did not answer in time, so this page was not checked.", "warn");
        }, shieldTimeoutMs);
      };

      return {
        get active() { return active; },
        raise,
        lift() { clearTimeout(timeout); lift(); },
        // Keep the cover up for good (a blocked frame).
        lock() { raise(); clearTimeout(timeout); },
        say(text, sub) { title.textContent = text; detail.textContent = sub || ""; },
        // A blocked page: the same red as the block page.
        danger() {
          cover.style.background = "#b42318";
          cover.style.color = "#fff";
          detail.style.opacity = ".9";
          title.style.fontSize = "22px";
        },
        // Make the cover invisible (input stays blocked) while `fn` captures the page.
        // Anything typed into fields is made invisible for the capture, so a
        // screenshot can never show a card number or other entered text.
        async whileHidden(fn) {
          const blank = document.createElement("style");
          blank.textContent = "input, textarea, select, [contenteditable] { color: transparent !important; " +
            "-webkit-text-fill-color: transparent !important; caret-color: transparent !important; " +
            "text-shadow: none !important; }";
          document.documentElement.append(blank);
          if (active) cover.style.visibility = "hidden";
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          try {
            return await fn();
          } finally {
            blank.remove();
            if (active) cover.style.visibility = "visible";
          }
        }
      };
    })();

    if (isTop && !trusted && !own && coverAll) shield.raise();
    else window.__ssoEarlyCover?.remove();

    // Progress from the background script (e.g. "Taking a closer look at this site").
    browser.runtime.onMessage.addListener(message => {
      if (message?.type === "status" && shield.active) shield.say(message.text, message.detail);
      // The closer look that finished after the page was opened raised the verdict.
      if (message?.type === "verdict" && isTop && message.result) onVerdict(message.result);
      // A frame inside this page was judged malicious: block the whole page.
      if (message?.type === "frame-verdict" && isTop && message.result?.verdict === "malicious") {
        let from = "another site";
        try { from = new URL(message.result.frameUrl).host; } catch {}
        onVerdict({...message.result, summary: "A sign-in or payment form inside this page, from " + from +
          ", was judged malicious. " + (message.result.summary || "")});
      }
    });

    // Same list as pagehooks.js: programs, scripts, installers, disk images and
    // archives, macro documents, and HTML files (used to smuggle phishing pages).
    const riskyTypes = /\.(com|exe|msi|bat|cmd|scr|ps1|vbs|js|jse|wsf|hta|lnk|jar|dmg|pkg|app|command|terminal|tool|scpt|applescript|sh|zip|7z|rar|iso|img|vhdx?|html?|svg|docm|xlsm|pptm|one)$/i;
    const suspiciousCode = {
      eval: /\beval\s*\(/, newFunction: /new\s+Function\s*\(/, atob: /\batob\b/,
      documentWrite: /document\.write\s*\(/, fromCharCode: /fromCharCode/, unescape: /\bunescape\s*\(/,
      websocket: /wss?:\/\//, obfuscatedNames: /_0x[0-9a-f]{2,}/i
    };
    const approved = new WeakSet();
    // Filled-in secrets the person already let through on this page (by the model's
    // "allow" or their own "Proceed anyway"), as hashes: other clicks with the same
    // secrets aren't held again. A newly typed or changed secret is checked again.
    const clearedSecrets = new Set();

    // ---- Signal collection ---------------------------------------------------

    const originOf = value => {
      try { return new URL(value, location.href).origin; } catch { return "invalid"; }
    };
    // Never throws: one malformed link must not stop the whole check.
    const pathOf = value => {
      try { return new URL(value, location.href).pathname; } catch { return ""; }
    };
    const clipboardCommands = [];
    const secretSends = [];
    // Matched against whole words: field names are split at camelCase, "_", "-" and "."
    // first (cardNumber -> card number), so carDropOff ("car drop off") is not a card.
    const paymentWords = /\b((credit|debit)?card(holder|number|num|no|name)?|cvv2?|cvc2?|csc|security code|expir\w*|iban|routing|account number|ssn|social security)\b/i;
    const fieldWords = text => String(text || "").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_\-.\[\]]+/g, " ");
    // Only fields a person types or picks a secret into; choices (radio, checkbox),
    // buttons, dates and files never hold a card number or password.
    const typedTypes = new Set(["text", "tel", "number", "password", "search", "month", "email"]);
    const holdsTypedText = field => field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement ||
      (field instanceof HTMLInputElement && typedTypes.has(field.type));
    const clip = (text, max) => (text || "").replace(/\s+/g, " ").trim().slice(0, max);
    // Privacy: balances, account and card numbers, and dates never reach the model.
    // Page text and titles lose every digit; code and addresses lose long numbers
    // (account IDs), keeping short ones so code still reads as code.
    const maskDigits = text => (text || "").replace(/\d/g, "#");
    const maskLongNumbers = text => (text || "").replace(/\d{4,}/g, "####");

    function labelFor(element) {
      const label = element.labels?.[0]?.textContent || element.getAttribute("aria-label") ||
        element.getAttribute("placeholder") || "";
      return clip(label, 40);
    }

    function isPaymentField(field) {
      return holdsTypedText(field) && (paymentWords.test(fieldWords(labelFor(field) + " " + field.name + " " + field.id)) ||
        /^cc-/.test(field.getAttribute("autocomplete") || ""));
    }
    // A wallet's recovery (seed) phrase or private key: whoever has it owns the funds.
    const phraseWords = /recovery phrase|seed phrase|secret phrase|wallet phrase|mnemonic|private key|\b(12|24)[- ]word/i;
    function isPhraseField(field) {
      return (field instanceof HTMLTextAreaElement || (field instanceof HTMLInputElement && field.type !== "hidden")) &&
        phraseWords.test(labelFor(field) + " " + field.name + " " + field.id + " " + (field.getAttribute("placeholder") || ""));
    }
    function isSecretField(field) {
      return (field instanceof HTMLInputElement && field.type !== "hidden" &&
        (field.type === "password" || isPaymentField(field))) || isPhraseField(field);
    }
    // Every input on the page, including inside open shadow roots.
    function allInputs() {
      const found = [];
      const walk = root => {
        found.push(...root.querySelectorAll("input, textarea"));
        for (const element of root.querySelectorAll("*")) if (element.shadowRoot) walk(element.shadowRoot);
      };
      walk(document);
      return found;
    }
    function secretFieldsOutsideForms() {
      return allInputs().filter(field => isSecretField(field) && (!field.form || field.getRootNode() !== document));
    }

    const newPasswordWords = /\b(new|create|choose|confirm|re-?enter|repeat|retype|set up|sign up)\b/i;
    function createsPassword(fields) {
      return fields.length >= 2 || fields.some(f => f.getAttribute("autocomplete") === "new-password" ||
        newPasswordWords.test(labelFor(f) + " " + (f.getAttribute("placeholder") || "")));
    }

    function describeForm(form) {
      const actionOrigin = originOf(form.getAttribute("action") || location.href);
      return {
        actionOrigin,
        method: (form.getAttribute("method") || "get").toLowerCase(),
        crossOrigin: actionOrigin !== location.origin,
        hasPassword: !!form.querySelector('input[type="password"]'),
        // Sign-up or password change rather than sign-in: phishing wants existing passwords.
        ...(createsPassword([...form.querySelectorAll('input[type="password"]')]) ? {createsNewPassword: true} : {}),
        asksForPayment: [...form.querySelectorAll("input, select")].some(isPaymentField),
        ...([...form.querySelectorAll("input, textarea")].some(isPhraseField) ? {asksForRecoveryPhrase: true} : {}),
        // Field types and labels only, never values.
        fields: [...form.querySelectorAll("input, select, textarea")].slice(0, 15).map(field => ({
          type: field.type || field.tagName.toLowerCase(),
          name: maskLongNumbers(clip(field.name, 40)),
          label: maskDigits(labelFor(field))
        }))
      };
    }

    function hiddenFrame(frame) {
      const style = getComputedStyle(frame);
      const rect = frame.getBoundingClientRect();
      return style.display === "none" || style.visibility === "hidden" ||
        rect.width <= 2 || rect.height <= 2 || rect.right < 0 || rect.bottom < 0;
    }

    function collect() {
      const scripts = [...document.scripts];
      const links = [...document.querySelectorAll("a[href]")];
      return {
        page: {origin: location.origin,
               path: location.protocol === "blob:" ? "(none)" : maskLongNumbers(location.pathname.slice(0, 100)),
               title: maskDigits(clip(document.title, 120)), https: location.origin.startsWith("https:"),
               // Content no server sent: built in the browser by the site's script.
               ...(location.protocol === "blob:" ? {contentMadeByScript: "opened at a blob: address its script created"}
                 : rewrites ? {contentMadeByScript: "its script replaced the whole page (document.open/write)"} : {})},
        forms: [...document.forms].slice(0, 10).map(describeForm),
        scripts: {
          externalOrigins: [...new Set(scripts.filter(s => s.src).map(s => originOf(s.src)))].slice(0, 15),
          inline: scripts.filter(s => !s.src && s.textContent.trim()).slice(0, 5).map(s => ({
            length: s.textContent.length,
            flags: Object.keys(suspiciousCode).filter(k => suspiciousCode[k].test(s.textContent)),
            excerpt: maskLongNumbers(clip(s.textContent, 600))
          }))
        },
        iframes: [...document.querySelectorAll("iframe")].slice(0, 10).map(f => ({
          origin: f.src ? originOf(f.src) : "none", hidden: hiddenFrame(f)
        })),
        downloads: links.filter(a => a.hasAttribute("download") || riskyTypes.test(pathOf(a.href)))
          .slice(0, 10).map(a => ({origin: originOf(a.href), file: clip(pathOf(a.href).split("/").pop(), 60)})),
        // Password and card fields outside a regular form (sent by the page's own
        // script, or inside shadow DOM): forms above don't show them.
        secretFields: secretFieldsOutsideForms().slice(0, 10).map(field => ({
          type: field.type, name: maskLongNumbers(clip(field.name, 40)), label: maskDigits(labelFor(field)),
          ...(isPhraseField(field) ? {recoveryPhrase: true} : {}),
          ...(field.type === "password" && createsPassword([field]) ? {createsNewPassword: true} : {}),
          ...(field.getRootNode() !== document ? {inShadowRoot: true} : {})
        })),
        externalLinkOrigins: [...new Set(links.map(a => originOf(a.href)).filter(o => o !== location.origin))].slice(0, 15),
        // Commands this page tried to put on the clipboard (blocked by pagehooks.js).
        ...(clipboardCommands.length ? {clipboardCommands: clipboardCommands.slice(-3)} : {}),
        ...(secretSends.length ? {secretSends: secretSends.slice(-3)} : {}),
        // Trusted sites: structure only, never what the page says.
        text: trusted ? "" : maskDigits(clip(document.body?.innerText, 1500)),
        ...(trusted ? {textWithheld: "trusted site"} : {}),
        identity: identity(),
        images: [...document.images].filter(img => img.width >= 24 && img.height >= 24).slice(0, 12).map(img => ({
          alt: maskDigits(clip(img.alt, 60)),
          host: originOf(img.currentSrc || img.src),
          file: maskLongNumbers(clip(pathOf(img.currentSrc || img.src).split("/").pop(), 60))
        }))
      };
    }

    // Facts about the domain the model cannot work out by itself. Whether the user
    // has visited it before is added by the background script.
    function identity() {
      const host = location.hostname;
      const labels = host.split(".");
      const registrable = labels.slice(-2).join(".");
      const name = labels.length > 1 ? labels[labels.length - 2] : host;
      return {
        host,
        registrableDomain: registrable,
        punycode: /(^|\.)xn--/.test(host),
        digitsMixedIntoWord: /[a-z][0-9][a-z]|[a-z][0-9]$|^[0-9][a-z]/i.test(name),
        securityWordsInDomain: (host.match(/login|signin|secure|verify|account|update|support|wallet|auth/gi) || []).map(w => w.toLowerCase()),
        hyphens: (name.match(/-/g) || []).length,
        faviconHost: originOf(document.querySelector('link[rel~="icon"]')?.href || "/favicon.ico")
      };
    }

    // Pages that ask for credentials or payment details get a screenshot (except on trusted sites).
    function asksForSecrets(signals) {
      return signals.forms.some(f => f.hasPassword || f.asksForPayment || f.asksForRecoveryPhrase) ||
        signals.secretFields.length > 0;
    }

    // Wait (briefly) for images to load so the screenshot shows the real page.
    function pageLoaded(maxMs) {
      if (document.readyState === "complete") return Promise.resolve();
      return new Promise(resolve => {
        window.addEventListener("load", resolve, {once: true});
        setTimeout(resolve, maxMs);
      });
    }

    // What the page runs, for the verdict cache: full inline script text, script
    // URLs, form destinations and fields, frames, and download links. Visible text
    // is left out, so a news page with new headlines still matches.
    function fingerprintSource() {
      const scripts = [...document.scripts];
      return JSON.stringify([
        scripts.filter(s => s.src).map(s => s.src),
        scripts.filter(s => !s.src).map(s => s.textContent),
        [...document.forms].map(describeForm).map(f => [f.actionOrigin, f.method, f.fields.map(x => x.type + ":" + x.name)]),
        [...document.querySelectorAll("iframe")].map(f => f.src),
        [...document.querySelectorAll("a[download]")].map(a => a.href),
        document.title,
        [...new Set([...document.images].map(img => originOf(img.currentSrc || img.src) + " " + img.alt))].sort(),
        secretFieldsOutsideForms().map(f => f.type + ":" + f.name)
      ]).slice(0, 1000000);
    }

    // Full addresses of external scripts, so the background script can fingerprint
    // what they contain (a file swapped at the same address then triggers a re-check).
    function externalScriptUrls() {
      return [...new Set([...document.scripts].filter(s => s.src).map(s => s.src.split("#")[0]))]
        .filter(src => /^https?:/.test(src)).slice(0, 25);
    }

    // Safari suspends the background script when idle; the message that wakes it
    // can be dropped. Retry a few times instead of failing silently.
    // A sendMessage that never settles is treated as a failure after `ms`.
    function withTimeout(promise, ms) {
      return Promise.race([promise, new Promise((_, reject) =>
        setTimeout(() => reject(new Error("timed out after " + ms + " ms")), ms))]);
    }

    async function wakeBackground() {
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          if ((await withTimeout(browser.runtime.sendMessage({type: "ping"}), 2000))?.pong) return true;
        } catch (error) {
          console.warn("[Safari Script Observer] ping " + attempt + " failed:", error.message);
        }
        await new Promise(resolve => setTimeout(resolve, 300 * attempt));
      }
      return false;
    }

    async function send(message) {
      if (!await wakeBackground()) {
        console.warn("[Safari Script Observer] background script not responding; " + message.type + " skipped.");
        return null;
      }
      try {
        // Long enough for the analyzer's own 30 s model timeout.
        return await withTimeout(browser.runtime.sendMessage(message), 40000);
      } catch (error) {
        console.warn("[Safari Script Observer] " + message.type + " failed:", error.message);
        return null;
      }
    }

    // ---- Page assessment -----------------------------------------------------

    let assessments = 0;
    // The password/card fields (and their forms) as of the last verdict, so a
    // re-check of a page whose secret fields didn't change doesn't lock typing again.
    let judgedSecrets = null;
    const secretsOf = signals => JSON.stringify([
      signals.forms.filter(f => f.hasPassword || f.asksForPayment || f.asksForRecoveryPhrase).map(f => [f.actionOrigin, f.fields.map(x => x.type + ":" + x.name)]),
      signals.secretFields.map(f => f.type + ":" + f.name)]);

    // One check in flight at a time; a change during a check triggers one more.
    let inFlight = false;
    let pending = false;

    // What a re-check compares: structure (forms, scripts, frames, downloads,
    // secret fields), title, images, and the words of the visible text (digits are
    // masked, so counters and clocks don't count as changes).
    const wordsOf = text => new Set((text || "").toLowerCase().match(/[a-z\u00c0-\uffff]{3,}/g) || []);
    function overlap(a, b) {
      if (!a.size && !b.size) return 1;
      let shared = 0;
      for (const word of a) if (b.has(word)) shared++;
      return shared / (a.size + b.size - shared);
    }
    let lastSeen = null;
    let lastAssessAt = 0;
    let retryTimer = null;

    // A check that throws (an odd page) counts as a check that couldn't be done:
    // on pages asking for secrets, their fields stay locked (see onVerdict).
    async function assess() {
      try {
        await assessPage();
      } catch (error) {
        console.error("[Safari Script Observer] check failed:", error);
        onVerdict(null);
      }
    }

    async function assessPage() {
      if (own) return;
      await bypassReady;
      if (inFlight) {
        pending = true;
        return;
      }
      const signals = collect();
      const secrets = asksForSecrets(signals);
      // Frames are checked only once they ask for a password or payment details.
      if (!isTop && !secrets) return;
      const seen = {structure: JSON.stringify([signals.forms, signals.scripts, signals.iframes, signals.downloads, signals.secretFields,
                                                signals.clipboardCommands, signals.secretSends]),
                    title: signals.page.title, images: JSON.stringify(signals.images.map(i => [i.host, i.alt])),
                    words: wordsOf(signals.text), secrets};
      const textChanged = !!lastSeen && (seen.title !== lastSeen.title || overlap(seen.words, lastSeen.words) < 0.6);
      if (lastSeen && !textChanged && seen.structure === lastSeen.structure && seen.images === lastSeen.images) return;
      // After six checks, changes are spaced out so a page that keeps changing can't
      // flood the model, but is never left unchecked: changes to what the page says
      // or shows (text, title, images, password or card fields) within 5 seconds,
      // other structural churn within 20.
      const visible = textChanged || seen.images !== lastSeen?.images || !!signals.secretSends ||
        (secrets && !lastSeen?.secrets);
      const wait = assessments >= 6 ? lastAssessAt + (visible ? 5000 : 20000) - Date.now() : 0;
      if (wait > 0) {
        retryTimer ??= setTimeout(() => { retryTimer = null; assess(); }, wait);
        return;
      }
      lastSeen = seen;
      lastAssessAt = Date.now();
      inFlight = true;
      // New password or card fields: no typing into them until this check answers.
      const secretState = secretsOf(signals);
      if (secrets && secretState !== judgedSecrets) fieldGuard.pending();
      const message = {type: "assess", signals, fp: fingerprintSource(), newPage: isTop && assessments++ === 0,
                       asksForSecrets: secrets, trusted, textChanged, scriptUrls: externalScriptUrls()};
      if (!isTop) assessments++;
      send(message).then(async result => {
        // Not remembered, and the page asks for secrets: capture the page, then ask again.
        if (result?.needScreenshot) {
          await pageLoaded(2000);
          await shield.whileHidden(() => send({type: "capture"}));
          result = await send({...message, signals: collect(), newPage: false, screenshotTaken: true});
        }
        if (result?.verdict === "safe") judgedSecrets = secretState;
        return onVerdict(result);
      }).finally(() => {
        inFlight = false;
        if (pending) {
          pending = false;
          assess();
        }
      });
    }

    function onVerdict(result) {
      const verdict = result?.verdict;
      if (verdict === "malicious" && !result.allowedByUser && !isTop) {
        // The background script blocks the whole page; until then, this frame stays covered.
        shield.lock();
        shield.say("This sign-in form was blocked.", result.summary || "Your model judged it malicious.");
        return;
      }
      if (verdict === "malicious" && !result.allowedByUser) {
        // Replace the page with the extension's block page. This also stops the
        // page's scripts. replace() keeps the bad page out of history, so
        // "Go back" returns to the page before it.
        shield.say("This page was blocked.", result.summary || "Your model judged it malicious.");
        // Everything the block page shows travels in its address, so it needs no
        // extension storage access (Safari may not grant it to pages opened this way).
        const params = new URLSearchParams({url: location.href.split("#")[0], token: result.bypassToken || "",
          back: result.backUrl || "", summary: result.summary || "", source: result.source || "",
          reasons: JSON.stringify(result.reasons || [])});
        location.replace(browser.runtime.getURL("blocked.html") + "?" + params);
        // Safari may refuse to leave the page (seen after the user clicked through
        // Safari's own Deceptive Website Warning). If the page is still here, cover
        // it for good: the sealed full-page cover blocks all clicks and typing.
        setTimeout(() => {
          shield.lock();
          shield.danger();
          shield.say("This page was blocked.", (result.summary || "Your model judged it malicious.") +
            " Close this tab, or use Back to leave it.");
        }, 1500);
        return;
      }
      shield.lift();
      if (verdict === "malicious") {
        fieldGuard.open();
        keepWarning();
      } else if (verdict === "suspicious") {
        banner("Your model found this page suspicious. Open the extension for details.", "warn");
        fieldGuard.suspicious();
      } else if ((!result || verdict === "unchecked") && lastSeen?.secrets) {
        // No verdict on a page asking for secrets (the model timed out or could not
        // be reached; a page could try to cause that): its secret fields stay
        // locked until the user chooses to type, as on a suspicious page.
        banner("Your model could not check this page, so its password, card and recovery-phrase fields stay " +
               "locked until you choose to type.", "warn");
        fieldGuard.unchecked();
      } else {
        fieldGuard.open();
        if (!result) banner("The extension could not check this page.", "warn");
      }
    }

    // Password and card fields take no typing while the page's check is pending,
    // and on a suspicious page until you choose to type: a page's script can send
    // each keystroke as it is typed, long before any submit could be held.
    // Local-only stats (see stats.js): what the user chose despite a warning, and
    // how long typing waited for a check. Never blocks anything.
    const stat = message => {
      try { browser.runtime.sendMessage({type: "stat", ...message}).catch(() => {}); } catch {}
    };

    const fieldGuard = (() => {
      let state = "open"; // "open" | "pending" | "suspicious" | "unchecked"
      let unlocked = false;
      // When the user first tried to type into a held field while the check was pending.
      let waitingSince = null;
      const waitEnded = outcome => {
        if (waitingSince !== null) stat({event: "typing-wait", ms: Date.now() - waitingSince, outcome});
        waitingSince = null;
      };
      const letMeType = () => {
        unlocked = true;
        stat({event: "override", detail: state === "unchecked" ? "typed on an unchecked page" : "typed on a suspicious page"});
      };
      let installed = false;
      let note = null;
      const targetOf = event => event.composedPath?.()[0] || event.target;
      // "unchecked": no verdict could be had; held like a suspicious page.
      const wary = () => state === "suspicious" || state === "unchecked";
      const blocking = () => state === "pending" || (wary() && !unlocked);
      // On a suspicious page, a card number typed or pasted into any other box
      // (a chat message, a notes field, a fake card drawn without card fields)
      // is held too: a run of 13 or more digits, ignoring spaces and dashes.
      let cardNote = null;
      const cardLike = event => {
        if (!wary() || unlocked || !["beforeinput", "paste"].includes(event.type)) return false;
        const target = targetOf(event);
        const editable = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target?.isContentEditable;
        if (!editable) return false;
        const current = "value" in target ? String(target.value || "") : String(target.textContent || "");
        const added = event.type === "paste" ? event.clipboardData?.getData("text") || "" : event.data || "";
        const text = current + added;
        if (/\d{13,19}/.test(text.replace(/[\s-]/g, ""))) return "card";
        // Or a recovery phrase: 12 or more words of 3 to 8 letters and nothing else
        // (ordinary sentences have short words like "a", "to", "is").
        const words = text.trim().split(/\s+/);
        return words.length >= 12 && words.every(w => /^[a-z]{3,8}$/i.test(w)) ? "phrase" : false;
      };
      const stop = event => {
        const looksLike = cardLike(event);
        if (looksLike) {
          event.preventDefault();
          event.stopImmediatePropagation();
          if (!cardNote?.isConnected) {
            cardNote = banner((state === "unchecked" ? "Your model could not check this page" : "This page looks suspicious") +
              ", and what you are typing looks like " +
              (looksLike === "card" ? "a card number" : "a wallet recovery phrase") + ". " +
              "It could be sent as you type it.", "warn", () => {
                unlocked = true;
                stat({event: "override", detail: looksLike === "card" ? "typed a card number" : "typed a recovery phrase"});
              }, "Let me type");
          }
          return;
        }
        if (!blocking() || !isSecretField(targetOf(event))) return;
        event.preventDefault();
        event.stopImmediatePropagation();
      };
      const install = () => {
        if (installed) return;
        installed = true;
        for (const type of ["keydown", "keypress", "keyup", "beforeinput", "input", "paste", "drop"]) {
          on(type, stop, true);
        }
        on("focusin", event => {
          if (!blocking() || !isSecretField(targetOf(event))) return;
          if (state === "pending") waitingSince ??= Date.now();
          note = state === "pending"
            ? banner("Checking this page before you type here\u2026", "info")
            : banner((state === "unchecked" ? "Your model could not check this page" : "This page looks suspicious") +
                     ", and it could send what you type here as you type it.", "warn",
                     letMeType, "Let me type");
        }, true);
      };
      return {
        pending() { install(); if (state !== "suspicious") state = "pending"; },
        suspicious() { install(); waitEnded("suspicious"); state = "suspicious"; if (note?.getAttribute("role") === "status") note.remove(); },
        unchecked() { install(); waitEnded("unchecked"); state = "unchecked"; if (note?.getAttribute("role") === "status") note.remove(); },
        open() { waitEnded("open"); state = "open"; if (note?.getAttribute("role") === "status") note.remove(); }
      };
    })();

    // After "Visit this unsafe page": a warning bar that stays for as long as the
    // page is open, and a reminder whenever a password or payment field is used.
    let warned = false;
    // Sealed like the banners (closed shadow root), and put back if the page
    // removes it or rewrites itself: the page can't make the warning go away.
    function sealed(cssText, text) {
      const host = document.createElement("div");
      host.style.cssText = "all:initial;display:block;" + cssText;
      host.setAttribute("role", "alert");
      const box = document.createElement("div");
      box.textContent = text;
      host.attachShadow({mode: "closed"}).append(box);
      return {host, box};
    }

    function keepWarning() {
      if (warned) return;
      warned = true;
      const bar = sealed("position:fixed;top:0;left:0;right:0;z-index:2147483646",
        "\u26a0\ufe0f Your model judged this page malicious. You chose to open it anyway \u2014 " +
        "do not enter real passwords or payment details.");
      bar.box.style.cssText = "background:#b42318;color:#fff;font:14px system-ui;padding:8px 16px;text-align:center;" +
        "box-shadow:0 2px 8px rgba(0,0,0,.3)";
      const keep = () => { if (!bar.host.isConnected) document.documentElement?.append(bar.host); };
      keep();
      new MutationObserver(keep).observe(document, {childList: true, subtree: true});

      let tip;
      on("focusin", event => {
        const field = event.target;
        if (!(field instanceof HTMLInputElement)) return;
        const secret = field.type === "password" || (holdsTypedText(field) && paymentWords.test(fieldWords(field.name + " " +
          field.autocomplete + " " + (field.labels?.[0]?.textContent || "") + " " + (field.placeholder || ""))));
        if (!secret) return;
        tip?.host.remove();
        const box = field.getBoundingClientRect();
        tip = sealed("position:fixed;z-index:2147483647;max-width:320px;left:" + Math.max(8, box.left) + "px;top:0;visibility:hidden",
          "Warning: this page was judged malicious. Don't type real details here.");
        tip.box.style.cssText = "background:#b42318;color:#fff;font:13px system-ui;padding:6px 10px;border-radius:6px;" +
          "box-shadow:0 2px 8px rgba(0,0,0,.3)";
        document.documentElement.append(tip.host);
        // Above the field, where Safari's autofill menu (which opens below) can't
        // cover it; below only if there is no room above.
        const above = box.top - tip.host.offsetHeight - 6;
        tip.host.style.top = (above >= 4 ? above : box.bottom + 6) + "px";
        tip.host.style.visibility = "visible";
      }, true);
      on("focusout", () => tip?.host.remove(), true);
    }

    let timer;
    // Runs one second after the first change; changes in the meantime don't push it
    // back (a page that changes constantly can't postpone its re-check forever).
    const scheduleAssess = () => { timer ??= setTimeout(() => { timer = null; assess(); }, 1000); };
    new MutationObserver(scheduleAssess).observe(document, {
      childList: true, subtree: true, attributes: true, attributeFilter: ["action", "src", "href", "type"]
    });
    if (bypassMatch) {
      bypassReady = send({type: "bypass", token: bypassMatch[1]})
        .then(reply => console.info("[Safari Script Observer] bypass " + (reply?.ok ? "accepted" : "rejected")))
        .catch(() => null);
    }
    // Rewritten by document.open(): a new page as far as the user can tell.
    onRewrite = () => {
      // Counts as changed text, so no remembered verdict is reused.
      if (lastSeen) lastSeen = {...lastSeen, title: "\u0000rewritten"};
      scheduleAssess();
    };
    if (rewrites) onRewrite();
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", assess);
    else assess();

    // ---- Banner --------------------------------------------------------------

    let current;
    // Banners are drawn in a closed shadow root, and their buttons answer only real
    // clicks (event.isTrusted): the page's script can't read, reword or press them
    // (e.g. press "Let me type" on a suspicious page for the user).
    function banner(text, tone, proceed, proceedLabel = "Proceed anyway") {
      // A progress note never covers a warning: it is created but not shown.
      if (tone === "info" && current?.isConnected && current.dataset.tone === "danger") {
        return document.createElement("div");
      }
      current?.remove();
      const host = document.createElement("div");
      host.setAttribute("role", tone === "info" ? "status" : "alert");
      host.dataset.tone = tone;
      const colors = {danger: "#b42318", warn: "#b54708", info: "#344054"};
      host.style.cssText = "all:initial;position:fixed;top:16px;left:50%;transform:translateX(-50%);max-width:560px;" +
        "z-index:2147483647;display:block";
      const root = host.attachShadow({mode: "closed"});
      const note = document.createElement("div");
      note.style.cssText = "color:#fff;padding:10px 16px;border-radius:8px;font:14px system-ui;" +
        "box-shadow:0 4px 16px rgba(0,0,0,.3);background:" + colors[tone];
      note.append(text);
      const button = (label, action) => {
        const b = document.createElement("button");
        b.textContent = label;
        b.style.cssText = "margin-left:12px;font:inherit";
        b.addEventListener("click", event => {
          if (!event.isTrusted) return;
          host.remove();
          action?.();
        });
        note.append(b);
      };
      if (proceed) button(proceedLabel, proceed);
      if (tone === "danger") button("Dismiss");
      root.append(note);
      document.documentElement.append(host);
      current = host;
      if (tone === "info" || tone === "danger") return host;
      setTimeout(() => host.remove(), proceed ? 15000 : 8000);
      return host;
    }

    // ---- Action gating -------------------------------------------------------

    async function hold(event, target, action, resume, cleared) {
      if (own) return;
      if (approved.has(target)) {
        approved.delete(target);
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
      // This page's own scripts were caught sending a typed secret elsewhere: nothing
      // more is sent or saved from it.
      if (secretSends.length) return banner(sendWarning(secretSends.at(-1)), "danger");

      const waiting = banner("Checking with your model\u2026", "info");
      const verdict = await send({type: "gate", action, signals: collect()});
      waiting.remove();

      const go = () => { approved.add(target); cleared?.(); resume(); };
      if (verdict?.decision === "allow") return go();
      if (verdict?.decision === "block") {
        return banner(verdict.checkFailed ? "Blocked: this page could not be checked although your model server is working."
          : "Blocked by your model. Open the extension for details.", "danger");
      }
      banner("Could not check this. " + (verdict?.summary || ""), "warn", () => {
        stat({event: "override", detail: "went ahead after a failed check"});
        go();
      });
    }

    function onClick(event) {
      const element = event.composedPath?.()[0] instanceof Element ? event.composedPath()[0]
        : event.target instanceof Element ? event.target : null;
      if (!element) return;
      const link = element.closest("a[href]");
      let url = null;
      try { url = link && new URL(link.href, location.href); } catch {}
      if (url && ["http:", "https:"].includes(url.protocol) &&
          (link.hasAttribute("download") || riskyTypes.test(url.pathname))) {
        return hold(event, link, {kind: "download", url: url.href}, () => link.click());
      }
      // A button that isn't a form's submit button, while a password or card field
      // is filled in: the page's own script may be about to send it.
      const button = element.closest('button, input[type="button"], input[type="submit"], [role="button"], a');
      if (!button || (button.form && button.type === "submit")) return; // submits are held in onSubmit
      // Only secrets the person can see or typed in: a box filled out of sight (for
      // example a hidden sign-in form AutoFill completed) doesn't hold every click.
      const filled = allInputs().filter(field => isSecretField(field) && field.value &&
        (field.getClientRects().length > 0 || typedInto.has(field)));
      if (!filled.length) return;
      const secretsKey = hashOf(filled.map(f => f.name + "\u0000" + f.value).join("\u0001"));
      if (clearedSecrets.has(secretsKey)) return;
      hold(event, button, {kind: "submit", form: {
        actionOrigin: "unknown: sent by the page's own script", method: "script", crossOrigin: null,
        hasPassword: filled.some(f => f.type === "password"), asksForPayment: filled.some(isPaymentField),
        ...(filled.some(isPhraseField) ? {asksForRecoveryPhrase: true} : {}),
        fields: filled.slice(0, 15).map(f => ({type: f.type, name: maskLongNumbers(clip(f.name, 40)), label: maskDigits(labelFor(f))}))
      }}, () => button.click(), () => clearedSecrets.add(secretsKey));
    }

    function onSubmit(event) {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      const described = describeForm(form);
      if (!described.hasPassword && !described.asksForPayment && !described.asksForRecoveryPhrase) return;
      hold(event, form, {kind: "submit", form: described}, () => form.requestSubmit());
    }

    // ---- Reports from pagehooks.js -------------------------------------------------
    // A command the page tried to put on the clipboard (already blocked there), or a
    // file the page built or saves by script (not saved). After the model allows it,
    // this script copies or saves it itself, on the user's click: nothing is resumed
    // in the page's context, where the page could fake the go-ahead.
    // Whether the copied text is what the page visibly shows. A copy that adds
    // text the user cannot see ("pastejacking") is a strong sign of a scam.
    // Copy buttons in chat apps and docs often copy Markdown while the page shows it
    // formatted, so formatting is ignored and the copy is compared line by line: only
    // lines that appear nowhere on the page count as hidden.
    function comparedWithPage(command) {
      const norm = text => String(text || "").replace(/\s+/g, " ").replace(/^\s*\$\s+/, "").trim();
      const plain = line => norm(String(line)
        .replace(/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/, "")           // table divider row
        .replace(/^\s*\|(.*)\|\s*$/, (_, cells) => cells.split("|").join(" "))     // table row
        .replace(/^\s*(#{1,6}\s+|>\s?|[-*+]\s+|\d+[.)]\s+)/, "")                   // heading, quote, list marker
        .replace(/!?\[([^\]]*)\]\([^)\s]*\)/g, "$1")                               // link or image: its text
        .replace(/\*\*|__|`+|~~/g, "")                                              // bold, code, strikethrough
        .replace(/^\s*```.*$/, ""));                                                // code fence
      const copied = norm(command);
      const pageText = norm(document.body?.innerText);
      if (pageText.includes(copied)) return {shownOnPage: true};
      const pagePlain = norm(pageText.replace(/\t/g, " "));
      const lines = String(command).split(/\r?\n/).map(plain).filter(Boolean);
      const hidden = lines.filter(line => !pagePlain.includes(line));
      if (lines.length && !hidden.length) return {shownOnPage: true};
      if (lines.length > 1 && hidden.length < lines.length) {
        return {shownOnPage: false, shownPart: lines.filter(line => !hidden.includes(line)).join("\n").slice(0, 300),
                hiddenPart: hidden.join("\n").slice(0, 500)};
      }
      const onScreen = element => {
        const box = element.getBoundingClientRect();
        return box.width > 2 && box.height > 2 && box.right > 0 && box.bottom > 0 &&
          getComputedStyle(element).visibility !== "hidden" && getComputedStyle(element).opacity !== "0";
      };
      const shown = [...document.querySelectorAll("pre, code, kbd, samp, input, textarea")]
        .filter(onScreen).map(e => norm("value" in e ? e.value : e.innerText))
        .filter(text => text.length >= 8 && copied.includes(text)).sort((a, b) => b.length - a.length)[0] || "";
      return {shownOnPage: false, shownPart: shown.slice(0, 300),
              hiddenPart: (shown ? copied.replace(shown, " \u2026 ") : copied).trim().slice(0, 500)};
    }

    async function clipboardAttempt(hook) {
      const command = String(hook.text || "").slice(0, 2000);
      if (!command) return;
      if (own) return void navigator.clipboard.writeText(command).catch(() => {});
      clipboardCommands.push(command.slice(0, 300));
      const waiting = banner("This page tried to put a command on your clipboard. Checking it with your model\u2026", "info");
      const verdict = await send({type: "gate", action: {kind: "clipboard", command, via: String(hook.via || ""),
                                                          ...comparedWithPage(command)}, signals: collect()});
      waiting.remove();
      const copy = () => navigator.clipboard.writeText(command).catch(() => {});
      if (verdict?.decision === "allow") {
        banner("This page wants to copy a command to your clipboard. Your model found no problem with it.", "info", copy, "Copy it");
      } else if (verdict?.decision === "block") {
        banner("Blocked: this page tried to put a command on your clipboard. Sites that ask you to paste a command " +
               "into Terminal, Run or PowerShell are a common scam. Don't run it.", "danger");
        scheduleAssess(); // the page itself is judged again, with this attempt
      } else {
        banner("This page tried to put a command on your clipboard, and it could not be checked.", "warn", () => {
          stat({event: "override", detail: "copied a command anyway"});
          copy();
        }, "Copy anyway");
      }
    }

    // A script on this page tried to send a password or card number the person typed
    // to another site (already stopped in the page). Shown, counted, and given to the
    // model as evidence: the page is judged again with it.
    const sendWarning = send => "Blocked: a script on this page tried to send the " + send.sent.join(" and ") +
      " you typed to " + send.destination + ". This is how skimmers on hacked sites steal passwords and cards. Don't continue on this page.";
    function secretSent(hook) {
      let destination = "";
      try { destination = new URL(String(hook.destination)).host; } catch { return; }
      const kinds = (Array.isArray(hook.kinds) ? hook.kinds : []).filter(k => ["password", "card number"].includes(k));
      if (!kinds.length) return;
      secretSends.push({destination, sent: kinds, via: String(hook.via || "").slice(0, 30)});
      banner(sendWarning(secretSends.at(-1)), "danger");
      stat({event: "send blocked", detail: destination});
      scheduleAssess();
    }

    async function fileAttempt(hook) {
      const name = String(hook.name || pathOf(hook.href || "").split("/").pop() || "download").slice(0, 80);
      const action = hook.href
        ? {kind: "download", url: String(hook.href)}
        : {kind: "download", file: {origin: "built by the page itself (" + String(hook.source) + " link)", name,
            size: hook.size, contentType: String(hook.contentType || "").slice(0, 100), prefix: String(hook.prefix || "")}};
      const waiting = own ? null : banner("Checking a file this page wants to save\u2026", "info");
      const verdict = own ? null : await send({type: "gate", action, signals: collect()});
      waiting?.remove();
      const save = () => {
        const link = document.createElement("a");
        link.download = name;
        if (hook.href) link.href = String(hook.href);
        else if (hook.data) {
          const bytes = Uint8Array.from(atob(hook.data), c => c.charCodeAt(0));
          link.href = URL.createObjectURL(new Blob([bytes], {type: "application/octet-stream"}));
          setTimeout(() => URL.revokeObjectURL(link.href), 60000);
        } else return;
        link.click();
      };
      if (own) return save();
      if (verdict?.decision === "allow") banner("Your model checked " + name + " and found no problem.", "info", save, "Save file");
      else if (verdict?.decision === "block") banner("Blocked the file " + name + ". Open the extension for details.", "danger");
      else banner("The file " + name + " could not be checked.", "warn", () => {
        stat({event: "override", detail: "saved a file anyway"});
        save();
      }, "Save anyway");
    }

    onHook = hook => {
      if (hook?.type === "clipboard") clipboardAttempt(hook);
      else if (hook?.type === "send") secretSent(hook);
      else if (hook?.type === "download") fileAttempt(hook);
    };
    hookQueue.splice(0).forEach(hook => onHook(hook));

    // Fields the person typed into (trusted input), for onClick.
    const typedInto = new WeakSet();
    on("input", event => { if (event.isTrusted && event.target instanceof Element) typedInto.add(event.target); }, true);
    on("click", onClick, true);
    on("auxclick", onClick, true);
    on("submit", onSubmit, true);
  }

  // A site matches if it is a listed domain or a subdomain of one.
  function onSkipList(host, list) {
    return list.some(domain => host === domain || host.endsWith("." + domain));
  }

  // Whether this page is on the person's own network (see "own" in start), counted
  // only where it can be proven:
  // - the model server's own address when it is this Mac (localhost);
  // - on Tailscale, any device on the model server's tailnet, over https only: only
  //   that tailnet can get a certificate for its names, while over http a hostile
  //   network's DNS could answer for them.
  // Not private IP addresses (192.168.x, 10.x): on hotel or café Wi-Fi the same
  // address is someone else's machine. Not other ts.net names: Tailscale Funnel can
  // publish anyone's to the internet.
  function onOwnNetwork(location, llm) {
    let server;
    try {
      server = new URL(llm?.kind === "ollama" ? llm.ollamaUrl || "http://localhost:11434" : llm?.customUrl);
    } catch { return false; }
    const serverHost = server.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const host = String(location.hostname).replace(/^\[|\]$/g, "").toLowerCase();
    const loopback = h => h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
    if (loopback(serverHost)) return host === serverHost;
    const tailnet = server.protocol === "https:" && serverHost.match(/^[^.]+\.([^.]+\.ts\.net)$/)?.[1];
    return !!tailnet && location.protocol === "https:" && (host === serverHost || host.endsWith("." + tailnet));
  }

  // A short hash (FNV-1a), so secrets the person let through aren't kept as text.
  function hashOf(text) {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 0x01000193) >>> 0;
    return h.toString(36) + ":" + text.length;
  }
})();
