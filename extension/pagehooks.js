// Runs in the page's own JavaScript context ("world": "MAIN"), before the page's
// scripts, to see two things an isolated content script cannot:
//
//   1. Commands put on the clipboard by script ("paste this into Terminal" scams,
//      a.k.a. ClickFix): clipboard.writeText, execCommand("copy"/"cut"), and
//      clipboardData.setData during a copy.
//   2. Files the page builds itself (blob:/data: links, HTML smuggling), and
//      download links clicked by script while not attached to the page.
//   3. A typed password or card number sent by script to another site (web
//      skimmers such as the 2018 British Airways attack).
//
// It only ever BLOCKS and REPORTS. The page shares this context and could fake
// any message sent back here, so nothing is resumed from here: after the model
// allows it, the extension's isolated script copies the command or saves the file
// itself, on the user's click (see inspector.js).
(() => {
  // Web pages, and pages a web page builds in the browser itself (blob:https://site/...,
  // e.g. HTML smuggling), which belong to that site.
  if (!/^https?:$/.test(location.protocol) &&
      !(location.protocol === "blob:" && /^https?:\/\//.test(location.origin))) return;

  const report = detail => window.dispatchEvent(new CustomEvent("__sso_hook", {detail: JSON.stringify(detail)}));

  // Commands that download or run code, decode hidden code, or weaken security:
  // what "paste this into Terminal / Run / PowerShell" scams put on the clipboard.
  // A broad pre-filter only; the user's model decides.
  const commandLike = new RegExp([
    "\\b(curl|wget)\\b[^\\n]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b", "\\b(ba|z)?sh\\s+-c\\b", "/bin/(ba|z)?sh\\b",
    "\\bbase64\\s+(-d|-D|--decode)\\b", "\\bosascript\\b", "\\bxattr\\s+-[a-z]*[cd]", "\\bspctl\\s+--master-disable",
    "\\bchmod\\s+\\+x\\b", "\\blaunchctl\\b", "\\bnohup\\b",
    "\\bpowershell\\b", "\\bpwsh\\b", "\\biex\\b", "\\binvoke-(expression|webrequest)\\b", "\\biwr\\b",
    "-enc(odedcommand)?\\b", "\\bmshta\\b", "\\bcmd(\\.exe)?\\s+/c\\b", "\\brundll32\\b", "\\bregsvr32\\b",
    "\\bcertutil\\b[^\\n]*-urlcache", "\\bbitsadmin\\b", "\\bstart-process\\b", "\\bfrombase64string\\b",
    // JavaScript meant for the browser console or address bar ("paste this into
    // the Console to verify"): reads session data, runs hidden code, or adds scripts.
    "document\\.cookie", "\\b(local|session)Storage\\b", "\\bindexedDB\\b", "\\beval\\s*\\(",
    "\\bnew\\s+Function\\s*\\(", "\\batob\\s*\\(", "fromCharCode", "createElement\\(\\s*['\"`]script",
    "^\\s*javascript:"
  ].join("|"), "im");

  // ---- Clipboard ------------------------------------------------------------------
  const clipboardProto = window.Clipboard?.prototype;
  const writeText = clipboardProto?.writeText;
  if (writeText) {
    clipboardProto.writeText = function (text) {
      if (commandLike.test(String(text))) {
        report({type: "clipboard", via: "clipboard.writeText", text: String(text).slice(0, 2000)});
        return Promise.resolve(); // the page believes it copied
      }
      return writeText.call(this, text);
    };
  }

  const execCommand = Document.prototype.execCommand;
  Document.prototype.execCommand = function (command, ...rest) {
    if (/^(copy|cut)$/i.test(String(command))) {
      const field = document.activeElement;
      const text = field && "selectionStart" in field && typeof field.value === "string"
        ? field.value.slice(field.selectionStart ?? 0, field.selectionEnd ?? field.value.length)
        : String(getSelection?.() || "");
      if (commandLike.test(text)) {
        report({type: "clipboard", via: "document.execCommand", text: text.slice(0, 2000)});
        return false;
      }
    }
    return execCommand.call(this, command, ...rest);
  };

  // Pages can also replace what a copy puts on the clipboard from a "copy" handler.
  let copying = false;
  window.addEventListener("copy", () => { copying = true; setTimeout(() => { copying = false; }, 0); }, true);
  window.addEventListener("cut", () => { copying = true; setTimeout(() => { copying = false; }, 0); }, true);
  const setData = DataTransfer.prototype.setData;
  DataTransfer.prototype.setData = function (format, data) {
    if (copying && commandLike.test(String(data))) {
      report({type: "clipboard", via: "copy event", text: String(data).slice(0, 2000)});
      return setData.call(this, format, "");
    }
    return setData.call(this, format, data);
  };

  // ---- Files built by the page ------------------------------------------------------
  const riskyTypes = /\.(com|exe|msi|bat|cmd|scr|ps1|vbs|js|jse|wsf|hta|lnk|jar|dmg|pkg|app|command|terminal|tool|scpt|applescript|sh|zip|7z|rar|iso|img|vhdx?|html?|svg|docm|xlsm|pptm|one)$/i;
  const maxBytes = 20 * 1024 * 1024;

  function toBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  }

  async function reportBuiltFile(anchor) {
    const name = (anchor.getAttribute("download") || "download").slice(0, 80);
    try {
      const response = await fetch(anchor.href);
      const bytes = new Uint8Array(await response.arrayBuffer());
      report({type: "download", source: anchor.href.slice(0, 5), name, contentType: response.headers.get("content-type") || "",
              size: bytes.length, data: bytes.length <= maxBytes ? toBase64(bytes) : null,
              // The start of the file: enough for signatures, the file type, and the
              // first few kilobytes of a script or web page for the model to read.
              prefix: toBase64(bytes.subarray(0, 8192))});
    } catch {
      report({type: "download", source: anchor.href.slice(0, 5), name, size: null, data: null, prefix: ""});
    }
  }

  const builtByPage = anchor => /^(blob|data):/i.test(anchor.href || "");

  // Script-triggered clicks: blob/data files always; ordinary download links only
  // when detached from the page (attached ones reach the isolated script's click check).
  const anchorClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    if (builtByPage(this)) return void reportBuiltFile(this);
    let path = "";
    try { path = new URL(this.href, location.href).pathname; } catch {}
    if (!this.isConnected && /^https?:/i.test(this.href) && (this.hasAttribute("download") || riskyTypes.test(path))) {
      return void report({type: "download", source: "link", href: this.href});
    }
    return anchorClick.call(this);
  };

  // ---- Typed secrets sent to another site (web skimmers, e.g. Magecart) -------------
  // While a password or a card number is typed into this page, a request from the
  // page's scripts that carries it (as typed, digits only, URL-encoded or base64) to
  // another site is blocked and reported, before it leaves. Known payment and sign-in
  // providers, and the site a field's own form sends to, are not "another site".
  // The comparison happens here; the secret itself is never reported.
  const typedFields = new Set();
  window.addEventListener("input", event => {
    const field = event.composedPath?.()[0];
    if (event.isTrusted && field instanceof HTMLInputElement) typedFields.add(field);
  }, true);
  const luhn = digits => {
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let d = digits.charCodeAt(digits.length - 1 - i) - 48;
      if (i % 2) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  };
  function typedSecrets() {
    const found = [];
    const fields = new Set([...typedFields, ...document.querySelectorAll('input[type="password"]')]);
    for (const field of fields) {
      const value = field.isConnected ? String(field.value || "") : "";
      const digits = value.replace(/[\s-]/g, "");
      if (field.type === "password" && value.length >= 4) found.push({kind: "password", value, field});
      else if (/^\d{13,19}$/.test(digits) && luhn(digits)) found.push({kind: "card number", value: digits, field});
    }
    return found;
  }
  // The site of a host name (approximate: "shop.example.co.uk" -> "example.co.uk").
  const siteOf = host => {
    const labels = String(host).toLowerCase().split(".");
    if (/^[\d.]+$/.test(host) || labels.length <= 2) return labels.join(".");
    const twoPart = labels.at(-1).length === 2 && labels.at(-2).length <= 3;
    return labels.slice(twoPart ? -3 : -2).join(".");
  };
  const providers = new Set(["stripe.com", "stripe.network", "braintreegateway.com", "braintree-api.com", "paypal.com",
    "adyen.com", "adyenpayments.com", "checkout.com", "squareup.com", "square.com", "authorize.net", "cybersource.com",
    "worldpay.com", "klarna.com", "afterpay.com", "shopifycs.com", "recurly.com", "chargebee.com", "mollie.com",
    "razorpay.com", "mercadopago.com", "paddle.com", "spreedly.com", "verygoodvault.com", "apple.com", "google.com",
    "okta.com", "oktapreview.com", "auth0.com", "microsoftonline.com", "live.com", "onelogin.com", "pingidentity.com",
    "amazoncognito.com", "clerk.com", "stytch.com", "supabase.co"]);
  const providerHost = host => providers.has(siteOf(host)) || /^(cognito-idp\.[a-z0-9-]+\.amazonaws\.com|(identitytoolkit|securetoken)\.googleapis\.com)$/.test(host);
  function contains(text, value) {
    if (!text) return false;
    if (text.includes(value) || text.includes(encodeURIComponent(value))) return true;
    if (/^\d+$/.test(value) && text.replace(/[\s-]|%20/g, "").includes(value)) return true;
    for (const token of (text.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) || []).slice(0, 50)) {
      try { if (atob(token.replace(/-/g, "+").replace(/_/g, "/")).includes(value)) return true; } catch {}
    }
    return false;
  }
  const asText = body => {
    try {
      if (body == null) return "";
      if (typeof body === "string") return body;
      if (body instanceof URLSearchParams) return body.toString();
      if (body instanceof FormData) return [...body].map(([k, v]) => k + "=" + (typeof v === "string" ? v : "")).join("&");
      if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return new TextDecoder().decode(body);
    } catch {}
    return "";
  };
  // Whether a request must be stopped; reports it once per site and kind.
  const reportedSends = new Set();
  function stopsSecret(url, body, via) {
    const secrets = typedSecrets();
    if (!secrets.length) return false;
    let target;
    try { target = new URL(url, location.href); } catch { return false; }
    if (!/^(https?|wss?):$/.test(target.protocol)) return false;
    const host = target.hostname;
    if (siteOf(host) === siteOf(location.hostname) || providerHost(host)) return false;
    const text = target.href + "\n" + asText(body);
    const sent = secrets.filter(s => {
      let formSite = "";
      try { formSite = s.field.form ? siteOf(new URL(s.field.form.action, location.href).hostname) : ""; } catch {}
      return formSite !== siteOf(host) && contains(text, s.value);
    });
    if (!sent.length) return false;
    const kinds = [...new Set(sent.map(s => s.kind))];
    const key = target.origin + "|" + kinds.join(",");
    if (!reportedSends.has(key)) {
      reportedSends.add(key);
      report({type: "send", destination: target.origin, kinds, via});
    }
    return true;
  }

  const nativeFetch = window.fetch;
  window.fetch = async function (input, init) {
    if (typedSecrets().length) {
      const url = input instanceof Request ? input.url : String(input);
      let body = init?.body;
      if (body === undefined && input instanceof Request) body = await input.clone().text().catch(() => "");
      if (body instanceof Blob) body = await body.text().catch(() => "");
      if (stopsSecret(url, body, "fetch")) throw new TypeError("Failed to fetch");
    }
    return nativeFetch.apply(this, arguments);
  };
  const xhrOpen = XMLHttpRequest.prototype.open, xhrSend = XMLHttpRequest.prototype.send;
  const xhrUrls = new WeakMap();
  XMLHttpRequest.prototype.open = function (method, url) {
    xhrUrls.set(this, String(url));
    return xhrOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    if (stopsSecret(xhrUrls.get(this) || "", body, "XMLHttpRequest")) {
      setTimeout(() => this.dispatchEvent(new ProgressEvent("error")), 0);
      return;
    }
    return xhrSend.apply(this, arguments);
  };
  const beacon = Navigator.prototype.sendBeacon;
  if (beacon) {
    Navigator.prototype.sendBeacon = function (url, data) {
      return stopsSecret(url, data, "sendBeacon") ? false : beacon.apply(this, arguments);
    };
  }
  const wsSend = window.WebSocket?.prototype.send;
  if (wsSend) {
    WebSocket.prototype.send = function (data) {
      if (stopsSecret(this.url, data, "WebSocket")) return;
      return wsSend.apply(this, arguments);
    };
  }
  // Image and script addresses that carry the data ("pixel" or JSONP exfiltration).
  for (const Element of [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement]) {
    const src = Object.getOwnPropertyDescriptor(Element.prototype, "src");
    if (!src?.set) continue;
    Object.defineProperty(Element.prototype, "src", {...src, set(value) {
      if (stopsSecret(String(value), "", Element.name.replace(/^HTML|Element$/g, "").toLowerCase() + " address")) return;
      src.set.call(this, value);
    }});
  }
  const setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    if (/^src$/i.test(String(name)) && /^(IMG|SCRIPT|IFRAME)$/.test(this.tagName) &&
        stopsSecret(String(value), "", this.tagName.toLowerCase() + " address")) return;
    return setAttribute.call(this, name, value);
  };

  // Real clicks on blob/data links (registered before the page's own listeners).
  window.addEventListener("click", event => {
    const anchor = event.composedPath?.()[0]?.closest?.("a[href]");
    if (!anchor || !builtByPage(anchor)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    reportBuiltFile(anchor);
  }, true);
})();
