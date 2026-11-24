// Runs in the page's own JavaScript context ("world": "MAIN"), before the page's
// scripts, to see two things an isolated content script cannot:
//
//   1. Commands put on the clipboard by script ("paste this into Terminal" scams,
//      a.k.a. ClickFix): clipboard.writeText, execCommand("copy"/"cut"), and
//      clipboardData.setData during a copy.
//   2. Files the page builds itself (blob:/data: links, HTML smuggling), and
//      download links clicked by script while not attached to the page.
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

  // Real clicks on blob/data links (registered before the page's own listeners).
  window.addEventListener("click", event => {
    const anchor = event.composedPath?.()[0]?.closest?.("a[href]");
    if (!anchor || !builtByPage(anchor)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    reportBuiltFile(anchor);
  }, true);
})();
