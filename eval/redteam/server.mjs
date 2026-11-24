// Offline web for the red-team test: answers every hostname declared in the
// scenarios from test-site/redteam/<id>/<hostname>/, records requests carrying a
// canary, and refuses everything else. Used two ways:
//   - by Chromium through a local proxy (every request, any host, lands here);
//   - in-process by the harness's stand-in for the extension's native app.
import {createServer as createHttpServer} from "node:http";
import {createServer as createHttpsServer} from "node:https";
import {connect} from "node:net";
import {readFileSync, readdirSync, existsSync, statSync} from "node:fs";
import {extname, join, normalize} from "node:path";
import {execFileSync} from "node:child_process";

const types = {".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8", ".js": "text/javascript",
  ".mjs": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml",
  ".png": "image/png", ".jpg": "image/jpeg", ".gif": "image/gif", ".ico": "image/x-icon", ".txt": "text/plain",
  ".pdf": "application/pdf", ".csv": "text/csv", ".xml": "application/xml", ".webmanifest": "application/manifest+json"};

export function loadScenarios(root) {
  const scenarios = [];
  for (const id of readdirSync(root).sort()) {
    const file = join(root, id, "scenario.json");
    if (!existsSync(file)) continue;
    try {
      scenarios.push({...JSON.parse(readFileSync(file, "utf8")), dir: join(root, id), folder: id});
    } catch (error) {
      console.warn("Skipping " + id + ": " + error.message);
    }
  }
  return scenarios;
}

export function createLab(scenarios) {
  const hosts = new Map(); // hostname -> {dir, scenario}
  for (const s of scenarios) {
    for (const host of Object.keys(s.hosts || {})) {
      const h = host.toLowerCase();
      if (hosts.has(h)) console.warn(`Host ${h} is declared by both ${hosts.get(h).scenario.folder} and ${s.folder}`);
      hosts.set(h, {dir: join(s.dir, host), scenario: s});
    }
  }
  const canaries = [...new Set(scenarios.flatMap(s => [...(s.harm?.canaries || []), ...(s.expect?.canaries || [])]))]
    .filter(c => typeof c === "string" && c.length >= 4);
  const hits = [];

  // One request -> {status, headers, body}. `body` of the request is a Buffer or string.
  function handle({method = "GET", host, path = "/", body = ""}) {
    const h = String(host || "").toLowerCase().replace(/:\d+$/, "");
    const text = String(path) + "\n" + (Buffer.isBuffer(body) ? body.toString("latin1") : String(body || ""));
    let decoded = text;
    try { decoded = decodeURIComponent(text.replace(/\+/g, " ")); } catch {}
    for (const canary of canaries) {
      if (text.includes(canary) || decoded.includes(canary)) {
        hits.push({host: h, method, path: String(path).slice(0, 200), canary, at: Date.now()});
      }
    }
    const site = hosts.get(h);
    if (!site) return {status: 404, headers: {"content-type": "text/plain"}, body: "No such host in the lab: " + h};
    // Cross-site API calls: answer the browser's preflight like a typical API would.
    if (method === "OPTIONS") {
      return {status: 204, headers: {"access-control-allow-origin": "*", "access-control-allow-methods": "*",
                                     "access-control-allow-headers": "*", "access-control-allow-credentials": "true"}, body: ""};
    }
    if (method !== "GET" && method !== "HEAD") {
      return {status: 200, headers: {"content-type": "application/json", "access-control-allow-origin": "*"}, body: '{"ok":true}'};
    }
    let rel = decodeURIComponent(String(path).split("?")[0].split("#")[0]);
    if (rel.endsWith("/")) rel += "index.html";
    const file = normalize(join(site.dir, rel));
    if (!file.startsWith(site.dir) || !existsSync(file) || !statSync(file).isFile()) {
      // Query-string beacons (e.g. /c.gif?d=...) and missing files.
      return {status: String(path).includes("?") ? 200 : 404, headers: {"content-type": "text/plain"}, body: ""};
    }
    // Files without an extension are web pages (paths like /login, /install).
    const ext = extname(file).toLowerCase();
    return {status: 200, headers: {"content-type": ext ? types[ext] || "application/octet-stream" : "text/html; charset=utf-8",
                                   "cache-control": "no-store"}, body: readFileSync(file)};
  }

  return {hosts, canaries, hits, handle};
}

// Real listeners for the browser: an HTTP server, an HTTPS server (self-signed;
// the browser ignores certificate errors), and a proxy that sends every request
// to one of them.
export async function startServers(lab, workDir) {
  const key = join(workDir, "lab.key"), cert = join(workDir, "lab.crt");
  if (!existsSync(cert)) {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
      "-days", "30", "-subj", "/CN=redteam.lab"], {stdio: "ignore"});
  }
  const serve = (request, response) => {
    const chunks = [];
    request.on("data", c => chunks.push(c));
    request.on("end", () => {
      const result = lab.handle({method: request.method, host: request.headers.host, path: request.url, body: Buffer.concat(chunks)});
      response.writeHead(result.status, result.headers);
      response.end(request.method === "HEAD" ? undefined : result.body);
    });
  };
  const http = createHttpServer(serve).listen(0, "127.0.0.1");
  const https = createHttpsServer({key: readFileSync(key), cert: readFileSync(cert)}, serve).listen(0, "127.0.0.1");
  await Promise.all([http, https].map(s => new Promise(r => s.listening ? r() : s.once("listening", r))));
  const httpPort = http.address().port, httpsPort = https.address().port;

  // CONNECT (https) goes to the HTTPS server; plain proxied http to the HTTP server.
  const proxy = createHttpServer((request, response) => {
    const url = new URL(request.url);
    const chunks = [];
    request.on("data", c => chunks.push(c));
    request.on("end", () => {
      const result = lab.handle({method: request.method, host: url.host, path: url.pathname + url.search, body: Buffer.concat(chunks)});
      response.writeHead(result.status, result.headers);
      response.end(result.body);
    });
  });
  proxy.on("connect", (request, socket, head) => {
    const upstream = connect(httpsPort, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  });
  proxy.listen(0, "127.0.0.1");
  await new Promise(r => proxy.once("listening", r));
  return {proxyPort: proxy.address().port, close() { http.close(); https.close(); proxy.close(); }};
}
