// Local test server for eval/native-check/run.sh: big, slow-drip and redirecting responses.
import http from "node:http";
http.createServer((req, res) => {
  if (req.url === "/big") { res.end(Buffer.alloc(5_000_000, 97)); return; }
  if (req.url === "/drip") { let n = 0; const t = setInterval(() => { res.write(Buffer.alloc(65536, 98)); if (++n > 40) { clearInterval(t); res.end(); } }, 400); return; }
  if (req.url === "/redirect-local") { res.writeHead(302, {Location: "http://127.0.0.1:8799/secret"}); res.end(); return; }
  res.end("hello from local " + req.url);
}).listen(8799, "127.0.0.1");
