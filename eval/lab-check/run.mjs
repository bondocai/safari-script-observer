// Evasion check for the extension's page scanning.
//
//   node eval/lab-check/run.mjs
//
// 1. Runs check.mjs in the sandbox container (headless Chromium, no network),
//    against the lab sites in test-site/lab/, with the extension's real
//    inspector.js. Needs Docker and the sso-phish-capture image
//    (built by eval/phish/run.mjs, or: docker build -t sso-phish-capture eval/phish).
// 2. Checks the domain logic used for lookups: user sites on shared hosting
//    (pages.dev, github.io, ...) must not be treated as the platform itself.
import {spawnSync} from "node:child_process";
import {readFileSync} from "node:fs";

const root = new URL("../../", import.meta.url).pathname;

console.log("Page scanning (lab sites in a sandboxed browser):");
const docker = spawnSync("docker", ["run", "--rm", "--init", "--network=none", "--cap-drop=ALL",
  "--security-opt=no-new-privileges", "--memory=2g",
  "-e", "ONLY=" + (process.env.ONLY || ""), "-e", "VERBOSE=" + (process.env.VERBOSE || ""),
  "-v", root + "test-site:/site:ro", "-v", root + "extension:/ext:ro",
  "-v", root + "eval/lab-check/check.mjs:/t/check.mjs:ro",
  "--entrypoint", "node", "sso-phish-capture", "/t/check.mjs"], {stdio: "inherit"});

console.log("\nDomain used for age lookups:");
globalThis.browser = {storage: {local: {get: async () => ({}), set: async () => {}}, onChanged: {addListener() {}}}, runtime: {}};
const files = ["psl.js", "models.js", "investigate.js"].map(f => {
  try { return readFileSync(root + "extension/" + f, "utf8"); } catch { return ""; }
});
const ext = new Function("const scriptHashes = new Map();\n" + files.join("\n") + "; return {registrableDomain};")();
const domainCases = [
  ["www.paypal.com", "paypal.com"], ["login.examplebank.co.uk", "examplebank.co.uk"],
  ["secure-login.pages.dev", "secure-login.pages.dev"], ["account-verify.github.io", "account-verify.github.io"],
  ["paypal-help.web.app", "paypal-help.web.app"], ["bank.vercel.app", "bank.vercel.app"],
  ["shop.example.com.au", "example.com.au"]
];
let domainFailures = 0;
for (const [host, expected] of domainCases) {
  const got = ext.registrableDomain(host);
  if (got !== expected) domainFailures++;
  console.log(`${got === expected ? "  PASS" : "  FAIL"}  ${host.padEnd(28)} -> ${got.padEnd(26)} (expected ${expected})`);
}
process.exit(docker.status || domainFailures ? 1 : 0);
