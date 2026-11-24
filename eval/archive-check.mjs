// Checks the extension's zip reading (extension/archive.js) with the extension's
// own signature check: test zips are built here, in memory.
//   node eval/archive-check.mjs            (add --online to also fetch eicar.org's files)
// The EICAR test string is kept base64-encoded so this repository never contains it.
import {readFileSync} from "node:fs";

const ext = new URL("../extension/", import.meta.url).pathname;
const background = readFileSync(ext + "background.js", "utf8");
const pick = name => background.match(new RegExp("(async )?function " + name + "\\([\\s\\S]*?\\n}\\n"))[0];
const {zipContents, isZip, matchSignature} = new Function(
  readFileSync(ext + "signatures.js", "utf8") + readFileSync(ext + "archive.js", "utf8") +
  ["sha256Hex", "onlyWhitespace", "matchSignature"].map(pick).join("\n") +
  "; return {zipContents, isZip, matchSignature};")();

const eicar = Buffer.from("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=", "base64");
const deflate = async bytes => new Uint8Array(await new Response(
  new Blob([bytes]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());

// A minimal zip writer (CRC left at 0: the extension doesn't check it).
async function zip(files) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name), data = f.store ? Buffer.from(f.data) : Buffer.from(await deflate(f.data));
    const size = f.claimSize ?? f.data.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(f.encrypted ? 1 : 0, 6);
    local.writeUInt16LE(f.store ? 0 : 8, 8); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(f.encrypted ? 1 : 0, 8); central.writeUInt16LE(f.store ? 0 : 8, 10);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(size, 24); central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += 30 + name.length + data.length;
  }
  const directory = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...locals, directory, end]));
}

const nest = async (levels, inner) => {
  let bytes = inner;
  for (let i = levels; i >= 1; i--) bytes = await zip([{name: "level" + i + ".zip", data: bytes}]);
  return bytes;
};
const eicarZip = await zip([{name: "eicar.com", data: eicar}]);

const cases = [
  {name: "Raw EICAR file", bytes: eicar, raw: true, ok: r => r.match === "EICAR-Test-File"},
  {name: "EICAR in a zip (stored)", bytes: await zip([{name: "eicar.com", data: eicar, store: true}]), ok: r => !!r.archive.signatureMatch},
  {name: "EICAR in a zip (compressed)", bytes: eicarZip, ok: r => !!r.archive.signatureMatch},
  {name: "EICAR in a zip in a zip (like eicar_com2.zip)", bytes: await zip([{name: "eicar_com.zip", data: eicarZip}]),
   ok: r => /eicar_com\.zip\/eicar\.com/.test(r.archive.signatureMatch || "")},
  {name: "Nested 3 deep: still found", bytes: await nest(2, eicarZip), ok: r => !!r.archive.signatureMatch},
  {name: "Nested 4 deep: reported as not scanned", bytes: await nest(3, eicarZip),
   ok: r => !r.archive.signatureMatch && r.archive.entries.some(e => e.notScanned)},
  {name: "Password-protected archive", bytes: await zip([{name: "scan.pdf", data: Buffer.from("x".repeat(50)), encrypted: true}]),
   ok: r => r.archive.entries[0].passwordProtected === true},
  {name: "Invoice zip hiding a script", bytes: await zip([{name: "Invoice_2291.pdf.js", data: Buffer.from("console.log('inert test')")}]),
   ok: r => r.archive.entries[0].path === "Invoice_2291.pdf.js" && /console\.log/.test(r.archive.entries[0].text || "") && !r.archive.signatureMatch},
  {name: "Entry claiming a huge size is not unpacked", bytes: await zip([{name: "big.bin", data: Buffer.from("small"), claimSize: 4e9}]),
   ok: r => r.archive.entries[0].notScanned === true},
  {name: "Ordinary zip: no match", bytes: await zip([{name: "photos/a.jpg", data: Buffer.from("jpeg data")}, {name: "notes.txt", data: Buffer.from("hello")}]),
   ok: r => r.archive.fileCount === 2 && !r.archive.signatureMatch}
];

// Hostile archives: none may crash, hang, or blow up memory; each is reported.
const bombData = new Uint8Array(30 * 1024 * 1024); // 30 MB of zeros, compresses to ~30 KB
const garbage = new Uint8Array(4096).map((_, i) => (i * 7919) % 256);
garbage.set([0x50, 0x4b, 0x03, 0x04]);
const truncated = (await zip([{name: "a.txt", data: Buffer.from("hello world")}])).slice(0, 40);
cases.push(
  {name: "Zip bomb: small claimed size, 30 MB inside", bytes: await zip([{name: "readme.txt", data: bombData, claimSize: 100}]),
   ok: r => r.archive.entries[0].notScanned === true},
  {name: "Zip bomb: honest 30 MB entry x3 (over the budget)", bytes: await zip([1, 2, 3].map(i => ({name: "f" + i + ".bin", data: bombData}))),
   ok: r => r.archive.entries.some(e => e.notScanned)},
  {name: "Garbage after a zip header", bytes: garbage, ok: r => r.archive.notes?.some(n => /not a readable zip/.test(n))},
  {name: "Truncated zip", bytes: truncated, ok: r => !!r.archive}
);
// Names that disagree: the directory says report.pdf, the file header says report.exe.
const twoFaced = await zip([{name: "report.pdf", data: Buffer.from("MZ inert test")}]);
twoFaced.set(Buffer.from("report.exe"), 30);
cases.push({name: "Crafted zip: directory and file names disagree", bytes: twoFaced,
            ok: r => r.archive.entries[0].mismatched === true && r.archive.notes?.some(n => /disagree/.test(n))});

if (process.argv.includes("--online")) {
  for (const file of ["eicar.com", "eicar.com.txt", "eicar_com.zip", "eicar_com2.zip"]) {
    try {
      const response = await fetch("https://secure.eicar.org/" + file);
      const bytes = new Uint8Array(await response.arrayBuffer());
      cases.push({name: "eicar.org " + file, bytes, raw: !isZip(bytes), ok: r => !!(r.match || r.archive?.signatureMatch)});
    } catch (error) {
      console.log("  (could not fetch " + file + ": " + error.message + ")");
    }
  }
}

let failures = 0;
for (const c of cases) {
  const r = {match: await matchSignature(c.bytes), archive: c.raw ? null : await zipContents(c.bytes, matchSignature)};
  const ok = !!c.ok(r);
  if (!ok) failures++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${c.name.padEnd(48)} ${JSON.stringify(r.archive ?? {signature: r.match}).slice(0, 150)}`);
}
console.log(`\n${cases.length - failures} of ${cases.length} passed`);
process.exit(failures ? 1 : 0);
