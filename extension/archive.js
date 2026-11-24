// What is inside a zip file being downloaded: every file's path, size and whether
// it is password-protected, with known-bad signatures checked inside (including
// zips inside zips, up to three levels). Lets the model see that "invoice.zip"
// holds "invoice.pdf.js", and lets a signature match inside an archive block it.
// Only reads; nothing is written or run.

// Limits against hostile archives (zip bombs, endless nesting, slow unpacking):
// anything past them is listed as notScanned, never silently skipped.
const archiveLimits = {depth: 3, entries: 200, listed: 30, totalBytes: 50 * 1024 * 1024, seconds: 5};

// The start of a script, web page or other text file, for the model to read:
// by file type, or by content (a "PDF" that is really HTML or a shell script).
// Long numbers are masked, as elsewhere.
const scriptTypes = /\.(js|jse|mjs|cjs|vbs|vbe|wsf|wsh|ps1|psm1|bat|cmd|sh|bash|zsh|command|tool|applescript|py|rb|pl|hta|html?|xhtml|svg|xml|url|desktop|reg|inf|lnk)$/i;
function readableText(name, bytes, max) {
  const text = new TextDecoder("utf-8").decode(bytes.subarray(0, max * 2));
  const looksLikeCode = /^\s*(<!doctype|<html|<svg|<script|<\?xml|#!|@echo|function |var |const |import |\$[a-z_]+ *=)/i.test(text);
  if (!scriptTypes.test(name) && !looksLikeCode) return null;
  const printable = text.replace(/[^\t\n\r\x20-\x7e\u00a0-\uffff]/g, "").length / Math.max(1, text.length);
  if (printable < 0.9) return null;
  return text.replace(/\d{4,}/g, "####").slice(0, max);
}

function isZip(bytes) {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

// Inflate raw deflate data, giving up past `limit` bytes (zip bombs).
async function inflateRaw(data, limit) {
  const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) {
        await reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

// `match(bytes)` returns a signature name or null.
async function zipContents(bytes, match) {
  const result = {entries: [], fileCount: 0, notes: [], signatureMatch: null};
  const budget = {bytes: archiveLimits.totalBytes, entries: archiveLimits.entries, texts: 5,
                  deadline: Date.now() + archiveLimits.seconds * 1000};
  await readZip(bytes, "", 1, match, result, budget);
  result.entries = result.entries.slice(0, archiveLimits.listed);
  if (result.fileCount > archiveLimits.listed) result.notes.push(result.fileCount + " files; first " + archiveLimits.listed + " listed");
  if (!result.notes.length) delete result.notes;
  if (!result.signatureMatch) delete result.signatureMatch;
  return result;
}

async function readZip(bytes, prefix, depth, match, result, budget) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = at => view.getUint16(at, true), u32 = at => view.getUint32(at, true);
  // End of central directory: the last 22+ bytes (a comment may follow it).
  let end = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 65557); at--) {
    if (u32(at) === 0x06054b50) { end = at; break; }
  }
  if (end < 0) { result.notes.push((prefix || "archive") + ": not a readable zip"); return; }
  const count = u16(end + 10);
  let at = u32(end + 16);
  const decoder = new TextDecoder();
  for (let i = 0; i < count && at + 46 <= bytes.length && u32(at) === 0x02014b50; i++) {
    const flags = u16(at + 8), method = u16(at + 10), compressed = u32(at + 20), size = u32(at + 24);
    const nameLength = u16(at + 28), extraLength = u16(at + 30), commentLength = u16(at + 32), local = u32(at + 42);
    const name = decoder.decode(bytes.subarray(at + 46, at + 46 + nameLength));
    at += 46 + nameLength + extraLength + commentLength;
    if (name.endsWith("/")) continue; // a folder
    const path = prefix + name;
    result.fileCount++;
    const entry = {path: path.slice(0, 160), size};
    result.entries.push(entry);
    if (flags & 1) { entry.passwordProtected = true; continue; }
    if (--budget.entries < 0 || size > budget.bytes || Date.now() > budget.deadline ||
        local + 30 > bytes.length || u32(local) !== 0x04034b50) {
      entry.notScanned = true;
      continue;
    }
    // The name before the file must match the directory's: a zip where they differ
    // shows a scanner one file and the program that unpacks it another.
    const localName = decoder.decode(bytes.subarray(local + 30, local + 30 + u16(local + 26)));
    if (localName !== name) {
      entry.mismatched = true;
      result.notes.push("names in the archive disagree (" + path.slice(0, 60) + "): a sign of a crafted archive");
    }
    const start = local + 30 + u16(local + 26) + u16(local + 28);
    const raw = bytes.subarray(start, start + compressed);
    const data = method === 0 ? raw : method === 8 ? await inflateRaw(raw, Math.min(size, budget.bytes)) : null;
    if (!data) { entry.notScanned = true; continue; }
    budget.bytes -= data.length;
    const text = budget.texts > 0 ? readableText(name, data, 1200) : null;
    if (text) { entry.text = text; budget.texts--; }
    const signature = await match(data);
    if (signature) {
      entry.signatureMatch = signature;
      result.signatureMatch ??= signature + " (inside the archive: " + entry.path + ")";
    }
    if (isZip(data)) {
      if (depth < archiveLimits.depth) await readZip(data, path + "/", depth + 1, match, result, budget);
      else entry.notScanned = true;
    }
  }
}
