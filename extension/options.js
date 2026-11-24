const $ = id => document.getElementById(id);

function show(kind) {
  for (const block of document.querySelectorAll("[data-kind]")) block.hidden = block.dataset.kind !== kind;
}

function readForm() {
  return {
    screenshots: $("screenshots").checked,
    investigate: $("investigate").checked,
    coverMode: document.querySelector("input[name=coverMode]:checked")?.value || "moments",
    skipSites: $("skipSites").value.split(/[\s,]+/)
      .map(entry => entry.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/:].*$/, "").replace(/^\*\./, ""))
      .filter(Boolean),
    llm: {
      kind: document.querySelector("input[name=kind]:checked")?.value || "none",
      ollamaUrl: $("ollamaUrl").value.trim() || defaultSettings.llm.ollamaUrl,
      ollamaModel: $("ollamaModel").value,
      customUrl: $("customUrl").value.trim(),
      customModel: $("customModel").value.trim(),
      apiKey: $("apiKey").value
    }
  };
}

function setOllamaModels(models, selected) {
  const select = $("ollamaModel");
  select.replaceChildren(...[...new Set([selected, ...models].filter(Boolean))].map(name => new Option(name, name)));
  select.value = selected || models[0] || "";
}

async function init() {
  const s = await loadSettings();
  document.querySelector(`input[name=kind][value="${s.llm.kind}"]`).checked = true;
  $("screenshots").checked = s.screenshots;
  $("investigate").checked = s.investigate !== false;
  document.querySelector(`input[name=coverMode][value="${s.coverMode === "all" ? "all" : "moments"}"]`).checked = true;
  $("skipSites").value = (s.skipSites || []).join("\n");
  $("ollamaUrl").value = s.llm.ollamaUrl;
  setOllamaModels([], s.llm.ollamaModel);
  $("customUrl").value = s.llm.customUrl;
  $("customModel").value = s.llm.customModel;
  $("apiKey").value = s.llm.apiKey;
  show(s.llm.kind);
}

for (const radio of document.querySelectorAll("input[name=kind]")) radio.onchange = () => show(radio.value);

for (const button of document.querySelectorAll("[data-load]")) {
  button.onclick = async () => {
    const llm = {...readForm().llm, kind: button.dataset.load};
    $("loadStatus").textContent = "Loading models\u2026";
    const reply = await browser.runtime.sendMessage({type: "list-models", llm});
    if (reply?.error) {
      $("loadStatus").textContent = "Could not load models: " + reply.error;
      $("loadStatus").className = "hint bad";
      return;
    }
    $("loadStatus").textContent = reply.models.length + " models found.";
    $("loadStatus").className = "hint ok";
    if (llm.kind === "ollama") setOllamaModels(reply.models, $("ollamaModel").value);
    else $("customModels").replaceChildren(...reply.models.map(id => new Option(id)));
  };
}

$("save").onclick = async () => {
  await browser.storage.local.set({settings: readForm()});
  $("saved").textContent = "Saved.";
  setTimeout(() => ($("saved").textContent = ""), 2000);
};

$("test").onclick = async () => {
  await $("save").onclick();
  $("testResult").textContent = "Testing\u2026";
  const results = await browser.runtime.sendMessage({type: "test"});
  const lines = [];
  for (const [name, r] of Object.entries(results || {})) {
    const label = "Model server";
    lines.push(label + ": " + (r.error ? "failed \u2014 " + r.error : "working, answered \"" + r.verdict + "\" (" + r.source + ")"));
  }
  $("testResult").textContent = lines.join("\n") || "No model server is set; only local rules will be used.";
  $("testResult").style.whiteSpace = "pre-line";
};

$("forget").onclick = async () => {
  await browser.runtime.sendMessage({type: "forget"});
  $("forgotten").textContent = "Forgotten. Every page will be checked again.";
};

// ---- Stats ---------------------------------------------------------------------------

const statSeconds = ms => ms === null ? "–" : (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + " s";
const timingLine = (label, t) => t.count
  ? `${label}: median ${statSeconds(t.median)}, 95% within ${statSeconds(t.p95)} (${t.count})` : `${label}: none yet`;
const tally = counts => Object.entries(counts).map(([k, n]) => `${n} ${k}`).join(", ") || "none";
const when = at => new Date(at).toLocaleString([], {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"});

function statsText(summary) {
  const lines = [
    summary.since ? `Since ${new Date(summary.since).toLocaleDateString()}` : "Nothing recorded yet.",
    `Pages checked: ${summary.pages.count} (${tally(summary.pages.outcomes)}; ${summary.pages.remembered} from memory). Frames: ${summary.frames.count}.`,
    "",
    "Time your model took:",
    "  " + timingLine("Pages", summary.modelTime.pages),
    "  " + timingLine("Held actions", summary.modelTime.actions),
    "  " + timingLine("Frames", summary.modelTime.frames),
    "",
    "Held actions (from the moment you acted to the decision):"
  ];
  const kinds = Object.entries(summary.actions);
  if (!kinds.length) lines.push("  none yet");
  for (const [kind, t] of kinds) lines.push(`  ${timingLine(kind, t)}: ${tally(t.outcomes)}`);
  lines.push("", timingLine("Waited to type in a password or card field", summary.typingWaits),
    `Checks that failed: ${tally(summary.failures)}`,
    `You went ahead anyway: ${summary.overrides.length} times. Flagged or blocked: ${summary.flagged.length}.`);
  return lines.join("\n");
}

function listEvents(element, events, describe) {
  element.replaceChildren(...events.slice(-50).reverse().map(e => {
    const row = document.createElement("div");
    row.textContent = `${when(e.at)} · ${e.host || "?"} · ${describe(e)}`;
    return row;
  }));
  if (!events.length) element.textContent = "None.";
}

async function showStats() {
  const {stats} = await browser.storage.local.get("stats");
  const summary = summarizeStats(stats);
  $("stats").textContent = statsText(summary);
  listEvents($("overrides"), summary.overrides, e => e.detail);
  listEvents($("flagged"), summary.flagged, e => [e.event, e.outcome, e.detail].filter(Boolean).join(", "));
  return summary;
}

$("copyStats").onclick = async () => {
  const summary = await showStats();
  await navigator.clipboard.writeText("Safari Script Observer stats\n" + statsText(summary));
  $("statsNote").textContent = "Copied.";
};

$("clearStats").onclick = async () => {
  await browser.storage.local.remove("stats");
  await showStats();
  $("statsNote").textContent = "Cleared.";
};

init();
showStats();
