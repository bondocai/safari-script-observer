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

init();
