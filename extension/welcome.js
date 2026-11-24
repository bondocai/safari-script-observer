// First-run setup page (opened by background.js on install, and from the popup
// while setup is unfinished): website access and the model server, checked live.
const allSites = {origins: ["http://*/*", "https://*/*"]};
const $ = id => document.getElementById(id);
const state = {access: false, model: false};

function mark(step, done) {
  $(step).classList.toggle("done", done);
  $(step).classList.toggle("todo", !done);
  $("final").classList.toggle("show", state.access && state.model);
}

async function checkAccess() {
  try {
    state.access = await browser.permissions.contains(allSites);
  } catch {
    state.access = false;
  }
  $("access-status").textContent = state.access ? "Allowed on every website." : "Not yet allowed on every website.";
  $("grant").hidden = state.access;
  $("access-help").hidden = state.access;
  mark("step-access", state.access);
}

$("grant").onclick = async () => {
  try {
    await browser.permissions.request(allSites);
  } catch {}
  await checkAccess();
  // Safari may not show its prompt from here; then the setting is the way.
  if (!state.access) $("access-fallback").hidden = false;
};

async function describeModel() {
  const {settings} = await browser.storage.local.get("settings");
  const llm = settings?.llm;
  if (!llm || llm.kind === "none") return null;
  return llm.kind === "ollama" ? llm.ollamaModel + " on " + llm.ollamaUrl : llm.customModel + " on " + llm.customUrl;
}

async function testModel() {
  const described = await describeModel();
  if (!described) {
    state.model = false;
    $("model-status").textContent = "No model server set.";
    $("model-detail").textContent = "Open settings and choose Local Ollama or your own server (LM Studio, llama.cpp, vLLM).";
    return mark("step-model", false);
  }
  $("model-status").textContent = "Testing " + described + "…";
  const results = await browser.runtime.sendMessage({type: "test"}).catch(error => ({server: {error: error.message}}));
  const result = results?.server;
  state.model = !!result && !result.error;
  $("model-status").textContent = state.model ? "Connected." : "Not working yet.";
  $("model-detail").textContent = state.model
    ? described + " answered in " + (result.source || "").split("·").pop().trim() + "."
    : (result?.error || "No answer from the model server.");
  mark("step-model", state.model);
}

$("test").onclick = testModel;
$("settings").onclick = () => browser.runtime.openOptionsPage();
browser.permissions.onAdded?.addListener(checkAccess);
browser.permissions.onRemoved?.addListener(checkAccess);
// Coming back from Safari's settings or the options page: check again.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { checkAccess(); if (!state.model) testModel(); }
});

checkAccess();
testModel();
