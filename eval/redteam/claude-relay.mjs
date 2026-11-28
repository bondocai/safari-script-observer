// Claude as a lab baseline for the red-team run (never used by the extension).
//
// A local relay: the harness keeps speaking the OpenAI-style chat API it uses for
// your own model server, and this relay answers it by calling Claude through
// Anthropic's SDK. The extension code under test is unchanged.
//
//   ANTHROPIC_API_KEY=$(tr -d '\n' < ~/.config/safe-browser/anthropic-key) node eval/redteam/claude-relay.mjs
//   MODEL_URL=http://127.0.0.1:8788/v1 MODEL=claude-sonnet-5-5 node eval/redteam/run.mjs
//
// Only the synthetic test pages go to Anthropic, never real browsing. Thinking is
// turned off where the model allows it, to match how the extension runs local
// models (reasoning_effort "none"), and the JSON answer is enforced with
// structured outputs, as the json_schema response format does for local servers.
// Token use and an estimated cost are printed as it goes.

import http from "node:http";
import Anthropic from "@anthropic-ai/sdk";

const port = Number(process.env.CLAUDE_RELAY_PORT || 8788);
const client = new Anthropic({maxRetries: 4});

// $ per million tokens (input, output), from the published price list, 2026-11.
const prices = {"claude-sonnet-5-5": [2, 10], "claude-haiku-5-5": [0.1, 0.5], "claude-opus-5-5": [4, 20]};
const totals = {calls: 0, input: 0, output: 0, refusals: 0, errors: 0, dollars: 0};

// Per-model settings: thinking off where possible (Opus 5.5 can't turn it off,
// so it runs at low effort with room for its thinking).
function modelSettings(model, requestedMax) {
  if (model === "claude-sonnet-5-5") return {thinking: {type: "between_tools"}, max_tokens: Math.max(requestedMax, 512)};
  if (model === "claude-haiku-5-5") return {thinking: {type: "disabled"}, output_config: {effort: "high"}, max_tokens: Math.max(requestedMax, 512)};
  if (model === "claude-opus-5-5") return {output_config: {effort: "low"}, max_tokens: Math.max(requestedMax, 4000)};
  throw Object.assign(new Error("This relay is set up for claude-sonnet-5-5, claude-haiku-5-5 and claude-opus-5-5."), {status: 404});
}

function toClaudeContent(content) {
  if (typeof content === "string") return content;
  const blocks = [];
  for (const part of content || []) {
    if (part.type === "text") blocks.push({type: "text", text: part.text});
    if (part.type === "image_url") {
      const match = /^data:(image\/[a-z+]+);base64,(.*)$/s.exec(part.image_url?.url || "");
      if (match) blocks.unshift({type: "image", source: {type: "base64", media_type: match[1], data: match[2]}});
    }
  }
  return blocks;
}

async function complete(body) {
  const system = body.messages.filter(m => m.role === "system").map(m => m.content).join("\n\n");
  const messages = body.messages.filter(m => m.role !== "system")
    .map(m => ({role: m.role, content: toClaudeContent(m.content)}));
  const settings = modelSettings(body.model, body.max_tokens || 512);
  // Structured outputs don't take array length limits; the extension trims the
  // explanation's reasons to 3 itself.
  const schema = body.response_format?.json_schema?.schema &&
    JSON.parse(JSON.stringify(body.response_format.json_schema.schema), (key, value) =>
      key === "maxItems" || key === "minItems" ? undefined : value);
  const request = {
    model: body.model, system, messages, ...settings,
    output_config: {...settings.output_config, ...(schema ? {format: {type: "json_schema", schema}} : {})}
  };
  const response = await client.messages.create(request);

  totals.calls++;
  totals.input += response.usage.input_tokens;
  totals.output += response.usage.output_tokens;
  const [inPrice, outPrice] = prices[body.model];
  totals.dollars += (response.usage.input_tokens * inPrice + response.usage.output_tokens * outPrice) / 1e6;
  if (response.stop_reason === "refusal") {
    totals.refusals++;
    console.log("refusal:", response.stop_details?.category ?? "no category");
  }
  if (totals.calls % 10 === 0) report();

  const text = response.content.filter(b => b.type === "text").map(b => b.text).join("");
  const finish = {end_turn: "stop", max_tokens: "length", refusal: "content_filter"}[response.stop_reason] || "stop";
  return {
    id: response.id, object: "chat.completion", model: body.model,
    choices: [{index: 0, message: {role: "assistant", content: text}, finish_reason: finish}],
    usage: {prompt_tokens: response.usage.input_tokens, completion_tokens: response.usage.output_tokens}
  };
}

function report() {
  console.log(`${totals.calls} calls · ${totals.input} in / ${totals.output} out tokens · ` +
    `~$${totals.dollars.toFixed(3)} · ${totals.refusals} refusals · ${totals.errors} errors`);
}

const send = (res, status, data) => {
  res.writeHead(status, {"Content-Type": "application/json"});
  res.end(JSON.stringify(data));
};

http.createServer(async (req, res) => {
  if (req.method === "GET" && /\/v1\/models\/?$/.test(req.url)) {
    return send(res, 200, {object: "list", data: Object.keys(prices).map(id => ({id, object: "model"}))});
  }
  if (req.method !== "POST" || !/\/v1\/chat\/completions\/?$/.test(req.url)) return send(res, 404, {error: {message: "not found"}});
  let raw = "";
  for await (const chunk of req) raw += chunk;
  try {
    send(res, 200, await complete(JSON.parse(raw)));
  } catch (error) {
    totals.errors++;
    const status = error instanceof Anthropic.APIError ? (error.status || 502) : (error.status || 500);
    console.log("error", status + ":", String(error.message).slice(0, 300));
    send(res, status, {error: {message: String(error.message)}});
  }
}).listen(port, "127.0.0.1", () => console.log(`Claude relay on http://127.0.0.1:${port}/v1`));

process.on("SIGINT", () => { report(); process.exit(0); });
