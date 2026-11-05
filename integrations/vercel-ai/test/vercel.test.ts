import { test } from "node:test";
import assert from "node:assert/strict";
import { generateText, tool, jsonSchema } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { Gate, generate, KeySet, makeConsent } from "../../../sdk/typescript/src/index.ts";
import { approvalMessage, NOT_APPROVED, previewFor, withOAC } from "../src/index.ts";

const EX = "https://app.example/oac", SIGNER = "https://signer.example", PERSON = "person:1";
const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const ARGS = { to: ["sam@example.com"], subject: "Lunch?", body: "Friday 1 pm?" };

function world(args: Record<string, unknown> = ARGS) {
  const key = generate();
  const gate = new Gate({ executor: EX, key: generate(), signers: new KeySet({ [SIGNER]: [key.jwk] }) });
  const sent: unknown[] = [];
  const send = tool({ description: "Send an email", inputSchema: jsonSchema({ type: "object", properties: { to: { type: "array", items: { type: "string" } }, subject: { type: "string" }, body: { type: "string" } }, required: ["to", "subject"] }),
    execute: async (input: any) => { sent.push(input); return "sent"; } });
  const { tools, toolApproval } = withOAC(gate, { send_email: send }, { send_email: { effect: "send", binds: { to: "to", title: "subject" }, otherArgs: ["body"] } }, { person: PERSON });
  const model = new MockLanguageModelV4({ doGenerate: [
    { content: [{ type: "tool-call", toolCallId: "c1", toolName: "send_email", input: JSON.stringify(args) }], finishReason: { unified: "tool-calls", raw: undefined }, usage, warnings: [] },
    { content: [{ type: "text", text: "done" }], finishReason: { unified: "stop", raw: undefined }, usage, warnings: [] },
  ] as any });
  return { gate, key, tools, toolApproval, model, sent };
}

async function firstRound(w: ReturnType<typeof world>) {
  const prompt = [{ role: "user" as const, content: "email Sam" }];
  const r1: any = await generateText({ model: w.model, tools: w.tools, toolApproval: w.toolApproval, messages: prompt });
  const req = r1.content.find((p: any) => p.type === "tool-approval-request");
  return { prompt, r1, req };
}

test("tier C pauses with the preview, then runs only with a signed consent", async () => {
  const w = world();
  const { prompt, r1, req } = await firstRound(w);
  assert.ok(req, "an approval request");
  assert.deepEqual(w.sent, []);
  const p = previewFor(w.gate, req, PERSON);
  assert.deepEqual(p.fields, { to: ["sam@example.com"], title: "Lunch?" });
  const token = makeConsent({ key: w.key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1 });
  await generateText({ model: w.model, tools: w.tools, toolApproval: w.toolApproval,
    messages: [...prompt, ...r1.response.messages, approvalMessage(w.gate, req.approvalId, token)] });
  assert.equal(w.sent.length, 1);
  assert.equal(w.gate.receipts.get(PERSON)!.length, 1);
});

test("an approval without a valid signed consent runs nothing", async () => {
  const w = world();
  const { prompt, r1, req } = await firstRound(w);
  const forged = makeConsent({ key: generate(), iss: SIGNER, sub: PERSON, aud: EX, previews: [previewFor(w.gate, req, PERSON)], now: Math.floor(Date.now() / 1000) });
  const msg = approvalMessage(w.gate, req.approvalId, forged);
  assert.equal(msg.content[0].approved, false);
  const bypass = { ...msg, content: [{ ...msg.content[0], approved: true }] }; // a client that flips the flag itself
  const r2: any = await generateText({ model: w.model, tools: w.tools, toolApproval: w.toolApproval, messages: [...prompt, ...r1.response.messages, bypass] });
  assert.deepEqual(w.sent, []);
  const out = JSON.stringify(r2.response.messages);
  assert.ok(out.includes(NOT_APPROVED.slice(0, 20)) || !out.includes('"sent"'));
});
