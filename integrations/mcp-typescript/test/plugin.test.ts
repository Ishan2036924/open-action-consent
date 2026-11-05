import { test } from "node:test";
import assert from "node:assert/strict";
import * as z from "zod";
import { McpServer, InMemoryTransport } from "@modelcontextprotocol/server";
import { Client } from "@modelcontextprotocol/client";
import { generate, KeySet, makeConsent, verify, verifyChain } from "@open-action-consent/sdk";
import { ID, OAC, PREVIEW_KEY, RECEIPT_KEY } from "../src/index.ts";

const EXECUTOR = "https://tables.example/oac", SIGNER = "https://signer.example", PERSON = "person:1";

async function setup(opts: { approve?: boolean; tainted?: boolean; speaksOAC?: boolean } = {}) {
  const personKey = generate();
  const oac = new OAC({ executor: EXECUTOR, key: generate(), signers: new KeySet({ [SIGNER]: [personKey.jwk] }),
    consentUrl: (p) => `https://signer.example/consent?r=${p.id}`, person: () => PERSON, tainted: () => opts.tainted ?? false });
  const server = new McpServer({ name: "tables", version: "0.1.0" }, { capabilities: { tools: {}, extensions: { [ID]: oac.settings() } } as any });
  const log: string[] = [];
  oac.registerTool(server, "book_table", { description: "Book a table", inputSchema: z.object({ restaurant: z.string(), time: z.string(), party: z.number() }) },
    { effect: "write", undo: "compensate", windowS: 86400, binds: { payee: "restaurant", when: "time", count: "party" } },
    async ({ restaurant, party }) => { log.push(`booked ${restaurant} ${party}`); return { content: [{ type: "text", text: "Booked." }] }; });
  oac.registerTool(server, "add_task", { description: "Add a task", inputSchema: z.object({ title: z.string() }) },
    { effect: "write", undo: "native", windowS: 600, binds: { title: "title" } },
    async ({ title }) => { log.push(`task ${title}`); return { content: [{ type: "text", text: "Added." }] }; });
  const caps: any = opts.speaksOAC === false ? {} : { elicitation: { url: {} }, extensions: { [ID]: {} } };
  const client = new Client({ name: "test", version: "0.1.0" }, { capabilities: caps });
  const seen: any[] = [];
  if (opts.speaksOAC !== false) client.setRequestHandler("elicitation/create", async (req: any) => {
    const preview = oac.preview(String(req.params.url).split("=").pop()!);
    seen.push(preview);
    if (opts.approve !== false) oac.acceptConsent(makeConsent({ key: personKey, iss: SIGNER, sub: PERSON, aud: EXECUTOR, previews: [preview!], now: preview!.iat + 1 }));
    return { action: opts.approve === false ? "decline" : "accept" } as any;
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  await client.connect(ct);
  return { oac, client, log, seen, personKey };
}

test("tier C asks, then runs with a signed receipt", async () => {
  const { oac, client, log, seen } = await setup();
  const tools = (await client.listTools()).tools;
  assert.equal((tools.find((t: any) => t.name === "book_table") as any)._meta[`${ID}-profile`].effect, "write");
  const r: any = await client.callTool({ name: "book_table", arguments: { restaurant: "Nobu", time: "Fri 7:30 pm", party: 2 } });
  assert.equal(r.isError ?? false, false);
  assert.deepEqual(log, ["booked Nobu 2"]);
  assert.deepEqual(seen[0].fields, { payee: "Nobu", when: "Fri 7:30 pm", count: 2 });
  assert.equal(verify(r._meta[RECEIPT_KEY], new KeySet({ [EXECUTOR]: [oac.o.key.jwk] }), "oac-receipt+jws").authority.kind, "consent");
});

test("declined: nothing runs", async () => {
  const { client, log } = await setup({ approve: false });
  const r: any = await client.callTool({ name: "book_table", arguments: { restaurant: "Nobu", time: "Fri", party: 2 } });
  assert.equal(r.isError, true);
  assert.deepEqual(log, []);
});

test("tier B runs at once with an undo token; receipts chain", async () => {
  const { oac, client, log } = await setup();
  const r1: any = await client.callTool({ name: "add_task", arguments: { title: "Call the dentist" } });
  const r2: any = await client.callTool({ name: "add_task", arguments: { title: "Buy milk" } });
  assert.deepEqual(log, ["task Call the dentist", "task Buy milk"]);
  const chain = verifyChain([r1._meta[RECEIPT_KEY], r2._meta[RECEIPT_KEY]], { keys: new KeySet({ [EXECUTOR]: [oac.o.key.jwk] }), executor: EXECUTOR });
  assert.equal(chain[0].undo.kind, "native");
});

test("tainted run asks even for tier B; declined = nothing", async () => {
  const { client, log } = await setup({ tainted: true, approve: false });
  const r: any = await client.callTool({ name: "add_task", arguments: { title: "Wire $500" } });
  assert.equal(r.isError, true);
  assert.deepEqual(log, []);
});

test("undeclared argument never runs", async () => {
  const { oac, log } = await setup();
  const r: any = await oac.guard("add_task", { title: "x", bcc: "boss@evil.test" }, {}, async () => { log.push("ran"); return { content: [] }; });
  assert.equal(r.isError, true);
  assert.deepEqual(log, []);
});

test("a retry with changed arguments is refused", async () => {
  const { oac, personKey, log } = await setup();
  const first: any = await oac.guard("book_table", { restaurant: "Nobu", time: "Fri", party: 2 }, {}, async () => ({ content: [] }));
  const preview = first._meta[PREVIEW_KEY];
  oac.acceptConsent(makeConsent({ key: personKey, iss: SIGNER, sub: PERSON, aud: EXECUTOR, previews: [preview], now: preview.iat + 1 }));
  const ctx = { mcpReq: { requestState: () => first.requestState, inputResponses: { oac_consent: { action: "accept" } } } };
  const r: any = await oac.guard("book_table", { restaurant: "Nobu", time: "Fri", party: 20 }, ctx, async () => { log.push("ran"); return { content: [] }; });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /action_mismatch/);
  assert.deepEqual(log, []);
});

test("forged request state is refused (falls back to asking)", async () => {
  const { oac, log } = await setup();
  const ctx = { mcpReq: { requestState: () => "e30.forged", inputResponses: { oac_consent: { action: "accept" } } } };
  const r: any = await oac.guard("book_table", { restaurant: "Nobu", time: "Fri", party: 2 }, ctx, async () => { log.push("ran"); return { content: [] }; });
  assert.equal(r.resultType, "input_required");
  assert.deepEqual(log, []);
});

test("a client without the extension is refused (-32021) and nothing runs", async () => {
  const { client, log } = await setup({ speaksOAC: false });
  const r: any = await client.callTool({ name: "book_table", arguments: { restaurant: "Nobu", time: "Fri", party: 2 } });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /-32021/);
  assert.deepEqual(log, []);
});
