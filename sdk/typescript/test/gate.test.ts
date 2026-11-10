import { test } from "node:test";
import assert from "node:assert/strict";
import { Gate, generate, KeySet, makeConsent, NeedsConsent, OACError, tokenDigest, verifyChain, type DeviceCheck } from "../src/index.ts";
import { passkeyProof } from "../src/testing.ts";

const EX = "https://app.example/oac", SIGNER = "https://signer.example", PERSON = "person:1";

test("gate: B runs, C needs a consent once, same pending preview, D and undeclared refused", async () => {
  const key = generate();
  const gate = new Gate({ executor: EX, key: generate(), signers: new KeySet({ [SIGNER]: [key.jwk] }) });
  gate.profile("send_email", { effect: "send", binds: { to: "to", title: "subject" }, otherArgs: ["body"] });
  gate.profile("add_task", { effect: "write", undo: "native", windowS: 600, binds: { title: "title" } });
  gate.profile("solve_captcha", { effect: "write", tierFloor: "D" });
  await gate.run("add_task", { title: "x" }, () => "ok", { person: PERSON, tainted: false });
  const args = { to: ["sam@example.com"], subject: "Hi", body: "Lunch?" };
  const sent: string[] = [];
  let p: any;
  await assert.rejects(gate.run("send_email", args, () => sent.push("x"), { person: PERSON }), (e: any) => { p = e.preview; return e instanceof NeedsConsent; });
  await assert.rejects(gate.run("send_email", args, () => sent.push("x"), { person: PERSON }), (e: any) => e.preview.id === p.id);
  assert.ok(gate.acceptConsent(makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1 })));
  await gate.run("send_email", args, () => sent.push("x"), { person: PERSON });
  assert.deepEqual(sent, ["x"]);
  await assert.rejects(gate.run("send_email", args, () => sent.push("x"), { person: PERSON }), NeedsConsent);
  await assert.rejects(gate.run("solve_captcha", {}, () => 1, { person: PERSON }), (e: any) => e instanceof OACError && e.code === "tier_d");
  await assert.rejects(gate.run("send_email", { ...args, bcc: ["x@evil.test"] }, () => 1, { person: PERSON }), (e: any) => e.code === "undeclared_argument");
  const chain = verifyChain(gate.receipts.get(PERSON)!, { keys: new KeySet({ [EX]: [gate.key.jwk] }), executor: EX });
  assert.deepEqual(chain.map((r) => r.tier), ["B", "C"]);
});

test("gate: a timed-out payment cannot be paid again until it is resolved", async () => {
  const key = generate();
  const gate = new Gate({ executor: EX, key: generate(), signers: new KeySet({ [SIGNER]: [key.jwk] }) });
  gate.profile("pay_order", { effect: "pay", undo: "compensate", windowS: 86400, otherArgs: ["order"], occurrence: "order",
    binds: { amount_minor: "amount", currency: "currency", payee: "shop" } });
  const args = { amount: 1800, currency: "USD", shop: "Sweetgreen", order: "ord_1" };
  const payment = { rail: "stripe_link", ref: "lsrq_test_1", amount_minor: 1800, currency: "USD", payee: "Sweetgreen" };
  const timeout = () => { throw new Error("the provider did not answer"); };
  const charged: string[] = [];
  const tokens: string[] = [];
  const approve = async () => {
    let p: any;
    await assert.rejects(gate.run("pay_order", args, () => null, { person: PERSON }), (e: any) => { p = e.preview; return e instanceof NeedsConsent; });
    tokens.push(makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1, payment }));
    assert.ok(gate.acceptConsent(tokens[tokens.length - 1]));
  };
  const code = (c: string) => (e: any) => e instanceof OACError && e.code === c;

  await approve();
  await assert.rejects(gate.run("pay_order", args, timeout, { person: PERSON }), /did not answer/);
  // nobody is asked again while the first attempt's outcome is unknown
  await assert.rejects(gate.run("pay_order", args, () => charged.push("paid"), { person: PERSON }), code("occurrence_unresolved"));
  gate.resolve("pay_order", "ord_1", { person: PERSON, outcome: "failed" });
  await approve();
  await gate.run("pay_order", args, () => charged.push("paid"), { person: PERSON });
  await assert.rejects(gate.run("pay_order", args, () => charged.push("paid"), { person: PERSON }), code("duplicate_occurrence"));
  assert.deepEqual(charged, ["paid"]);

  const chain = verifyChain(gate.receipts.get(PERSON)!, { keys: new KeySet({ [EX]: [gate.key.jwk] }), executor: EX });
  assert.deepEqual(chain.map((r) => r.outcome), ["unknown", "ok"]);
  assert.deepEqual(chain.map((r) => gate.tokens.get(r.authority.digest)), tokens);
  assert.deepEqual(chain.map((r) => r.authority.digest), tokens.map(tokenDigest));
});

test("gate: a passkey is required, and only a proof over the kept consent lets it run", async () => {
  const key = generate(), passkey = generate("ES256");
  const need: DeviceCheck = { proof: null, credentials: { "cred-1": passkey.jwk }, rp_id: "app.example", origins: ["https://app.example"] };
  const gate = new Gate({ executor: EX, key: generate(), signers: new KeySet({ [SIGNER]: [key.jwk] }), device: () => need });
  gate.profile("send_email", { effect: "send", binds: { to: "to", title: "subject" }, otherArgs: ["body"] });
  const args = { to: ["sam@example.com"], subject: "Hi", body: "See you at 6" };
  const sent: string[] = [];
  let p: any;
  await assert.rejects(gate.run("send_email", args, () => sent.push("x"), { person: PERSON }), (e: any) => { p = e.preview; return e instanceof NeedsConsent; });
  const token = makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1 });
  assert.ok(gate.acceptConsent(token));
  await assert.rejects(gate.run("send_email", args, () => sent.push("x"), { person: PERSON }), (e: any) => e.code === "device_proof_missing");
  const other = makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 2 });
  assert.equal(gate.acceptConsent(other, passkeyProof(other, passkey)), false);
  const proof = passkeyProof(token, passkey);
  assert.ok(gate.acceptConsent(token, proof));
  assert.ok(gate.acceptConsent(token, { junk: 1 })); // a junk re-post is not kept, so it cannot block the run
  assert.ok(gate.acceptConsent(token, null));
  await gate.run("send_email", args, () => sent.push("x"), { person: PERSON });
  assert.deepEqual(sent, ["x"]);
  assert.deepEqual(gate.deviceProofs.get(tokenDigest(token)), proof);
});

test("gate: two pay tools with one provider scope share an order", async () => {
  const key = generate();
  const gate = new Gate({ executor: EX, key: generate(), signers: new KeySet({ [SIGNER]: [key.jwk] }) });
  for (const tool of ["pay_order", "pay_express"]) {
    gate.profile(tool, { effect: "pay", undo: "compensate", windowS: 86400, otherArgs: ["order"], occurrence: "order",
      occurrenceScope: "stripe:acct_1", binds: { amount_minor: "amount", currency: "currency", payee: "shop" } });
  }
  const args = { amount: 1800, currency: "USD", shop: "Sweetgreen", order: "ord_1" };
  let p: any;
  await assert.rejects(gate.run("pay_order", args, () => "paid", { person: PERSON }), (e: any) => { p = e.preview; return e instanceof NeedsConsent; });
  const payment = { rail: "stripe_link", ref: "lsrq_test_1", amount_minor: 1800, currency: "USD", payee: "Sweetgreen" };
  assert.ok(gate.acceptConsent(makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1, payment })));
  const [, receipt] = await gate.run("pay_order", args, () => "paid", { person: PERSON });
  assert.equal(JSON.parse(Buffer.from(receipt.split(".")[1], "base64url").toString()).occurrence_scope, "stripe:acct_1");
  await assert.rejects(gate.run("pay_express", args, () => "paid", { person: PERSON }), (e: any) => e.code === "duplicate_occurrence");
  gate.profile("stripe:acct_1", { effect: "write", undo: "native", windowS: 600, otherArgs: ["order"], occurrence: "order" });
  await gate.run("stripe:acct_1", { order: "ord_1" }, () => "held", { person: PERSON, tainted: false });
});

test("gate: a tool cannot move to another order scope while it has orders", async () => {
  const key = generate();
  const gate = new Gate({ executor: EX, key: generate(), signers: new KeySet({ [SIGNER]: [key.jwk] }) });
  const pay = (occurrenceScope?: string) => gate.profile("pay_order", { effect: "pay", undo: "compensate", windowS: 86400,
    otherArgs: ["order"], occurrence: "order", occurrenceScope, binds: { amount_minor: "amount", currency: "currency", payee: "shop" } });
  pay();
  pay("stripe:acct_1"); // no orders yet: allowed
  const args = { amount: 1800, currency: "USD", shop: "Sweetgreen", order: "ord_1" };
  let p: any;
  await assert.rejects(gate.run("pay_order", args, () => "paid", { person: PERSON }), (e: any) => { p = e.preview; return e instanceof NeedsConsent; });
  const payment = { rail: "stripe_link", ref: "lsrq_test_1", amount_minor: 1800, currency: "USD", payee: "Sweetgreen" };
  assert.ok(gate.acceptConsent(makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1, payment })));
  await gate.run("pay_order", args, () => "paid", { person: PERSON });
  pay("stripe:acct_1"); // the same scope again: allowed
  assert.throws(() => pay("stripe:acct_2"), /move them before changing/);
  assert.throws(() => pay(), /move them before changing/);
  // the refused change left the profile as it was, so the paid order still cannot run again
  await assert.rejects(gate.run("pay_order", args, () => "paid", { person: PERSON }), (e: any) => e.code === "duplicate_occurrence");
  // a store that cannot list a scope refuses every scope change
  const opaque = new Gate({ executor: EX, key: generate(), signers: new KeySet({}),
    occurrences: { claim: () => null, finish: () => {}, release: () => {}, state: () => null } });
  opaque.profile("pay_order", { effect: "pay", undo: "compensate", windowS: 86400, otherArgs: ["order"], occurrence: "order",
    binds: { amount_minor: "amount", currency: "currency", payee: "shop" } });
  assert.throws(() => opaque.profile("pay_order", { effect: "pay", undo: "compensate", windowS: 86400, otherArgs: ["order"],
    occurrence: "order", occurrenceScope: "stripe:acct_1", binds: { amount_minor: "amount", currency: "currency", payee: "shop" } }));
});
