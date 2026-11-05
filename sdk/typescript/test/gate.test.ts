import { test } from "node:test";
import assert from "node:assert/strict";
import { Gate, generate, KeySet, makeConsent, NeedsConsent, OACError, tokenDigest, verifyChain } from "../src/index.ts";

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
    await assert.rejects(gate.run("pay_order", args, timeout, { person: PERSON }), (e: any) => { p = e.preview; return e instanceof NeedsConsent; });
    tokens.push(makeConsent({ key, iss: SIGNER, sub: PERSON, aud: EX, previews: [p], now: p.iat + 1, payment }));
    assert.ok(gate.acceptConsent(tokens[tokens.length - 1]));
  };
  const code = (c: string) => (e: any) => e instanceof OACError && e.code === c;

  await approve();
  await assert.rejects(gate.run("pay_order", args, timeout, { person: PERSON }), /did not answer/);
  await approve();
  await assert.rejects(gate.run("pay_order", args, () => charged.push("paid"), { person: PERSON }), code("occurrence_unresolved"));
  gate.resolve("pay_order", "ord_1", { person: PERSON, outcome: "failed" });
  await gate.run("pay_order", args, () => charged.push("paid"), { person: PERSON });
  await approve();
  await assert.rejects(gate.run("pay_order", args, () => charged.push("paid"), { person: PERSON }), code("duplicate_occurrence"));
  assert.deepEqual(charged, ["paid"]);

  const chain = verifyChain(gate.receipts.get(PERSON)!, { keys: new KeySet({ [EX]: [gate.key.jwk] }), executor: EX });
  assert.deepEqual(chain.map((r) => r.outcome), ["unknown", "ok"]);
  assert.deepEqual(chain.map((r) => r.authority.digest), [tokenDigest(tokens[0]), tokenDigest(tokens[1])]);
});
