import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPreview, canonical, generate, KeySet, makeConsent, MemoryNonces, OACError, parse, sign, verify, verifyConsent } from "../src/index.ts";

const PROFILE = { oac: "0.1", type: "action-profile", tool: "send_email", effect: "send", undo: { kind: "none", window_s: 0 }, tier_floor: "A", binds: { to: "to", title: "subject" }, other_args: ["body"] };
const ACTION = { tool: "send_email", args: { to: ["sam@example.com"], subject: "Hi", body: "See you" } };
const code = (f: () => unknown) => { try { f(); } catch (e) { if (e instanceof OACError) return e.code; throw e; } return "no error"; };

for (const alg of ["EdDSA", "ES256"]) {
  test(`${alg} round trip and unknown key`, () => {
    const key = generate(alg);
    const token = sign({ oac: "0.1", n: 1, iss: "me" }, key, "t+jws");
    assert.deepEqual(verify(token, new KeySet({ me: [key.jwk] }), "t+jws"), { oac: "0.1", n: 1, iss: "me" });
    assert.equal(code(() => verify(token, new KeySet({ me: [generate(alg).jwk] }), "t+jws")), "unknown_key");
    assert.equal(code(() => verify(token, new KeySet({ someone: [key.jwk] }), "t+jws")), "wrong_issuer");
  });
}

test("strict JSON and canonical form", () => {
  assert.equal(code(() => parse('{"a":1,"a":2}')), "malformed");
  assert.equal(code(() => parse('{"a":1.0}')), "malformed");
  assert.equal(code(() => canonical({ a: 1.5 })), "malformed");
  assert.equal(code(() => canonical({ a: "\ud800" })), "malformed");
  assert.equal(canonical(parse('{"__proto__":{"x":1},"a":2}')), '{"__proto__":{"x":1},"a":2}');
});

test("full flow; nonce single use; a failed check does not burn the nonce", () => {
  const user = generate(), now = 1_800_000_000;
  const preview = buildPreview({ profile: PROFILE, action: ACTION, executor: "ex", sub: "p1", summary: "Email sam", now });
  const token = makeConsent({ key: user, iss: "signer", sub: "p1", aud: "ex", previews: [preview], now });
  const nonces = new MemoryNonces();
  const opts = { keys: new KeySet({ signer: [user.jwk] }), executor: "ex", sub: "p1", previews: [preview], profiles: { send_email: PROFILE }, now: now + 5, nonces };
  const evil = { ...ACTION, args: { ...ACTION.args, to: ["x@evil.test"] } };
  assert.equal(code(() => verifyConsent(token, { ...opts, actions: [evil] })), "action_mismatch");
  assert.equal(verifyConsent(token, { ...opts, actions: [ACTION] }).sub, "p1");
  assert.equal(code(() => verifyConsent(token, { ...opts, actions: [ACTION] })), "replay");
});

test("ES256 signatures are low-S; non-ASCII tokens and a BOM are malformed", () => {
  const key = generate("ES256");
  const half = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n / 2n;
  for (let i = 0; i < 40; i++) {
    const sig = Buffer.from(sign({ i, iss: "me" }, key, "t").split(".")[2], "base64url");
    assert.ok(BigInt("0x" + sig.subarray(32).toString("hex")) <= half);
  }
  assert.equal(code(() => verify("é.a.b", new KeySet({}), "t")), "malformed");
  assert.equal(code(() => parse(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))), "malformed");
  assert.equal(code(() => parse("[".repeat(5000) + "]".repeat(5000))), "malformed");
});
