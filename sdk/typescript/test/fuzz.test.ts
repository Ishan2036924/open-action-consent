// Property-based fuzzing of every surface that reads untrusted input, mirroring sdk/python/tests/test_fuzz.py.
// A hostile input is refused with OACError and a known code, never another exception; the well-formed path
// round-trips. Runs are seeded; OAC_FUZZ_EXAMPLES raises the budget (OAC_FUZZ_EXAMPLES=5000 npm test).
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
  assess, canonical, Gate, NeedsConsent, CODES, digest, KeySet, makeObservation, makeReceipt, makeSeal, OACError, parse, shapes, sign, tokenDigest,
  verify, verifyChain, verifyExport,
} from "../src/index.ts";
import { checkSemantics } from "../src/receipts.ts";
import { vectorKey } from "../src/testing.ts";

const RUNS = Number(process.env.OAC_FUZZ_EXAMPLES ?? 100);
const OPTS = { numRuns: RUNS, seed: 20261121 };
const SAFE = Number.MAX_SAFE_INTEGER;

const EX = "https://shop.example/oac", SIGNER = "https://signer.example", SEER_ISS = "https://seer.example", PERSON = "person:1";
const NOW = 1_800_000_000;
const EXEC = vectorKey("fuzz executor"), USER = vectorKey("fuzz signer"), SEER = vectorKey("fuzz observer", "ES256");
const KEYS = new KeySet({ [EX]: [EXEC.jwk] }), USER_KEYS = new KeySet({ [SIGNER]: [USER.jwk] }), SEER_KEYS = new KeySet({ [SEER_ISS]: [SEER.jwk] });
const ALL_KEYS = new KeySet({ [EX]: [EXEC.jwk], [SIGNER]: [USER.jwk], [SEER_ISS]: [SEER.jwk] });
const RES = digest({ ok: true });

function receipt(n: number, prev: string | null, fields: Record<string, unknown> = {}): string {
  return makeReceipt(EXEC, {
    iss: EX, sub: PERSON, seq: n, prev, iat: NOW + n, tool: "add_task", tier: "A", authority: { kind: "tier" },
    action: digest({ tool: "add_task", args: { title: "Call" } }), outcome: "ok", result: RES, undo: { kind: "none" }, ...fields,
  });
}

const CHAIN: string[] = [];
for (let i = 1; i <= 4; i++) CHAIN.push(receipt(i, CHAIN.length ? tokenDigest(CHAIN[CHAIN.length - 1]) : null));
const SEALS = [1, 2, 3, 4].map((i) => makeSeal({ key: USER, iss: SIGNER, sub: PERSON, executor: EX, seq: i, headToken: CHAIN[i - 1], now: NOW }));
const OBS = ["seen", "not_seen", "uncheckable"].map((effect) =>
  makeObservation({ key: SEER, iss: SEER_ISS, sub: PERSON, executor: EX, receiptToken: CHAIN[0], effect, now: NOW + 5 }));
const payloadOf = (t: string) => parse(Buffer.from(t.split(".")[1], "base64url")) as Record<string, unknown>;
const VALID = { receipt: payloadOf(CHAIN[0]), seal: payloadOf(SEALS[0]), observation: payloadOf(OBS[0]) };

/** Run f; an OACError with a known code is a fine answer, anything else fails the property. */
function refused<T>(f: () => T): T | OACError {
  try {
    return f();
  } catch (e) {
    if (!(e instanceof OACError)) throw e;
    assert.ok(CODES.has(e.code), e.code);
    return e;
  }
}

// Arbitraries

const scalar = fc.oneof(fc.constant(null), fc.boolean(), fc.integer({ min: -SAFE, max: SAFE }), fc.string({ unit: "grapheme", maxLength: 20 }));
const { json } = fc.letrec((tie) => ({
  json: fc.oneof({ depthSize: "small", withCrossShrink: true }, scalar,
    fc.array(tie("json"), { maxLength: 5 }), fc.dictionary(fc.string({ unit: "grapheme", maxLength: 10 }), tie("json"), { maxKeys: 5, noNullPrototype: true })),
}));
const jsonValue = json as fc.Arbitrary<unknown>;

function mutated(text: string): fc.Arbitrary<string> {
  if (!text) return fc.string({ maxLength: 4 });
  const ch = fc.oneof(fc.string({ unit: "binary", minLength: 1, maxLength: 1 }), fc.constantFrom(..."{}[]\",:.\\-0123456789eE AaZz_="));
  return fc.tuple(fc.nat({ max: text.length - 1 }), fc.constantFrom("insert", "delete", "replace", "swap", "truncate"), ch).map(([i, op, c]) => {
    if (op === "insert") return text.slice(0, i) + c + text.slice(i);
    if (op === "delete") return text.slice(0, i) + text.slice(i + 1);
    if (op === "replace") return text.slice(0, i) + c + text.slice(i + 1);
    if (op === "swap" && i + 1 < text.length) return text.slice(0, i) + text[i + 1] + text[i] + text.slice(i + 2);
    return text.slice(0, i);
  });
}

const b64 = (s: string | Uint8Array) => Buffer.from(s).toString("base64url");
const tokens = fc.oneof(
  fc.string({ unit: "binary", maxLength: 80 }),
  fc.constantFrom(...CHAIN, ...SEALS, ...OBS).chain(mutated),
  fc.tuple(jsonValue, jsonValue, fc.uint8Array({ maxLength: 70 })).map(([h, p, s]) => `${b64(JSON.stringify(h) ?? "")}.${b64(JSON.stringify(p) ?? "")}.${b64(s)}`),
  fc.tuple(fc.constantFrom("EdDSA", "ES256", "none", "HS256"), fc.constantFrom(EXEC.jwk.kid, SEER.jwk.kid, "x"), jsonValue, fc.uint8Array({ maxLength: 70 }))
    .map(([alg, kid, p, s]) => `${b64(canonical({ alg, kid, typ: "oac-receipt+jws" }))}.${b64(JSON.stringify(p) ?? "")}.${b64(s)}`),
  fc.array(fc.constantFrom("", "e30", "eyJ9", "AA", "_-", "=", ".", "AAAAA"), { maxLength: 5 }).map((a) => a.join(".")),
);

function damaged(doc: Record<string, unknown>): fc.Arbitrary<unknown> {
  const keys = Object.keys(doc).sort();
  return fc.oneof(
    jsonValue,
    fc.tuple(fc.string({ maxLength: 8 }), jsonValue).map(([k, v]) => ({ ...doc, [k]: v })),
    fc.constantFrom(...keys).map((k) => { const d = { ...doc }; delete d[k]; return d; }),
    fc.tuple(fc.constantFrom(...keys), fc.oneof(jsonValue, fc.dictionary(fc.constantFrom("kind", "ref", "digest", "until", "token"), jsonValue, { maxKeys: 3, noNullPrototype: true })))
      .map(([k, v]) => ({ ...doc, [k]: v })),
  );
}

const withIss = (iss: string) => (d: unknown) => (d !== null && typeof d === "object" && !Array.isArray(d) ? { ...(d as object), iss } : d);
const trustedGarbage = fc.oneof(
  damaged(VALID.receipt).map(withIss(EX)).map((d) => sign(d as Record<string, unknown>, EXEC, "oac-receipt+jws")),
  damaged(VALID.seal).map(withIss(SIGNER)).map((d) => sign(d as Record<string, unknown>, USER, "oac-seal+jws")),
  damaged(VALID.observation).map(withIss(SEER_ISS)).map((d) => sign(d as Record<string, unknown>, SEER, "oac-observation+jws")),
);
const anyToken = fc.oneof(tokens, trustedGarbage, fc.constantFrom(...CHAIN, ...SEALS, ...OBS));
const tokenLists = fc.oneof(fc.array(anyToken, { maxLength: 5 }), fc.shuffledSubarray(CHAIN), jsonValue);

// Strict JSON and JCS

test("fuzz: JCS round trip and idempotence", () => {
  fc.assert(fc.property(jsonValue, (v) => {
    const c = canonical(v);
    assert.deepEqual(parse(c), v);
    assert.equal(canonical(parse(c)), c);
    assert.deepEqual(parse(new TextEncoder().encode(c)), v);
  }), OPTS);
});

test("fuzz: canonical refuses only with OACError, including values JSON cannot hold", () => {
  const hostile = fc.anything({
    maxDepth: 3, withBigInt: true, withDate: true, withMap: true, withSet: true, withBoxedValues: true, withTypedArray: true,
    withSparseArray: true, withNullPrototype: true, withObjectString: true,
  });
  fc.assert(fc.property(fc.oneof(hostile, fc.double()), (v) => {
    const out = refused(() => canonical(v));
    if (typeof out === "string") assert.equal(canonical(parse(out)), out);
  }), OPTS);
});

test("fuzz: parse arbitrary text, bytes and near misses", () => {
  fc.assert(fc.property(fc.oneof(fc.string({ unit: "binary", maxLength: 60 }), fc.uint8Array({ maxLength: 80 }), jsonValue.chain((v) => mutated(canonical(v)))), (input) => {
    const out = refused(() => parse(input));
    if (!(out instanceof OACError)) assert.equal(canonical(parse(canonical(out))), canonical(out));
  }), OPTS);
});

test("fuzz: deep nesting is refused past 64 levels, never a stack overflow", () => {
  fc.assert(fc.property(fc.integer({ min: 1, max: 5000 }), fc.constantFrom("[", '{"a":'), (depth, open) => {
    const close = open === "[" ? "]" : "}";
    const out = refused(() => parse(open.repeat(depth) + "1" + close.repeat(depth)));
    assert.equal(out instanceof OACError, depth > 64);
  }), { ...OPTS, numRuns: Math.min(RUNS, 200) });
});

// Compact JWS and keys

test("fuzz: verify refuses hostile tokens", () => {
  fc.assert(fc.property(tokens, fc.constantFrom("oac-receipt+jws", "oac-seal+jws", "oac-observation+jws"), (token, typ) => {
    const out = refused(() => verify(token, ALL_KEYS, typ));
    if (!(out instanceof OACError)) assert.ok([...CHAIN, ...SEALS, ...OBS].includes(token));
  }), OPTS);
});

test("fuzz: any edit of a signed token is refused", () => {
  fc.assert(fc.property(fc.constantFrom(...CHAIN).chain(mutated), (token) => {
    if (!CHAIN.includes(token)) assert.ok(refused(() => verify(token, KEYS, "oac-receipt+jws")) instanceof OACError);
  }), OPTS);
});

const jwkLike = fc.record({
  kty: fc.oneof(fc.constantFrom("OKP", "EC", "RSA"), jsonValue),
  crv: fc.oneof(fc.constantFrom("Ed25519", "P-256", "X25519"), jsonValue),
  x: fc.oneof(fc.constantFrom(EXEC.jwk.x, SEER.jwk.x, "", "AA"), jsonValue),
  y: fc.oneof(fc.constantFrom(SEER.jwk.y ?? "", ""), jsonValue),
  kid: fc.oneof(fc.constantFrom(EXEC.jwk.kid, SEER.jwk.kid), jsonValue),
}, { requiredKeys: [] });

test("fuzz: KeySet refuses hostile key documents with OACError", () => {
  // issuer key documents come from the network
  fc.assert(fc.property(fc.oneof(jwkLike, jsonValue), fc.constantFrom("list", "bare", "whole"), (jwk, how) => {
    const by = how === "list" ? { iss: [jwk] } : how === "bare" ? { iss: jwk } : jwk;
    refused(() => new KeySet(by as never));
  }), OPTS);
  fc.assert(fc.property(jwkLike, fc.constantFrom(...CHAIN, ...SEALS, ...OBS), (jwk, token) => {
    const keys = refused(() => new KeySet({ [EX]: [jwk as never] }));
    if (keys instanceof KeySet) refused(() => verify(token, keys, "oac-receipt+jws"));
  }), OPTS);
});

// Shape checks

for (const [name, check] of [["receipt", shapes.receipt], ["seal", shapes.seal], ["observation", shapes.observation]] as const) {
  test(`fuzz: ${name} shape check`, () => {
    fc.assert(fc.property(damaged(VALID[name]), (v) => {
      const out = refused(() => check(v));
      if (name === "receipt" && !(out instanceof OACError)) refused(() => checkSemantics(out));
    }), OPTS);
  });
}

// verifyExport and assess

const expectArb = fc.oneof(fc.constant(null), jsonValue, fc.record({
  seq: fc.integer({ min: -2, max: 8 }),
  head: fc.oneof(fc.constantFrom(...CHAIN.map(tokenDigest)), fc.string({ maxLength: 5 })),
}, { requiredKeys: ["seq"] }));

test("fuzz: verifyExport on hostile input", () => {
  fc.assert(fc.property(tokenLists, tokenLists, expectArb, (toks, anchors, expect) => {
    const out = refused(() => verifyExport(toks as string[], { keys: KEYS, executor: EX, anchors: anchors as string[], anchorKeys: USER_KEYS, expect: expect as never }));
    if (!(out instanceof OACError)) assert.ok(["complete", "prefix"].includes(out.status));
  }), OPTS);
});

test("fuzz: verifyChain seals on hostile input", () => {
  fc.assert(fc.property(fc.array(fc.oneof(fc.constantFrom(...SEALS), anyToken), { maxLength: 4 }), (seals) => {
    refused(() => verifyChain(CHAIN, { keys: KEYS, executor: EX, seals, sealKeys: USER_KEYS }));
  }), OPTS);
});

test("fuzz: assess on hostile input", () => {
  fc.assert(fc.property(anyToken, fc.oneof(fc.array(fc.oneof(fc.constantFrom(...OBS), anyToken), { maxLength: 4 }), jsonValue), fc.option(anyToken), (rec, obs, auth) => {
    const out = refused(() => assess(rec, { keys: KEYS, executor: EX, observations: obs as string[], observerKeys: SEER_KEYS, authorityToken: auth, authorityKeys: USER_KEYS }));
    if (!(out instanceof OACError)) assert.ok(["pass", "fail", "cannot_establish"].includes(out.verdict));
  }), OPTS);
});

test("fuzz: assess with a trusted but hostile authority", () => {
  fc.assert(fc.property(fc.constantFrom("consent", "mandate", "undo"), jsonValue, fc.constantFrom("oac-consent+jws", "oac-mandate+jws", "oac-undo+jws"), (kind, payload, typ) => {
    const auth = sign(withIss(SIGNER)(payload) as Record<string, unknown>, USER, typ);
    const rec = receipt(1, null, { tier: "C", authority: { kind, ref: "r-1", digest: tokenDigest(auth) }, ...(kind === "undo" ? { undoes: RES } : {}) });
    refused(() => assess(rec, { keys: KEYS, executor: EX, authorityToken: auth, authorityKeys: USER_KEYS }));
  }), OPTS);
});

// The gate: what an agent or a gateway hands it is untrusted

const GATE_PROFILES: Record<string, Parameters<Gate["profile"]>[1]> = {
  "notes/read_note": { effect: "read", binds: { title: "title" } },
  "tasks/add_task": { effect: "write", undo: "native", windowS: 600, binds: { title: "title" } },
  "mail/send_email": { effect: "send", binds: { to: "to", title: "subject" }, otherArgs: ["body"] },
  "files/wipe_drive": { effect: "delete", tierFloor: "D", binds: { title: "drive" } },
  "shop/order": { effect: "write", undo: "native", windowS: 60, binds: { title: "item" }, otherArgs: ["order_id"], occurrence: "order_id", occurrenceScope: "shop" },
};
const ARG_NAMES = ["title", "to", "subject", "body", "drive", "item", "order_id", "x", "__proto__", "constructor", ""];

function gate(): Gate {
  const g = new Gate({ executor: EX, key: EXEC, signers: USER_KEYS, clock: () => NOW });
  for (const [tool, p] of Object.entries(GATE_PROFILES)) g.profile(tool, p);
  return g;
}

const hostileArgs = fc.oneof(
  fc.constantFrom({ title: "Call" }, { to: ["pat@example.org"], subject: "Hi", body: "x" }, { item: "tea", order_id: "o-1" }, { drive: "C" }),
  fc.dictionary(fc.oneof(fc.constantFrom(...ARG_NAMES), fc.string({ maxLength: 6 })), jsonValue, { maxKeys: 5, noNullPrototype: true }),
  fc.record({ title: fc.string({ maxLength: 30 }), order_id: jsonValue, to: jsonValue, subject: jsonValue, item: jsonValue, body: jsonValue },
    { requiredKeys: ["title"] }),
);
const hostileResult = fc.oneof(jsonValue, fc.anything({ maxDepth: 2, withBigInt: true, withDate: true, withMap: true }), fc.double(),
  fc.constantFrom("\ud800", undefined, () => 1));

test("fuzz: the gate refuses before running, or runs and writes a receipt", async () => {
  await fc.assert(fc.asyncProperty(fc.oneof(fc.constantFrom(...Object.keys(GATE_PROFILES)), fc.string({ maxLength: 12 })), hostileArgs,
    fc.oneof(fc.constantFrom(PERSON, "user_id:alice"), fc.string({ unit: "binary", maxLength: 12 })), fc.boolean(), hostileResult,
    async (tool, args, person, tainted, result) => {
      const g = gate(), ran: unknown[] = [];
      let out: [unknown, string];
      try {
        out = await g.run(tool, args as Record<string, unknown>, (a) => { ran.push(a); return result; }, { person, tainted });
      } catch (e) {
        if (e instanceof NeedsConsent) { assert.equal(ran.length, 0); shapes.preview(e.preview); return; }
        if (e instanceof OACError) { assert.equal(ran.length, 0); assert.ok(CODES.has(e.code)); return; }
        throw e;
      }
      assert.equal(ran.length, 1);
      assert.equal(verifyChain([out[1]], { keys: KEYS, executor: EX })[0].sub, person);
    }), OPTS);
});

test("fuzz: gate acceptConsent never throws", () => {
  fc.assert(fc.property(fc.oneof(anyToken, jsonValue), fc.oneof(fc.constant(null), jsonValue), (token, proof) => {
    const g = gate();
    g.preview("mail/send_email", { to: ["pat@example.org"], subject: "Hi", body: "x" }, PERSON);
    assert.ok([true, false].includes(g.acceptConsent(token as string, proof as never)));
  }), OPTS);
});
