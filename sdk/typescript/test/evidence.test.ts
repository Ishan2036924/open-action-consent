// Completeness anchors, observations and coverage (spec 8.4, 8.5, 13.2): each refusal and each verdict branch is pinned here.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  actionDigest, assess, buildPreview, coverage, digest, generate, KeySet, makeConsent, makeObservation, makeReceipt, makeSeal, OACError,
  makeMandate, makeUndo, parse, sign, tokenDigest, verifyChain, verifyExport,
} from "../src/index.ts";

const EX = "https://shop.example/oac", SIGNER = "https://atlas.example/signer", PROVIDER = "https://provider.example", PERSON = "person:1", NOW = 1_800_000_000;
const EXEC = generate(), USER = generate(), SEER = generate();
const KEYS = new KeySet({ [EX]: [EXEC.jwk] }), USER_KEYS = new KeySet({ [SIGNER]: [USER.jwk] }), SEER_KEYS = new KeySet({ [PROVIDER]: [SEER.jwk] });
const TASK = { tool: "add_task", args: { title: "Call" } };
const RES = digest({ ok: true });
const code = (f: () => unknown) => { try { f(); } catch (e) { if (e instanceof OACError) return e.code; throw e; } return "no error"; };

function receipt(n = 1, prev: string | null = null, fields: Record<string, any> = {}): string {
  return makeReceipt(EXEC, { iss: EX, sub: PERSON, seq: n, prev, iat: NOW + n, tool: "add_task", tier: "A", authority: { kind: "tier" },
    action: actionDigest(TASK), outcome: "ok", result: RES, undo: { kind: "none" }, ...fields });
}
const RS: string[] = [];
for (let i = 1; i <= 6; i++) RS.push(receipt(i, i > 1 ? tokenDigest(RS[i - 2]) : null));

function anchor(n: number, o: { key?: any; iss?: string; sub?: string; executor?: string; head?: string } = {}): string {
  return makeSeal({ key: o.key ?? USER, iss: o.iss ?? SIGNER, sub: o.sub ?? PERSON, executor: o.executor ?? EX, seq: n, headToken: o.head ?? RS[n - 1], now: NOW });
}
const exp = (tokens: string[], anchors: string[] = [], o: Record<string, any> = {}) =>
  verifyExport(tokens, { keys: KEYS, executor: EX, anchors, anchorKeys: USER_KEYS, ...o });
const report = (first: number | null, last: number | null, proven_to: number | null, status: string, reason: string | null) => ({ first, last, proven_to, status, reason });

test("six cut to four verifies as a chain but is only a prefix", () => {
  assert.equal(verifyChain(RS.slice(0, 4), { keys: KEYS, executor: EX }).length, 4);
  assert.deepEqual(exp(RS.slice(0, 4)), report(1, 4, null, "prefix", "no_anchor"));
});

test("an anchor or a count beyond the export says it was cut", () => {
  assert.equal(code(() => exp(RS.slice(0, 4), [anchor(6)])), "chain_truncated");
  assert.equal(code(() => exp([], [anchor(1)])), "chain_truncated");
  assert.equal(code(() => exp(RS.slice(0, 4), [], { expect: { seq: 6 } })), "chain_truncated");
  assert.equal(code(() => exp(RS.slice(0, 4), [], { expect: { seq: 4, head: tokenDigest(RS[2]) } })), "seal_mismatch");
  assert.equal(exp(RS.slice(0, 4), [], { expect: { seq: 4, head: tokenDigest(RS[3]) } }).status, "prefix");
  assert.equal(code(() => exp(RS.slice(0, 4), [], { expect: { seq: 0 } })), "malformed");
});

test("anchors prove up to themselves", () => {
  assert.deepEqual(exp(RS.slice(0, 4), [anchor(3)]), report(1, 4, 3, "prefix", "unanchored_tail"));
  assert.deepEqual(exp(RS.slice(0, 4), [anchor(3), anchor(4)]), report(1, 4, 4, "complete", null));
});

test("an anchor must come from someone other than the executor, and match the chain", () => {
  const mine = makeSeal({ key: EXEC, iss: EX, sub: PERSON, executor: EX, seq: 4, headToken: RS[3], now: NOW });
  assert.equal(code(() => exp(RS.slice(0, 4), [mine], { anchorKeys: KEYS })), "anchor_not_independent");
  assert.equal(code(() => exp(RS.slice(0, 4), [anchor(3, { head: RS[3] })])), "seal_mismatch");
  assert.equal(code(() => exp(RS.slice(0, 4), [anchor(4, { executor: "https://other.example" })])), "seal_mismatch");
  assert.equal(code(() => exp(RS.slice(0, 4), [anchor(4, { sub: "person:2" })])), "subject_mismatch");
  assert.equal(code(() => exp(RS.slice(0, 4), [anchor(4, { key: generate() })])), "unknown_key");
  assert.equal(code(() => exp(RS.slice(0, 4), [anchor(4)], { anchorKeys: null })), "malformed");
});

test("an export that starts late needs an anchor before it", () => {
  assert.deepEqual(exp(RS.slice(2, 4), [anchor(2), anchor(4)]), report(3, 4, 4, "complete", null));
  assert.equal(exp(RS.slice(2, 4), [anchor(4)]).reason, "unanchored_start");
  assert.equal(exp(RS.slice(2, 4), [anchor(2)]).reason, "unanchored_tail");
  assert.equal(code(() => exp(RS.slice(2, 4), [anchor(2, { head: RS[2] }), anchor(4)])), "seal_mismatch");
  assert.equal(exp(RS.slice(2, 4), [anchor(1)]).proven_to, null);
});

test("route and policy are optional receipt fields", () => {
  assert.equal(verifyChain([receipt(1, null, { route: "task-api", policy: digest({ p: 1 }) })], { keys: KEYS, executor: EX })[0].route, "task-api");
  assert.equal(code(() => receipt(1, null, { route: "" })), "malformed");
  assert.equal(code(() => receipt(1, null, { policy: "p1" })), "malformed");
});

const watch = (rec: string, effect: string, o: Record<string, any> = {}) =>
  makeObservation({ key: SEER, iss: PROVIDER, sub: PERSON, executor: EX, receiptToken: rec, effect, now: NOW, ...o });
const judge = (rec: string, obs: string[], o: Record<string, any> = {}) => assess(rec, { keys: KEYS, executor: EX, observations: obs, observerKeys: SEER_KEYS, ...o });
const subj = (n: number) => digest({ id: n });

const EFFECTS: [string, [string, number | null][], string, string][] = [
  ["ok", [], "cannot_establish", "cannot_establish"],
  ["ok", [["seen", null]], "observed", "pass"],
  ["ok", [["not_seen", null]], "not_observed", "fail"],
  ["ok", [["not_seen", null], ["seen", null]], "contradicted", "fail"],
  ["unknown", [["not_seen", null], ["seen", null]], "contradicted", "fail"],
  ["ok", [["uncheckable", null]], "cannot_establish", "cannot_establish"],
  ["ok", [["seen", 1], ["seen", 2]], "duplicate", "fail"],
  ["ok", [["seen", 1], ["seen", 1]], "observed", "pass"],
  ["failed", [], "absent", "pass"],
  ["failed", [["not_seen", null]], "absent", "pass"],
  ["failed", [["seen", null]], "contradicted", "fail"],
  ["failed", [["seen", 1], ["seen", 2]], "duplicate", "fail"],
  ["unknown", [], "cannot_establish", "cannot_establish"],
  ["unknown", [["not_seen", null]], "cannot_establish", "cannot_establish"],
  ["unknown", [["seen", null]], "observed", "pass"],
];
for (const [outcome, obs, effect, verdict] of EFFECTS) {
  test(`effect and verdict: ${outcome} with ${JSON.stringify(obs)}`, () => {
    const rec = receipt(1, null, { outcome });
    const got = judge(rec, obs.map(([e, s]) => watch(rec, e, s ? { subject: subj(s) } : {})));
    assert.deepEqual([got.effect, got.verdict, got.decision, got.route], [effect, verdict, "tier", null]);
  });
}

test("only a reader other than the executor counts, and only for this receipt", () => {
  const rec = receipt();
  assert.equal(code(() => judge(rec, [watch(rec, "seen", { key: EXEC, iss: EX })], { observerKeys: KEYS })), "observer_not_independent");
  assert.equal(code(() => judge(rec, [watch(receipt(1, null, { outcome: "failed" }), "seen")])), "receipt_mismatch");
  assert.equal(code(() => judge(rec, [watch(rec, "seen", { sub: "person:2" })])), "subject_mismatch");
  assert.equal(code(() => judge(rec, [watch(rec, "seen", { executor: "https://other.example" })])), "executor_mismatch");
  assert.equal(code(() => judge(rec, [watch(rec, "seen", { key: generate() })])), "unknown_key");
  assert.equal(code(() => judge(rec, [watch(rec, "seen")], { observerKeys: null })), "malformed");
});

test("an unverified decision cannot pass, a missing effect still fails, and the token must cover this action", () => {
  const profile = { oac: "0.2", type: "action-profile", tool: "add_task", effect: "write", undo: { kind: "native", window_s: 600 }, tier_floor: "A", binds: { title: "title" } };
  const prev = buildPreview({ profile, action: TASK, executor: EX, sub: PERSON, summary: "Add", now: NOW });
  const cons = makeConsent({ key: USER, iss: SIGNER, sub: PERSON, aud: EX, previews: [prev], now: NOW, jti: "n_consent_0000000001" });
  const other = makeConsent({ key: USER, iss: SIGNER, sub: PERSON, aud: EX, previews: [prev], now: NOW, jti: "n_consent_0000000002" });
  const decided = (authority: Record<string, any> = {}, preview: string = digest(prev)) =>
    receipt(1, null, { tier: "C", authority: { kind: "consent", ref: "n_consent_0000000001", digest: tokenDigest(cons), ...authority }, preview,
      undo: { kind: "compensate", until: NOW + 99 }, route: "task-api" });
  const rec = decided(), ok = { authorityToken: cons, authorityKeys: USER_KEYS };
  assert.deepEqual(judge(rec, [watch(rec, "seen")], ok), { route: "task-api", decision: "bound", effect: "observed", verdict: "pass" });
  assert.equal(judge(rec, [watch(rec, "seen")]).verdict, "cannot_establish");
  assert.equal(judge(rec, [watch(rec, "not_seen")]).verdict, "fail");
  assert.equal(judge(rec, [], ok).verdict, "cannot_establish");
  assert.equal(code(() => judge(rec, [], { authorityToken: other, authorityKeys: USER_KEYS })), "authority_mismatch");
  assert.equal(code(() => judge(decided({ ref: "n_consent_0000000009" }), [], ok)), "authority_mismatch");
  assert.equal(code(() => judge(rec, [], { authorityToken: cons })), "malformed");
  assert.equal(code(() => judge(decided({}, digest({ another: "preview" })), [], ok)), "authority_mismatch");
});

const row = (effect: string, routes: string[], records = "durable") =>
  ({ effect, key: "k", held_by: "executor only", records, routes: routes.map((route) => ({ route, credential: "login", control: "people only" })) });
const tried = (effect: string, route: string, effect_occurred = "no") => ({ effect, route, decision: "none", effect_occurred, observed_by: "log" });
const CASES: [any[], any[], string, boolean, Record<string, string>][] = [
  [[row("e", ["r"])], [tried("e", "x"), tried("e", "r")], "covered", false, { e: "covered" }],
  [[row("e", ["r"])], [], "not_checked", false, { e: "not_checked" }],
  [[row("e", ["r"])], [tried("e", "x")], "incomplete", false, { e: "incomplete" }],
  [[row("e", ["x"])], [tried("e", "x", "cannot_tell")], "incomplete", false, { e: "incomplete" }],
  [[row("e", ["x"], "memory")], [tried("e", "x")], "incomplete", false, { e: "incomplete" }],
  [[row("e", ["r"])], [tried("e", "r", "yes")], "bypass", false, { e: "bypass" }],
  [[row("e", ["r"]), row("f", ["x"])], [tried("e", "r"), tried("e", "z", "yes"), tried("f", "x")], "bypass", true, { e: "bypass", f: "covered" }],
  [[row("e", ["x"])], [tried("g", "z", "yes")], "bypass", true, { e: "not_checked", g: "bypass" }],
  [[row("e", ["x"]), row("f", ["x"])], [tried("e", "x")], "incomplete", false, { e: "covered", f: "not_checked" }],
  [[], [], "not_checked", false, {}],
];
test("coverage results", () => {
  for (const [statement, attempts, result, statement_wrong, effects] of CASES) {
    assert.deepEqual(coverage(statement, attempts), { result, statement_wrong, effects });
  }
});

test("coverage refuses a row without routes, reads none as empty, and takes any name", () => {
  assert.equal(code(() => coverage([row("e", [])], [])), "malformed");
  assert.deepEqual(coverage(null, undefined), { result: "not_checked", statement_wrong: false, effects: {} });
  assert.equal(code(() => coverage([], {})), "malformed");
  assert.equal(code(() => coverage("x", [])), "malformed");
  const got = coverage([row("__proto__", ["api"])], [tried("__proto__", "api", "yes")]);
  assert.equal(JSON.stringify(got), '{"result":"bypass","statement_wrong":false,"effects":{"__proto__":"bypass"}}');
});

test("coverage refuses a malformed statement", () => {
  assert.equal(code(() => coverage([row("e", ["x"]), row("e", ["x"])], [])), "malformed");
  assert.equal(code(() => coverage([row("e", ["r", "r"])], [])), "malformed");
  assert.equal(code(() => coverage([], [{ ...tried("e", "r"), effect_occurred: "maybe" }])), "malformed");
});

test("independence is by key, not only by name", () => {
  const renamed = makeSeal({ key: EXEC, iss: "https://notary.example", sub: PERSON, executor: EX, seq: 4, headToken: RS[3], now: NOW });
  assert.equal(code(() => exp(RS.slice(0, 4), [renamed], { anchorKeys: new KeySet({ "https://notary.example": [EXEC.jwk] }) })), "anchor_not_independent");
  const rec = receipt();
  assert.equal(code(() => judge(rec, [watch(rec, "seen", { key: EXEC })], { observerKeys: new KeySet({ [PROVIDER]: [EXEC.jwk] }) })), "observer_not_independent");
});

test("null and wrong types are read the same way everywhere", () => {
  const rec = receipt();
  assert.equal(verifyExport(RS.slice(0, 4), { keys: KEYS, executor: EX, anchors: null, anchorKeys: null }).reason, "no_anchor");
  assert.equal(verifyExport(null as any, { keys: KEYS, executor: EX }).first, null);
  assert.equal(code(() => verifyExport(RS.slice(0, 4), { keys: KEYS, executor: EX, anchors: "x" as any })), "malformed");
  assert.equal(code(() => verifyExport(RS.slice(0, 4), { keys: KEYS, executor: EX, anchors: [5] as any, anchorKeys: USER_KEYS })), "malformed");
  assert.equal(code(() => verifyExport("x" as any, { keys: KEYS, executor: EX })), "malformed");
  assert.equal(assess(rec, { keys: KEYS, executor: EX, observations: null }).verdict, "cannot_establish");
  assert.equal(code(() => assess(rec, { keys: KEYS, executor: EX, observations: "x" as any, observerKeys: SEER_KEYS })), "malformed");
  assert.equal(code(() => assess(rec, { keys: KEYS, executor: EX, observations: [5] as any, observerKeys: SEER_KEYS })), "malformed");
});

test("a stale look does not count and sixty seconds does", () => {
  const rec = receipt(5);
  assert.equal(judge(rec, [watch(rec, "seen", { now: NOW + 5 - 61 })]).effect, "cannot_establish");
  assert.equal(judge(rec, [watch(rec, "seen", { now: NOW + 5 - 60 })]).effect, "observed");
});

test("the authority token must be for this person, executor and time", () => {
  const profile = { oac: "0.2", type: "action-profile", tool: "add_task", effect: "write", undo: { kind: "native", window_s: 600 }, tier_floor: "A", binds: { title: "title" } };
  const prev = buildPreview({ profile, action: TASK, executor: EX, sub: PERSON, summary: "Add", now: NOW });
  const cons = makeConsent({ key: USER, iss: SIGNER, sub: PERSON, aud: EX, previews: [prev], now: NOW, jti: "n_consent_0000000001" });
  const body = parse(Buffer.from(cons.split(".")[1], "base64url").toString());
  const under = (t: string) => receipt(1, null, { tier: "C", authority: { kind: "consent", ref: "n_consent_0000000001", digest: tokenDigest(t) },
    undo: { kind: "compensate", until: NOW + 99 }, preview: digest(prev) });
  const ok = { authorityToken: cons, authorityKeys: USER_KEYS };
  assert.equal(judge(under(cons), [], ok).decision, "bound");
  for (const change of [{ sub: "person:2" }, { aud: "https://other.example/oac" }, { iat: NOW + 62, exp: NOW + 200 }]) {
    const moved = sign({ ...(body as any), ...change }, USER, "oac-consent+jws");
    assert.equal(code(() => judge(under(moved), [], { authorityToken: moved, authorityKeys: USER_KEYS })), "authority_mismatch");
  }
});

test("a mandate must be for this person, tool and time", () => {
  const mandate = (change: Record<string, any> = {}) => makeMandate(USER, { id: "md_1", iss: SIGNER, sub: PERSON, holder: { type: "agent", id: "bot" }, goal: "g",
    tools: ["add_task"], bounds: { calls: { per_day: 5 } }, iat: NOW - 100, exp: NOW + 100, signer: { kind: "custodial" }, ...change });
  const under = (t: string, fields: Record<string, any> = {}) => receipt(1, null, { tier: "C", authority: { kind: "mandate", ref: "md_1", digest: tokenDigest(t) }, ...fields });
  const good = mandate();
  assert.equal(judge(under(good), [], { authorityToken: good, authorityKeys: USER_KEYS }).decision, "bound");
  const bad: [string, Record<string, any>][] = [[mandate({ sub: "person:2" }), {}], [mandate({ tools: ["send_email"] }), {}],
    [mandate({ exp: NOW }), { iat: NOW + 61 }], [mandate({ iat: NOW + 100, exp: NOW + 200 }), { iat: NOW + 30 }]];
  for (const [t, fields] of bad) assert.equal(code(() => judge(under(t, fields), [], { authorityToken: t, authorityKeys: USER_KEYS })), "authority_mismatch");
});

test("an undo request must be for this person and executor", () => {
  const orig = receipt(1, null, { tier: "B", undo: { kind: "native", until: NOW + 600, token: "u1" } });
  const request = (o: Record<string, any> = {}) => makeUndo({ key: USER, iss: SIGNER, sub: PERSON, aud: EX, receiptToken: orig, mode: "native", now: NOW, jti: "n_undo_00000000000001", ...o });
  const under = (t: string) => receipt(1, null, { tier: "B", authority: { kind: "undo", ref: "n_undo_00000000000001", digest: tokenDigest(t) }, undoes: tokenDigest(orig) });
  const good = request();
  assert.equal(judge(under(good), [], { authorityToken: good, authorityKeys: USER_KEYS }).decision, "bound");
  for (const o of [{ sub: "person:2" }, { aud: "https://other.example/oac" }]) {
    const bad = request(o);
    assert.equal(code(() => judge(under(bad), [], { authorityToken: bad, authorityKeys: USER_KEYS })), "authority_mismatch");
  }
});
