// Field-level checks for every OAC object: the same rules as schemas/*.schema.json plus the cross-field rules a JSON
// Schema cannot say (marked "rule"). Every failure is `malformed`. Unknown fields are refused. Mirrors shapes.py.

import { OACError } from "./errors.ts";
import { canonical } from "./jcs.ts";

export const VERSION = "0.1";
export const EFFECTS = ["read", "write", "send", "pay", "delete"];
const UNDO_KINDS = ["native", "compensate", "none"];
export const TIERS = ["A", "B", "C", "D"];
const RAILS = ["stripe_link", "ap2", "vi", "other"];
const HOLDERS = ["agent", "client", "run"];
const SIGNERS = ["custodial", "device"];
const AUTHORITIES = ["consent", "mandate", "tier", "undo"];
export const PREVIEW_MAX_S = 900;
const YEAR_S = 366 * 86400;

type Check = (v: any) => boolean;
type Fields = Record<string, [boolean, Check]>;

const isObj = (v: unknown): v is Record<string, any> => v !== null && typeof v === "object" && !Array.isArray(v);
const int = (lo: number, hi = Number.MAX_SAFE_INTEGER): Check => (v) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const str = (lo: number, hi: number): Check => (v) => typeof v === "string" && v.length >= lo && v.length <= hi;
const re = (rx: RegExp): Check => (v) => typeof v === "string" && rx.test(v);
const oneOf = (...vals: string[]): Check => (v) => typeof v === "string" && vals.includes(v);
const constant = (val: string): Check => (v) => v === val;
const list = (item: Check, lo: number, hi: number, unique = true): Check => (v) =>
  Array.isArray(v) && v.length >= lo && v.length <= hi && v.every(item) && (!unique || new Set(v.map(canonical)).size === v.length);
const obj = (fields: Fields, what: string): Check => (v) => { check(v, fields, what); return true; };

// String lengths follow Python's len() (code points), not UTF-16 units.
const cpLen = (s: string) => [...s].length;
const strCp = (lo: number, hi: number): Check => (v) => typeof v === "string" && cpLen(v) >= lo && cpLen(v) <= hi;

export function check(v: unknown, fields: Fields, what: string): void {
  if (!isObj(v)) throw new OACError("malformed", `${what} must be an object`);
  const extra = Object.keys(v).filter((k) => !Object.hasOwn(fields, k)).sort();
  if (extra.length) throw new OACError("malformed", `${what}: unknown field ${extra[0]}`);
  for (const [name, [required, ok]] of Object.entries(fields)) {
    if (!Object.hasOwn(v, name)) {
      if (required) throw new OACError("malformed", `${what}: missing ${name}`);
      continue;
    }
    if (!ok(v[name])) throw new OACError("malformed", `${what}: bad ${name}`);
  }
}

const ID = re(/^[\x21-\x7e]{1,256}$/);
const TOOL = re(/^[A-Za-z0-9_.:/-]{1,128}$/);
const ARG = re(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/);
const DIGEST = re(/^sha-256:[A-Za-z0-9_-]{43}$/);
const NONCE = re(/^[A-Za-z0-9_-]{16,128}$/);
const CURRENCY = re(/^[A-Z]{3}$/);
const HOST = re(/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/);
// one bare ASCII address; a recipient rule is an address or "@domain" (same classes as shapes.py)
const LOCAL = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}";
const DOMAIN = "[A-Za-z0-9]([A-Za-z0-9.-]{0,188}[A-Za-z0-9])?";
const EMAIL = re(new RegExp(`^${LOCAL}@${DOMAIN}$`));
const ADDR = re(new RegExp(`^(${LOCAL})?@${DOMAIN}$`));
// characters that let displayed text lie (controls, bidi overrides, zero-width): refused in what a person reads
const UNSAFE = /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
const text = (lo: number, hi: number): Check => (v) => strCp(lo, hi)(v) && !UNSAFE.test(v);
const LAST4 = re(/^[0-9]{4}$/);
const TIME = int(0);
const UNDO: Fields = { kind: [true, oneOf(...UNDO_KINDS)], window_s: [true, int(0, YEAR_S)], note: [false, strCp(1, 200)] };

export const PREVIEW_FIELDS: Record<string, Check> = {
  title: text(1, 200),
  to: list(EMAIL, 1, 50),
  when: text(1, 64),
  amount_minor: int(0),
  currency: CURRENCY,
  payee: text(1, 200),
  site: HOST,
  count: int(0),
};
// rule: a pay tool must show amount, currency and payee; a send tool must show who receives it
export const REQUIRED_BINDS: Record<string, string[]> = { pay: ["amount_minor", "currency", "payee"], send: ["to"] };
const has = (o: object, k: string) => Object.hasOwn(o, k);

function undoRule(u: Record<string, any>, what: string): void {
  if ((u.kind === "none") !== (u.window_s === 0) || (u.kind !== "none" && u.window_s < 60)) {
    throw new OACError("malformed", `${what}: undo window does not fit its kind`);
  }
}

export function profile(v: any): Record<string, any> {
  const binds: Check = (b) => isObj(b) && Object.entries(b).every(([k, a]) => has(PREVIEW_FIELDS, k) && ARG(a));
  const others = list(ARG, 1, 64);
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("action-profile")], tool: [true, TOOL],
    effect: [true, oneOf(...EFFECTS)], undo: [true, obj(UNDO, "undo")], tier_floor: [true, oneOf(...TIERS)],
    binds: [false, binds], other_args: [false, others],
  }, "action profile");
  undoRule(v.undo, "action profile");
  if (v.effect === "read" && v.undo.kind !== "none") throw new OACError("malformed", "action profile: a read declares undo none");
  const bound = Object.values(v.binds ?? {}) as string[];
  const other: string[] = v.other_args ?? [];
  if (new Set(bound).size !== bound.length || bound.some((a) => other.includes(a))) {
    throw new OACError("malformed", "action profile: an argument is declared twice");
  }
  const missing = (REQUIRED_BINDS[v.effect] ?? []).filter((f) => !has(v.binds ?? {}, f));
  if (missing.length) throw new OACError("malformed", `action profile: a ${v.effect} tool must bind ${missing[0]}`);
  return v;
}

/** Every argument is declared (bound or other_args); bound values are valid fields; pay/send carry their fields. */
export function checkAction(actionDoc: Record<string, any>, prof: Record<string, any>): void {
  const binds: Record<string, string> = prof.binds ?? {}, args = actionDoc.args;
  const declared = new Set([...Object.values(binds), ...(prof.other_args ?? [])]);
  const extra = Object.keys(args).filter((a) => !declared.has(a)).sort();
  if (extra.length) throw new OACError("undeclared_argument", `argument ${extra[0]} is not in the tool's profile`);
  for (const [field, arg] of Object.entries(binds)) {
    if (has(args, arg) && !PREVIEW_FIELDS[field](args[arg])) throw new OACError("malformed", `argument ${arg} is not a valid ${field}`);
  }
  for (const field of REQUIRED_BINDS[prof.effect] ?? []) {
    if (!has(args, binds[field])) throw new OACError("malformed", `a ${prof.effect} action needs ${binds[field]}`);
  }
}

export function action(v: any): Record<string, any> {
  check(v, { tool: [true, TOOL], args: [true, isObj] }, "action");
  return v;
}

export function preview(v: any): Record<string, any> {
  const fields: Check = (f) => isObj(f) && Object.entries(f).every(([k, x]) => has(PREVIEW_FIELDS, k) && PREVIEW_FIELDS[k](x));
  const evidence: Check = (e) => isObj(e) && Object.keys(e).length > 0 && obj({ screenshot: [false, DIGEST], dom: [false, DIGEST] }, "evidence")(e);
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("preview")], id: [true, ID], executor: [true, ID], sub: [true, ID],
    tool: [true, TOOL], action: [true, DIGEST], summary: [true, text(1, 500)], fields: [true, fields],
    details: [false, (d) => isObj(d) && Object.keys(d).every((k) => ARG(k))],
    undo: [true, obj(UNDO, "undo")],
    cancel_policy: [false, obj({ text: [true, strCp(1, 2000)], source: [false, strCp(1, 2048)] }, "cancel_policy")],
    evidence: [false, evidence], iat: [true, TIME], exp: [true, TIME],
  }, "preview");
  undoRule(v.undo, "preview");
  if (!(v.iat < v.exp && v.exp <= v.iat + PREVIEW_MAX_S)) throw new OACError("malformed", "preview: exp must be after iat and at most 15 minutes later");
  return v;
}

const PAYMENT: Fields = {
  rail: [true, oneOf(...RAILS)], ref: [true, strCp(1, 256)], amount_minor: [true, int(0)], currency: [true, CURRENCY], payee: [true, strCp(1, 200)],
};

export function consent(v: any): Record<string, any> {
  const item = obj({ preview: [true, DIGEST], action: [true, DIGEST] }, "item");
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("consent")], iss: [true, ID], sub: [true, ID], aud: [true, ID],
    jti: [true, NONCE], iat: [true, TIME], exp: [true, TIME], items: [true, list(item, 1, 20)],
    signer: [true, obj({ kind: [true, oneOf(...SIGNERS)] }, "signer")], payment: [false, obj(PAYMENT, "payment")],
  }, "consent");
  return v;
}

export function mandate(v: any): Record<string, any> {
  const calls: Fields = { per_day: [true, int(1, 10000)], per_run: [false, int(1, 1000)] };
  const amount: Fields = { currency: [true, CURRENCY], per_call_minor: [false, int(0)], per_day_minor: [false, int(0)] };
  const bounds: Fields = {
    calls: [true, obj(calls, "calls")],
    amount: [false, (a) => obj(amount, "amount")(a) && Object.keys(a).length >= 2],
    recipients: [false, list(ADDR, 1, 100)], payees: [false, list(strCp(1, 200), 1, 100)], sites: [false, list(HOST, 1, 100)],
  };
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("mandate")], id: [true, ID], iss: [true, ID], sub: [true, ID],
    holder: [true, obj({ type: [true, oneOf(...HOLDERS)], id: [true, ID] }, "holder")], goal: [true, strCp(1, 300)],
    tools: [true, list(TOOL, 1, 32)], bounds: [true, obj(bounds, "bounds")], iat: [true, TIME], exp: [true, TIME],
    signer: [true, obj({ kind: [true, oneOf(...SIGNERS)] }, "signer")], supersedes: [false, ID],
    status: [false, obj({ list: [true, ID], index: [true, int(0, 2 * 1024 * 1024 * 8 - 1)] }, "status")],
  }, "mandate");
  return v;
}

const JWK_FIELDS: Fields = {
  kty: [true, oneOf("OKP", "EC")], crv: [true, oneOf("Ed25519", "P-256")], x: [true, strCp(1, 64)], y: [false, strCp(1, 64)],
  kid: [false, strCp(1, 64)], alg: [false, oneOf("EdDSA", "ES256")], use: [false, constant("sig")],
};

export function statusList(v: any): Record<string, any> {
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("status-list")], iss: [true, ID], id: [true, ID],
    purpose: [true, constant("revocation")], encoded_list: [true, strCp(2, 4 * 1024 * 1024)], iat: [true, TIME], exp: [true, TIME],
  }, "status list");
  if (!(v.iat < v.exp && v.exp <= v.iat + 7 * 86400)) throw new OACError("malformed", "status list: exp must be after iat and at most 7 days later");
  return v;
}

export function issuerMetadata(v: any): Record<string, any> {
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("issuer-metadata")], issuer: [true, ID],
    keys: [true, list(obj(JWK_FIELDS, "jwk"), 1, 20)], status_lists: [false, list(ID, 1, 20)],
  }, "issuer metadata");
  return v;
}

export function seal(v: any): Record<string, any> {
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("seal")], iss: [true, ID], sub: [true, ID], executor: [true, ID],
    seq: [true, int(1)], head: [true, DIGEST], iat: [true, TIME],
  }, "seal");
  return v;
}

export function receipt(v: any): Record<string, any> {
  const authority: Fields = { kind: [true, oneOf(...AUTHORITIES)], ref: [false, strCp(1, 256)] };
  const undo: Fields = { kind: [true, oneOf(...UNDO_KINDS)], until: [false, TIME], token: [false, strCp(1, 512)] };
  const payment: Fields = { rail: [true, oneOf(...RAILS)], ref: [true, strCp(1, 256)], last4: [false, LAST4], order: [false, strCp(1, 256)] };
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("receipt")], iss: [true, ID], sub: [true, ID], seq: [true, int(1)],
    prev: [true, (p) => p === null || DIGEST(p)], iat: [true, TIME], tool: [true, TOOL], tier: [true, oneOf(...TIERS)],
    authority: [true, obj(authority, "authority")], action: [true, DIGEST], preview: [false, DIGEST],
    outcome: [true, oneOf("ok", "failed")], result: [true, DIGEST], undo: [true, obj(undo, "undo")],
    undoes: [false, DIGEST], payment: [false, obj(payment, "payment")],
  }, "receipt");
  return v;
}

/** What a mandate already did, from the executor's own counters (spec 7.3). */
export function usage(v: any): Record<string, number> {
  if (v === null || v === undefined) return {};
  check(v, { calls_today: [false, int(0)], calls_this_run: [false, int(0)], amount_today_minor: [false, int(0)] }, "usage");
  return v;
}

export function undoRequest(v: any): Record<string, any> {
  check(v, {
    oac: [true, constant(VERSION)], type: [true, constant("undo")], iss: [true, ID], sub: [true, ID], aud: [true, ID],
    jti: [true, NONCE], iat: [true, TIME], exp: [true, TIME], receipt: [true, DIGEST],
    mode: [true, oneOf("native", "compensate")], consent: [false, NONCE],
  }, "undo request");
  return v;
}
