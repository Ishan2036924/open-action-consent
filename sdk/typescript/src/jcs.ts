// RFC 8785 (JCS) canonical JSON for the OAC subset, plus a strict parser. OAC carries integers only (money in minor
// units, time in unix seconds), so JCS reduces to: keys sorted by UTF-16 code units (JavaScript's default sort),
// no whitespace, strings as JSON.stringify writes them, integers in plain decimal within +-(2^53 - 1).

import { OACError } from "./errors.ts";

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export const MAX_DEPTH = 64; // arrays and objects nested deeper than this are refused

function str(s: string): string {
  if (!s.isWellFormed()) throw new OACError("malformed", "string is not valid Unicode");
  return JSON.stringify(s);
}

export function canonical(v: unknown, depth = 0): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new OACError("malformed", "non-integer numbers are not allowed");
    if (!Number.isSafeInteger(v)) throw new OACError("malformed", "integer out of the safe range");
    return String(v === 0 ? 0 : v);
  }
  if (typeof v === "string") return str(v);
  if (typeof v === "object" && depth >= MAX_DEPTH) throw new OACError("malformed", "nested too deeply");
  if (Array.isArray(v)) return "[" + v.map((x) => canonical(x, depth + 1)).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).map((k) => [k, str(k)] as const); // Unicode check before sorting
    return "{" + keys.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([k, s]) => s + ":" + canonical(o[k], depth + 1)).join(",") + "}";
  }
  throw new OACError("malformed", `type ${typeof v} cannot be canonicalized`);
}

export function canonicalBytes(v: unknown): Uint8Array {
  return new TextEncoder().encode(canonical(v));
}

const WS = new Set([" ", "\t", "\n", "\r"]);
const ESC: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/** Parse JSON strictly: no duplicate keys, no fractions or exponents, no NaN, integers in the safe range. */
export function parse(input: string | Uint8Array): Json {
  let text: string;
  try {
    text = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
  } catch {
    throw new OACError("malformed", "not UTF-8");
  }
  let i = 0, depth = 0;
  const bad = (why: string): never => { throw new OACError("malformed", why); };
  const ws = () => { while (i < text.length && WS.has(text[i])) i++; };
  const value = (): Json => {
    ws();
    const c = text[i];
    if (c === "{" || c === "[") {
      depth++;
      if (depth > MAX_DEPTH) bad("nested too deeply");
    }
    if (c === "{") {
      i++;
      const entries: [string, Json][] = [];
      const seen = new Set<string>();
      ws();
      if (text[i] === "}") { i++; depth--; return Object.fromEntries(entries); }
      for (;;) {
        ws();
        if (text[i] !== '"') bad("expected a key");
        const k = string();
        if (seen.has(k)) bad(`duplicate key ${k}`);
        seen.add(k);
        ws();
        if (text[i++] !== ":") bad("expected :");
        entries.push([k, value()]);
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; depth--; return Object.fromEntries(entries); }
        bad("expected , or }");
      }
    }
    if (c === "[") {
      i++;
      const out: Json[] = [];
      ws();
      if (text[i] === "]") { i++; depth--; return out; }
      for (;;) {
        out.push(value());
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; depth--; return out; }
        bad("expected , or ]");
      }
    }
    if (c === '"') return string();
    for (const [word, val] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(word, i)) { i += word.length; return val; }
    }
    const m = /^-?(0|[1-9][0-9]*)/.exec(text.slice(i));
    if (!m) return bad("not JSON");
    i += m[0].length;
    if (i < text.length && ".eE".includes(text[i])) bad("non-integer numbers are not allowed");
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) bad("integer out of the safe range");
    return n;
  };
  const string = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) bad("unterminated string");
      const c = text[i++];
      if (c === '"') return out;
      if (c < " ") bad("control character in string");
      if (c !== "\\") { out += c; continue; }
      const e = text[i++];
      if (e === "u") {
        const hex = text.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) bad("bad \\u escape");
        out += String.fromCharCode(parseInt(hex, 16));
        i += 4;
      } else if (e in ESC) out += ESC[e];
      else bad("bad escape");
    }
  };
  const v = value();
  ws();
  if (i !== text.length) bad("trailing characters");
  canonical(v); // Unicode check
  return v;
}
