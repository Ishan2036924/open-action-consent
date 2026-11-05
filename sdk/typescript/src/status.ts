// Status lists (spec 7.5): which Mandates a signer revoked, as a W3C bitstring.

import * as zlib from "node:zlib";
import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { b64url, b64urlDecode, KeySet, sign, verify, type SigningKey } from "./jws.ts";

export const TYP = "oac-status+jws";
export const MIN_BYTES = 16 * 1024;
export const MAX_BYTES = 2 * 1024 * 1024;

function gunzipOne(raw: Buffer): Buffer {
  const bad = (why: string): never => { throw new OACError("malformed", why); };
  if (raw.length < 18 || raw[0] !== 0x1f || raw[1] !== 0x8b || raw[2] !== 8) bad("status list is not gzip");
  const flg = raw[3];
  if (flg & 0xe0) bad("status list is not gzip");
  let p = 10;
  if (flg & 4) { if (p + 2 > raw.length) bad("status list is not gzip"); p += 2 + raw.readUInt16LE(p); }
  for (const f of [8, 16]) if (flg & f) { while (p < raw.length && raw[p] !== 0) p++; p++; }
  if (flg & 2) p += 2;
  if (p > raw.length - 8) bad("status list is not gzip");
  let out: Buffer, used: number;
  try {
    const r = zlib.inflateRawSync(raw.subarray(p), { maxOutputLength: MAX_BYTES, info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    out = r.buffer; used = r.engine.bytesWritten;
  } catch {
    return bad("status list too large or not gzip");
  }
  const trailer = raw.subarray(p + used);
  if (trailer.length !== 8) bad("data after the gzip member");
  if (trailer.readUInt32LE(0) !== zlib.crc32(out) || trailer.readUInt32LE(4) !== (out.length >>> 0)) bad("status list is not gzip");
  return out;
}

export function encode(revoked: Iterable<number>, sizeBytes = MIN_BYTES): string {
  const bits = Buffer.alloc(sizeBytes);
  for (const i of revoked) {
    if (!(Number.isSafeInteger(i) && i >= 0 && i < sizeBytes * 8)) throw new OACError("malformed", "index outside the list");
    bits[i >> 3] |= 0x80 >> (i % 8);
  }
  return "u" + b64url(zlib.gzipSync(bits));
}

export function decode(encoded: string): Buffer {
  if (typeof encoded !== "string" || !encoded.startsWith("u")) throw new OACError("malformed", "encoded list must be multibase base64url (prefix u)");
  const out = gunzipOne(Buffer.from(b64urlDecode(encoded.slice(1))));
  if (out.length < MIN_BYTES) throw new OACError("malformed", "status list shorter than 16 KB");
  return out;
}

export function bit(bits: Buffer, index: number): boolean {
  if (!(Number.isSafeInteger(index) && index >= 0 && index < bits.length * 8)) throw new OACError("malformed", "status index outside the list");
  return (bits[index >> 3] & (0x80 >> (index % 8))) !== 0;
}

export function makeStatusList(o: { key: SigningKey; iss: string; listId: string; revoked: Iterable<number>; now: number; ttl?: number; sizeBytes?: number }): string {
  const doc = { oac: shapes.VERSION, type: "status-list", iss: o.iss, id: o.listId, purpose: "revocation",
    encoded_list: encode(o.revoked, o.sizeBytes), iat: o.now, exp: o.now + (o.ttl ?? 3600) };
  return sign(shapes.statusList(doc), o.key, TYP);
}

export function isRevoked(mandate: Record<string, any>, o: { lists: Record<string, string>; keys: KeySet; now: number }): boolean {
  const entry = mandate.status;
  if (entry === undefined) return false;
  const token = Object.hasOwn(o.lists, entry.list) ? o.lists[entry.list] : undefined;
  if (token === undefined) throw new OACError("status_unknown", "the mandate's status list is not available");
  const s = verify(token, o.keys, TYP);
  shapes.statusList(s);
  if (s.id !== entry.list || s.iss !== mandate.iss) throw new OACError("status_unknown", "the status list is not this mandate's");
  if (!(s.iat <= o.now && o.now < s.exp)) throw new OACError("status_unknown", "the status list is stale");
  return bit(decode(s.encoded_list), entry.index);
}
