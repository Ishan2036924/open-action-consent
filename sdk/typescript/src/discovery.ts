// Issuer metadata (spec section 3.5): for issuer https://host/path the document is at
// https://host/.well-known/oac-issuer/path (the RFC 8414 pattern) and its `issuer` must equal the issuer exactly.
// `keysetFrom` turns documents you already have into a KeySet; `fetchMetadata` is a small, strict HTTPS fetcher.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { parse } from "./jcs.ts";
import { KeySet, type Jwk } from "./jws.ts";

export const MAX_DOC = 64 * 1024;

// Matched as text, same pattern as discovery.py, so every language agrees (no URL parser normalizing ports or IDNs).
const LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
const ISSUER = new RegExp(`^https://(${LABEL}(\\.${LABEL})*)(:[0-9]{1,5})?((/(?!\\.\\.?(/|$))[A-Za-z0-9._~-]+)*)/?$`);

export function metadataUrl(iss: string): string {
  const m = typeof iss === "string" ? ISSUER.exec(iss) : null;
  if (m === null) throw new OACError("malformed", "an issuer is https://host[:port][/path] in lowercase ASCII, without query or fragment");
  return `https://${m[1]}${m[5] ?? ""}/.well-known/oac-issuer${m[6]}`;
}

export function keysetFrom(docs: [string, Record<string, any>][]): KeySet {
  const grouped: Record<string, Jwk[]> = {};
  for (const [iss, doc] of docs) {
    metadataUrl(iss);
    shapes.issuerMetadata(doc);
    if (doc.issuer !== iss) throw new OACError("wrong_issuer", "the metadata names another issuer");
    (grouped[iss] ??= []).push(...doc.keys);
  }
  return new KeySet(grouped);
}

export async function fetchMetadata(iss: string, get?: (url: string) => Promise<Uint8Array>): Promise<Record<string, any>> {
  const fetcher = get ?? (async (url: string) => {
    const r = await fetch(url, { redirect: "error", headers: { accept: "application/json" }, signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new OACError("malformed", `issuer metadata: HTTP ${r.status}`);
    const body = new Uint8Array(await r.arrayBuffer());
    if (body.length > MAX_DOC) throw new OACError("malformed", "issuer metadata too large");
    return body;
  });
  const doc = parse(await fetcher(metadataUrl(iss))) as Record<string, any>;
  shapes.issuerMetadata(doc);
  if (doc.issuer !== iss) throw new OACError("wrong_issuer", "the metadata names another issuer");
  return doc;
}
