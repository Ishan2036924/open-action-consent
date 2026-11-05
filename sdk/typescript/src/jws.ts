// Keys, digests and the JWS envelope (RFC 7515 compact). Header = exactly {alg, kid, typ}, JCS-canonical; payload =
// JCS-canonical JSON; a token whose bytes are not the canonical form of what they parse to is refused.
// Algorithms: EdDSA (Ed25519, RFC 8037) and ES256 (P-256, raw r||s). kid = the RFC 7638 JWK thumbprint.

import * as crypto from "node:crypto";
import { OACError } from "./errors.ts";
import { canonical, canonicalBytes, parse, type Json } from "./jcs.ts";

export const ALGS = ["EdDSA", "ES256"];
export type Jwk = { kty: string; crv: string; x: string; y?: string; kid?: string };
export type SigningKey = { alg: string; private: crypto.KeyObject; jwk: Jwk & { kid: string } };

const B64URL = /^[A-Za-z0-9_-]*$/;
const enc = new TextEncoder();

export function b64url(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function b64urlDecode(text: string): Uint8Array {
  if (typeof text !== "string" || !B64URL.test(text) || text.length % 4 === 1) throw new OACError("malformed", "not base64url");
  const raw = Buffer.from(text, "base64url");
  if (b64url(raw) !== text) throw new OACError("malformed", "non-canonical base64url");
  return raw;
}

export function digestBytes(data: Uint8Array): string {
  return "sha-256:" + b64url(crypto.createHash("sha256").update(data).digest());
}

/** The digest of a JSON value: sha-256 over its JCS bytes. */
export function digest(value: unknown): string {
  return digestBytes(canonicalBytes(value));
}

export function thumbprint(jwk: Jwk): string {
  let members: Record<string, unknown>;
  if (jwk.kty === "OKP") members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  else if (jwk.kty === "EC") members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  else throw new OACError("malformed", "unsupported key type");
  return b64url(crypto.createHash("sha256").update(canonicalBytes(members)).digest());
}

function withKid(jwk: Jwk): Jwk & { kid: string } {
  return { ...jwk, kid: thumbprint(jwk) };
}

const ED25519_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export function ed25519FromSeed(seed: Uint8Array): SigningKey {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  const pub = crypto.createPublicKey(priv).export({ format: "jwk" }) as Jwk;
  return { alg: "EdDSA", private: priv, jwk: withKid({ kty: "OKP", crv: "Ed25519", x: pub.x }) };
}

export function p256FromSeed(seed: Uint8Array): SigningKey {
  const d = (BigInt("0x" + Buffer.from(seed).toString("hex")) % (P256_ORDER - 1n)) + 1n;
  const dBytes = Buffer.from(d.toString(16).padStart(64, "0"), "hex");
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(dBytes);
  const point = ecdh.getPublicKey(); // 04 || x || y
  const jwk = { kty: "EC", crv: "P-256", x: b64url(point.subarray(1, 33)), y: b64url(point.subarray(33, 65)) };
  const priv = crypto.createPrivateKey({ key: { ...jwk, d: b64url(dBytes) }, format: "jwk" });
  return { alg: "ES256", private: priv, jwk: withKid(jwk) };
}

export function generate(alg = "EdDSA"): SigningKey {
  if (alg === "EdDSA") return ed25519FromSeed(crypto.randomBytes(32));
  if (alg === "ES256") {
    const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pub = crypto.createPublicKey(privateKey).export({ format: "jwk" }) as Jwk;
    return { alg, private: privateKey, jwk: withKid({ kty: "EC", crv: "P-256", x: pub.x, y: pub.y }) };
  }
  throw new OACError("bad_alg", alg);
}

/** Public keys a verifier trusts for one role (a person's signer, or one executor), looked up by kid. */
export class KeySet {
  private keys = new Map<string, Jwk & { kid: string }>();
  constructor(jwks: Iterable<Jwk>) {
    for (const jwk of jwks) {
      const kid = thumbprint(jwk);
      if (jwk.kid !== undefined && jwk.kid !== kid) throw new OACError("malformed", "kid is not the key's thumbprint");
      this.keys.set(kid, { ...jwk, kid });
    }
  }
  get(kid: string): (Jwk & { kid: string }) | undefined {
    return this.keys.get(kid);
  }
}

export function sign(payload: Record<string, unknown>, key: SigningKey, typ: string): string {
  const header = { alg: key.alg, kid: key.jwk.kid, typ };
  const input = b64url(canonicalBytes(header)) + "." + b64url(canonicalBytes(payload));
  const sig = key.alg === "EdDSA"
    ? crypto.sign(null, enc.encode(input), key.private)
    : crypto.sign("sha256", enc.encode(input), { key: key.private, dsaEncoding: "ieee-p1363" });
  return input + "." + b64url(sig);
}

function checkSig(jwk: Jwk, alg: string, data: Uint8Array, sig: Uint8Array): void {
  let ok: boolean;
  try {
    if (alg === "EdDSA") {
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new OACError("bad_alg", "key is not Ed25519");
      const pub = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
      ok = crypto.verify(null, data, pub, sig);
    } else {
      if (jwk.kty !== "EC" || jwk.crv !== "P-256") throw new OACError("bad_alg", "key is not P-256");
      if (sig.length !== 64) throw new OACError("bad_signature", "ES256 signature must be 64 bytes");
      const pub = crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
      ok = crypto.verify("sha256", data, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
    }
  } catch (e) {
    if (e instanceof OACError) throw e;
    throw new OACError("bad_signature", "invalid key or signature encoding");
  }
  if (!ok) throw new OACError("bad_signature");
}

function canonicalPart(part: string): Json {
  const raw = b64urlDecode(part);
  const value = parse(raw);
  if (Buffer.compare(Buffer.from(canonicalBytes(value)), Buffer.from(raw)) !== 0) throw new OACError("not_canonical");
  return value;
}

/** Check the envelope and signature; return the payload. Field checks are the caller's. */
export function verify(token: string, keys: KeySet, typ: string): Record<string, any> {
  if (typeof token !== "string") throw new OACError("malformed", "token must be a string");
  const parts = token.split(".");
  if (parts.length !== 3) throw new OACError("malformed", "a compact JWS has three parts");
  const header = canonicalPart(parts[0]) as Record<string, any>;
  if (header === null || typeof header !== "object" || Array.isArray(header) || canonical(Object.keys(header).sort()) !== '["alg","kid","typ"]') {
    throw new OACError("malformed", "header must be exactly alg, kid, typ");
  }
  if (header.typ !== typ) throw new OACError("bad_type", `expected ${typ}`);
  if (!ALGS.includes(header.alg)) throw new OACError("bad_alg", String(header.alg));
  const jwk = typeof header.kid === "string" ? keys.get(header.kid) : undefined;
  if (jwk === undefined) throw new OACError("unknown_key");
  checkSig(jwk, header.alg, enc.encode(parts[0] + "." + parts[1]), b64urlDecode(parts[2]));
  const payload = canonicalPart(parts[1]);
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) throw new OACError("malformed", "payload must be an object");
  return payload as Record<string, any>;
}

/** The digest a later object uses to name a signed token (receipt chains, undo requests). */
export function tokenDigest(token: string): string {
  return digestBytes(enc.encode(token));
}
