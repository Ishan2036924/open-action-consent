// Device proofs (spec 3.6): a WebAuthn assertion from the person's passkey over one exact Consent token.

import * as crypto from "node:crypto";
import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { parse } from "./jcs.ts";
import { b64url, b64urlDecode, tokenDigest, type Jwk } from "./jws.ts";

export const USER_PRESENT = 0x01, USER_VERIFIED = 0x04;

/** Set by an executor that requires a passkey: the proof it got, the person's credentials (id -> public JWK),
 * its relying party id, and the origins its approval page runs on. */
export type DeviceCheck = { proof: Record<string, any> | null; credentials: Record<string, Jwk>; rp_id: string; origins: string[] };

/** The WebAuthn challenge for a Consent: SHA-256 of the token's ASCII bytes, base64url. */
export const challenge = (consentToken: string) => b64url(crypto.createHash("sha256").update(consentToken, "ascii").digest());

function verifyEs256Der(jwk: Jwk, data: Uint8Array, sig: Uint8Array): void {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") throw new OACError("bad_alg", "a credential key is P-256");
  let ok = false;
  try {
    const pub = crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
    ok = crypto.verify("sha256", data, { key: pub, dsaEncoding: "der" }, sig);
  } catch {
    ok = false;
  }
  if (!ok) throw new OACError("bad_signature");
}

export function verifyDeviceProof(consentToken: string, check: DeviceCheck): void {
  const proof = check.proof;
  if (proof === null || proof === undefined) throw new OACError("device_proof_missing");
  shapes.deviceProof(proof);
  if (proof.consent !== tokenDigest(consentToken)) throw new OACError("device_proof_mismatch", "the proof is for another consent");
  const jwk = Object.hasOwn(check.credentials, proof.credential) ? check.credentials[proof.credential] : undefined;
  if (jwk === undefined) throw new OACError("unknown_credential");
  const auth = b64urlDecode(proof.authenticator_data), client = b64urlDecode(proof.client_data_json);
  if (auth.length < 37) throw new OACError("malformed", "authenticator data is too short");
  const clientHash = crypto.createHash("sha256").update(client).digest();
  verifyEs256Der(jwk, Buffer.concat([auth, clientHash]), b64urlDecode(proof.signature));
  const data = parse(client) as Record<string, any>;
  if (data === null || typeof data !== "object" || Array.isArray(data) || data.type !== "webauthn.get") {
    throw new OACError("malformed", "client data is not an assertion");
  }
  if (data.challenge !== challenge(consentToken)) throw new OACError("challenge_mismatch");
  if (!check.origins.includes(data.origin) || data.crossOrigin === true) throw new OACError("wrong_origin");
  const rpHash = crypto.createHash("sha256").update(check.rp_id).digest();
  if (!Buffer.from(auth.subarray(0, 32)).equals(rpHash)) throw new OACError("rp_mismatch");
  if (!(auth[32] & USER_PRESENT)) throw new OACError("user_not_present");
  if (!(auth[32] & USER_VERIFIED)) throw new OACError("user_not_verified");
}
