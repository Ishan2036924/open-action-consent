// Fixed keys for tests and vectors. The seeds are public: never use them for anything real.

import * as crypto from "node:crypto";
import { b64url, ed25519FromSeed, p256FromSeed, tokenDigest, type SigningKey } from "./jws.ts";
import { VERSION } from "./shapes.ts";
import { challenge, USER_PRESENT, USER_VERIFIED } from "./webauthn.ts";

export function vectorKey(label: string, alg = "EdDSA"): SigningKey {
  const seed = crypto.createHash("sha256").update(`oac-v0.1 test key: ${label}`).digest();
  return alg === "EdDSA" ? ed25519FromSeed(seed) : p256FromSeed(seed);
}

/** A fake passkey assertion over a Consent. The options plant defects. */
export function passkeyProof(consentToken: string, key: SigningKey, o: {
  credential?: string; rpId?: string; origin?: string; flags?: number; challengeFor?: string; type?: string;
} = {}): Record<string, any> {
  const flags = o.flags ?? (USER_PRESENT | USER_VERIFIED);
  const auth = Buffer.concat([crypto.createHash("sha256").update(o.rpId ?? "app.example").digest(), Buffer.from([flags, 0, 0, 0, 0])]);
  const client = Buffer.from(JSON.stringify({ type: o.type ?? "webauthn.get", challenge: challenge(o.challengeFor ?? consentToken),
    origin: o.origin ?? "https://app.example", crossOrigin: false }));
  const sig = crypto.sign("sha256", Buffer.concat([auth, crypto.createHash("sha256").update(client).digest()]), { key: key.private, dsaEncoding: "der" });
  return { oac: VERSION, type: "device-proof", consent: tokenDigest(consentToken), credential: o.credential ?? "cred-1",
    authenticator_data: b64url(auth), client_data_json: b64url(client), signature: b64url(sig) };
}
