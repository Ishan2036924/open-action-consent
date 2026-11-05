// Fixed keys for tests and vectors. The seeds are public: never use them for anything real.

import * as crypto from "node:crypto";
import { ed25519FromSeed, p256FromSeed, type SigningKey } from "./jws.ts";

export function vectorKey(label: string, alg = "EdDSA"): SigningKey {
  const seed = crypto.createHash("sha256").update(`oac-v0.1 test key: ${label}`).digest();
  return alg === "EdDSA" ? ed25519FromSeed(seed) : p256FromSeed(seed);
}
