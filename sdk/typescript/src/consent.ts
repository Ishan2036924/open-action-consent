// Consent (spec section 6): the person's signed yes to one or more Previews. Checks run in the spec's order; the
// first failure is the one reported. Mirrors consent.py.

import * as crypto from "node:crypto";
import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { digest, KeySet, sign, verify, type SigningKey } from "./jws.ts";
import { actionDigest, checkBinding } from "./preview.ts";
import { tierFor } from "./tiers.ts";
import { verifyDeviceProof, type DeviceCheck } from "./webauthn.ts";

export const TYP = "oac-consent+jws";
export const MAX_S = 900;
export const SKEW_S = 60;

/** Record jti until exp and return true, or return false if already recorded. Must be atomic (insert-if-absent). */
export interface NonceStore { useOnce(jti: string, exp: number): boolean }

export class MemoryNonces implements NonceStore {
  private s = new Map<string, number>();
  constructor(seen: Iterable<string> = []) { for (const j of seen) this.s.set(j, 0); }
  useOnce(jti: string, exp: number): boolean { // single-threaded JS: check-and-set cannot interleave
    if (this.s.has(jti)) return false;
    this.s.set(jti, exp);
    return true;
  }
}

export const newNonce = () => crypto.randomBytes(18).toString("base64url");

export function makeConsent(o: {
  key: SigningKey; iss: string; sub: string; aud: string; previews: Record<string, any>[]; now: number; ttl?: number;
  jti?: string; signerKind?: string; payment?: Record<string, any>;
}): string {
  const payload: Record<string, any> = {
    oac: shapes.VERSION, type: "consent", iss: o.iss, sub: o.sub, aud: o.aud, jti: o.jti ?? newNonce(), iat: o.now,
    exp: o.now + (o.ttl ?? 300), items: o.previews.map((p) => ({ preview: digest(p), action: p.action })),
    signer: { kind: o.signerKind ?? "custodial" },
  };
  if (o.payment) payload.payment = { ...o.payment };
  return sign(shapes.consent(payload), o.key, TYP);
}

export function checkTime(p: Record<string, any>, now: number, maxS: number): void {
  if (p.iat > now + SKEW_S) throw new OACError("not_yet_valid");
  if (now >= p.exp) throw new OACError("expired");
  if (p.exp - p.iat > maxS || p.exp <= p.iat) throw new OACError("lifetime_too_long");
}

function payment(p: Record<string, any>, preview: Record<string, any>): void {
  const pay = p.payment;
  if (pay === undefined) throw new OACError("payment_missing", "a pay action needs consent.payment");
  for (const name of ["amount_minor", "currency", "payee"]) {
    if (preview.fields[name] !== pay[name]) throw new OACError("payment_mismatch", `payment ${name} differs from the preview`);
  }
}

export function verifyConsent(token: string, o: {
  keys: KeySet; executor: string; sub: string; previews: Record<string, any>[]; actions: Record<string, any>[];
  profiles: Record<string, Record<string, any>>; now: number; nonces: NonceStore; policyFloor?: string; tainted?: boolean;
  device?: DeviceCheck;
}): Record<string, any> {
  const p = verify(token, o.keys, TYP);
  shapes.consent(p);
  if (p.aud !== o.executor) throw new OACError("wrong_audience");
  if (p.sub !== o.sub) throw new OACError("subject_mismatch", "the consent is another person's");
  checkTime(p, o.now, MAX_S);
  if (p.items.length !== o.previews.length || o.previews.length !== o.actions.length) {
    throw new OACError("preview_mismatch", "one preview and one action per item");
  }
  let pays = 0;
  p.items.forEach((item: Record<string, any>, i: number) => {
    const preview = o.previews[i], action = o.actions[i];
    shapes.preview(preview);
    if (digest(preview) !== item.preview) throw new OACError("preview_mismatch");
    if (preview.action !== item.action || actionDigest(action) !== item.action) throw new OACError("action_mismatch");
    if (preview.sub !== p.sub) throw new OACError("subject_mismatch");
    if (preview.executor !== o.executor) throw new OACError("executor_mismatch");
    if (o.now >= preview.exp) throw new OACError("preview_expired");
    const profile = Object.hasOwn(o.profiles, action.tool) ? o.profiles[action.tool] : undefined;
    if (profile === undefined) throw new OACError("unknown_tool");
    shapes.profile(profile);
    checkBinding(preview, action, profile);
    if (tierFor(profile, { policyFloor: o.policyFloor, tainted: o.tainted }) === "D") throw new OACError("tier_d");
    if (profile.effect === "pay") {
      pays += 1;
      if (pays > 1) throw new OACError("malformed", "one payment per consent");
      payment(p, preview);
    }
  });
  if (pays === 0 && Object.hasOwn(p, "payment")) throw new OACError("payment_mismatch", "payment given but no item pays");
  if (o.device) verifyDeviceProof(token, o.device);
  if (!o.nonces.useOnce(p.jti, p.exp)) throw new OACError("replay");
  return p;
}
