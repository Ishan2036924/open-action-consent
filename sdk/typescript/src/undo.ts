// Undo requests (spec section 8.3): native restores prior state inside the window; compensate runs a new action that
// needs its own Consent, named here; none cannot be undone. Mirrors undo.py.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { KeySet, sign, tokenDigest, verify, type SigningKey } from "./jws.ts";
import { checkTime, MAX_S, newNonce, type NonceStore } from "./consent.ts";
import { checkSemantics, TYP as RECEIPT_TYP } from "./receipts.ts";

export const TYP = "oac-undo+jws";

export function makeUndo(o: {
  key: SigningKey; iss: string; sub: string; aud: string; receiptToken: string; mode: string; now: number; ttl?: number;
  jti?: string; consent?: string;
}): string {
  const doc: Record<string, any> = {
    oac: shapes.VERSION, type: "undo", iss: o.iss, sub: o.sub, aud: o.aud, jti: o.jti ?? newNonce(), iat: o.now,
    exp: o.now + (o.ttl ?? 300), receipt: tokenDigest(o.receiptToken), mode: o.mode,
  };
  if (o.consent !== undefined) doc.consent = o.consent;
  return sign(shapes.undoRequest(doc), o.key, TYP);
}

export function checkUndo(token: string, o: {
  keys: KeySet; executor: string; receiptToken: string; receiptKeys: KeySet; now: number; nonces: NonceStore;
}): Record<string, any> {
  const p = verify(token, o.keys, TYP);
  shapes.undoRequest(p);
  if (p.aud !== o.executor) throw new OACError("wrong_audience");
  checkTime(p, o.now, MAX_S);
  if (p.receipt !== tokenDigest(o.receiptToken)) throw new OACError("receipt_mismatch");
  const r = verify(o.receiptToken, o.receiptKeys, RECEIPT_TYP);
  shapes.receipt(r);
  checkSemantics(r);
  if (r.iss !== o.executor) throw new OACError("receipt_mismatch", "the receipt is another executor's");
  if (r.sub !== p.sub) throw new OACError("subject_mismatch");
  if (r.outcome !== "ok" || r.undo.kind === "none") throw new OACError("not_reversible");
  if (r.undo.kind !== p.mode) throw new OACError("undo_mode_mismatch");
  if (o.now > r.undo.until) throw new OACError("undo_window_closed");
  if (p.mode === "compensate" && !("consent" in p)) throw new OACError("malformed", "a compensating undo names the consent for its new action");
  if (o.nonces.seen(p.jti)) throw new OACError("replay");
  o.nonces.use(p.jti, p.exp);
  return p;
}
