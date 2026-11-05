// Undo requests (spec 8.3).

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { KeySet, sign, tokenDigest, verify, type SigningKey } from "./jws.ts";
import { checkTime, MAX_S, newNonce, type NonceStore } from "./consent.ts";
import { checkSemantics, TYP as RECEIPT_TYP } from "./receipts.ts";
import { actionDigest } from "./preview.ts";

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
  undone?: Iterable<string>; compensation?: { consent?: Record<string, any>; action?: Record<string, any> } | null;
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
  if (new Set(o.undone ?? []).has(p.receipt)) throw new OACError("already_undone");
  if (p.mode === "compensate") {
    if (!Object.hasOwn(p, "consent")) throw new OACError("malformed", "a compensating undo names the consent for its new action");
    const consent = o.compensation?.consent, act = o.compensation?.action;
    const isObj = (x: unknown): x is Record<string, any> => x !== null && typeof x === "object" && !Array.isArray(x);
    if (!isObj(consent) || !isObj(act) || consent.jti !== p.consent || consent.sub !== p.sub || !isObj(act.args)
      || act.args.undoes !== p.receipt || !(consent.items ?? []).map((i: any) => i.action).includes(actionDigest(act))) {
      throw new OACError("compensation_mismatch", "the compensating consent does not cover undoing this receipt");
    }
  }
  if (!o.nonces.useOnce(p.jti, p.exp)) throw new OACError("replay");
  return p;
}
