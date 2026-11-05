// Receipts (spec section 8): the executor's signed record of each action, chained per person. prev = digest of the
// previous receipt's whole token, so a dropped, reordered or edited receipt breaks the chain. Mirrors receipts.py.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { KeySet, sign, tokenDigest, verify, type SigningKey } from "./jws.ts";

export const TYP = "oac-receipt+jws";

export function makeReceipt(key: SigningKey, payload: Record<string, any>): string {
  const doc = { oac: shapes.VERSION, type: "receipt", ...payload };
  checkSemantics(shapes.receipt(doc));
  return sign(doc, key, TYP);
}

export function checkSemantics(r: Record<string, any>): void {
  const tier = r.tier, kind = r.authority.kind, undo = r.undo;
  if (tier === "D") throw new OACError("receipt_invalid", "a tier D action never runs");
  if (kind !== "tier" && !("ref" in r.authority)) throw new OACError("receipt_invalid", "authority needs a ref");
  if (kind === "tier" && tier !== "A" && tier !== "B") throw new OACError("receipt_invalid", "tier C needs a consent, mandate or undo authority");
  if (undo.kind === "none" && ("until" in undo || "token" in undo)) throw new OACError("receipt_invalid", "undo none carries no window or token");
  if (undo.kind !== "none" && r.outcome === "ok" && !("until" in undo)) throw new OACError("receipt_invalid", "a reversible action says until when");
  if (tier === "B" && kind !== "undo" && r.outcome === "ok" && (undo.kind !== "native" || !("token" in undo))) {
    throw new OACError("receipt_invalid", "tier B needs a native undo token");
  }
  if (kind === "undo" && !("undoes" in r)) throw new OACError("receipt_invalid", "an undo receipt names what it undoes");
}

export function verifyChain(tokens: string[], o: { keys: KeySet; executor: string; sub?: string | null }): Record<string, any>[] {
  const out: Record<string, any>[] = [];
  tokens.forEach((token, i) => {
    const r = verify(token, o.keys, TYP);
    shapes.receipt(r);
    checkSemantics(r);
    if (r.iss !== o.executor) throw new OACError("chain_issuer");
    if ((o.sub || (out.length ? out[0].sub : r.sub)) !== r.sub) throw new OACError("subject_mismatch");
    if (i === 0) {
      if ((r.seq === 1) !== (r.prev === null)) throw new OACError("chain_broken", "only seq 1 has no prev");
    } else {
      if (r.seq !== out[out.length - 1].seq + 1) throw new OACError("chain_seq");
      if (r.prev !== tokenDigest(tokens[i - 1])) throw new OACError("chain_broken");
    }
    out.push(r);
  });
  return out;
}
