// Receipts (spec 8): the executor's signed record of each action, chained per person.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { KeySet, sign, tokenDigest, verify, type SigningKey } from "./jws.ts";

export const TYP = "oac-receipt+jws";
export const SEAL_TYP = "oac-seal+jws";

/** The person's signer vouches that this person's chain at `executor` reached `seq` with this receipt. */
export function makeSeal(o: { key: SigningKey; iss: string; sub: string; executor: string; seq: number; headToken: string; now: number }): string {
  const doc = { oac: shapes.VERSION, type: "seal", iss: o.iss, sub: o.sub, executor: o.executor, seq: o.seq, head: tokenDigest(o.headToken), iat: o.now };
  return sign(shapes.seal(doc), o.key, SEAL_TYP);
}

export function makeReceipt(key: SigningKey, payload: Record<string, any>): string {
  const doc = { oac: shapes.VERSION, type: "receipt", ...payload };
  checkSemantics(shapes.receipt(doc));
  return sign(doc, key, TYP);
}

export function checkSemantics(r: Record<string, any>): void {
  const tier = r.tier, kind = r.authority.kind, undo = r.undo;
  if (tier === "D") throw new OACError("receipt_invalid", "a tier D action never runs");
  for (const name of ["ref", "digest"]) {
    if ((kind !== "tier") !== Object.hasOwn(r.authority, name)) {
      throw new OACError("receipt_invalid", `consent, mandate and undo authority carry a ${name}; tier carries none`);
    }
  }
  if (kind === "tier" && tier !== "A" && tier !== "B") throw new OACError("receipt_invalid", "tier C needs a consent, mandate or undo authority");
  if (undo.kind === "none" && ("until" in undo || "token" in undo)) throw new OACError("receipt_invalid", "undo none carries no window or token");
  if (undo.kind !== "none" && r.outcome === "ok" && !("until" in undo)) throw new OACError("receipt_invalid", "a reversible action says until when");
  if (tier === "B" && kind !== "undo" && r.outcome === "ok" && (undo.kind !== "native" || !("token" in undo))) {
    throw new OACError("receipt_invalid", "tier B needs a native undo token");
  }
  if (kind === "undo" && !("undoes" in r)) throw new OACError("receipt_invalid", "an undo receipt names what it undoes");
}

export function verifyChain(tokens: string[], o: { keys: KeySet; executor: string; sub?: string | null; seals?: string[]; sealKeys?: KeySet | null }): Record<string, any>[] {
  const out: Record<string, any>[] = [];
  const done = new Set<string>();
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
    if (Object.hasOwn(r, "occurrence") && r.outcome === "ok") {
      const key = JSON.stringify([r.tool, r.occurrence]);
      if (done.has(key)) throw new OACError("duplicate_occurrence", "the same occurrence ran twice");
      done.add(key);
    }
    out.push(r);
  });
  if (o.seals && o.seals.length) {
    if (!o.sealKeys) throw new OACError("malformed", "seals need the signer's keys");
    const bySeq = new Map(out.map((r, i) => [r.seq, tokens[i]]));
    for (const token of o.seals) {
      const s = verify(token, o.sealKeys, SEAL_TYP);
      shapes.seal(s);
      if (out.length && s.sub !== out[0].sub) throw new OACError("subject_mismatch");
      if (s.executor !== o.executor || !bySeq.has(s.seq) || s.head !== tokenDigest(bySeq.get(s.seq)!)) {
        throw new OACError("seal_mismatch", "the seal does not match this chain");
      }
    }
  }
  return out;
}
