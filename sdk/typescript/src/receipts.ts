// Receipts (spec 8): the executor's signed record of each action, chained per person.

import { scope } from "./occurrence.ts";
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
    if (Object.hasOwn(r, "occurrence") && r.outcome === "ok" && r.authority.kind !== "undo") {
      const key = JSON.stringify([scope(r), r.occurrence]);
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

/** A witness of the executor must not be the executor (spec 8.4, 8.5). */
export function independent(iss: string, executor: string, code: string): void {
  if (iss === executor) throw new OACError(code, "the executor cannot vouch for itself");
}

/** Check a head claimed at `seq` against the export. True when the export reaches back to it. */
function place(chain: Record<string, any>[], tokens: string[], seq: number, head: string | null | undefined): boolean {
  if (!chain.length || seq > chain[chain.length - 1].seq) throw new OACError("chain_truncated", `the export ends before seq ${seq}`);
  const first = chain[0].seq;
  if (seq < first - 1) return false;
  const want = seq === first - 1 ? chain[0].prev : tokenDigest(tokens[seq - first]);
  if (head !== undefined && head !== null && head !== want) throw new OACError("seal_mismatch", `the head at seq ${seq} is not the one claimed`);
  return true;
}

/** verifyChain, then say how much of the export is proven complete by anchors the executor does not hold (spec 8.4). */
export function verifyExport(tokens: string[], o: {
  keys: KeySet; executor: string; sub?: string | null; anchors?: string[]; anchorKeys?: KeySet | null; expect?: Record<string, any> | null;
}): Record<string, any> {
  const chain = verifyChain(tokens, { keys: o.keys, executor: o.executor, sub: o.sub });
  const first = chain.length ? chain[0].seq : null, last = chain.length ? chain[chain.length - 1].seq : null;
  if (o.anchors?.length && !o.anchorKeys) throw new OACError("malformed", "anchors need the signer's keys");
  let proven: number | null = null, start = first === 1;
  for (const token of o.anchors ?? []) {
    const a = verify(token, o.anchorKeys!, SEAL_TYP);
    shapes.seal(a);
    independent(a.iss, o.executor, "anchor_not_independent");
    if ((o.sub || (chain.length ? chain[0].sub : a.sub)) !== a.sub) throw new OACError("subject_mismatch");
    if (a.executor !== o.executor) throw new OACError("seal_mismatch", "the anchor is for another executor");
    if (place(chain, tokens, a.seq, a.head)) {
      start = start || a.seq === first - 1;
      proven = Math.max(proven ?? 0, a.seq);
    }
  }
  if (o.expect !== undefined && o.expect !== null) {
    shapes.expectation(o.expect);
    place(chain, tokens, o.expect.seq, o.expect.head);
  }
  const complete = proven !== null && proven === last && start;
  const reason = complete ? null : proven === null ? "no_anchor" : proven < last! ? "unanchored_tail" : "unanchored_start";
  return { first, last, proven_to: proven, status: complete ? "complete" : "prefix", reason };
}
