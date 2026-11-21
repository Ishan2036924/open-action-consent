// Observations and evidence verdicts (spec 8.5): what the decision was, and whether someone else saw the effect.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { KeySet, sign, tokenDigest, verify, type SigningKey } from "./jws.ts";
import { checkSemantics, independent, TYP as RECEIPT_TYP } from "./receipts.ts";
import { TYP as CONSENT_TYP } from "./consent.ts";
import { TYP as MANDATE_TYP } from "./mandate.ts";
import { TYP as UNDO_TYP } from "./undo.ts";

export const TYP = "oac-observation+jws";
// what each authority kind is signed as, and the check of its fields
const AUTHORITY: Record<string, [string, (v: any) => Record<string, any>]> = {
  consent: [CONSENT_TYP, shapes.consent], mandate: [MANDATE_TYP, shapes.mandate], undo: [UNDO_TYP, shapes.undoRequest],
};

/** A reader other than the executor says it saw (or did not see) the effect of this receipt. */
export function makeObservation(o: {
  key: SigningKey; iss: string; sub: string; executor: string; receiptToken: string; effect: string; now: number;
  subject?: string; route?: string; vantage?: string;
}): string {
  const doc: Record<string, any> = {
    oac: shapes.VERSION, type: "observation", iss: o.iss, sub: o.sub, executor: o.executor, receipt: tokenDigest(o.receiptToken),
    effect: o.effect, iat: o.now,
  };
  for (const k of ["subject", "route", "vantage"] as const) if (o[k] !== undefined) doc[k] = o[k];
  return sign(shapes.observation(doc), o.key, TYP);
}

function observed(r: Record<string, any>, token: string, observations: string[], keys: KeySet | null | undefined, executor: string): Record<string, any>[] {
  if (observations.length && !keys) throw new OACError("malformed", "observations need the observer's keys");
  return observations.map((t) => {
    const o = verify(t, keys!, TYP);
    shapes.observation(o);
    independent(o.iss, executor, "observer_not_independent");
    if (o.sub !== r.sub) throw new OACError("subject_mismatch");
    if (o.executor !== executor) throw new OACError("executor_mismatch");
    if (o.receipt !== tokenDigest(token)) throw new OACError("receipt_mismatch", "the observation is about another receipt");
    return o;
  });
}

function binds(r: Record<string, any>, p: Record<string, any>): boolean {
  const { kind, ref } = r.authority;
  if (kind === "consent") return p.jti === ref && p.items.some((i: any) => i.preview === r.preview && i.action === r.action);
  if (kind === "mandate") return p.id === ref;
  return p.jti === ref && p.receipt === r.undoes;
}

function decide(r: Record<string, any>, token: string | null | undefined, keys: KeySet | null | undefined): string {
  const a = r.authority;
  if (a.kind === "tier") return "tier";
  if (token === undefined || token === null) return "unverified";
  if (!keys) throw new OACError("malformed", "an authority token needs its signer's keys");
  if (tokenDigest(token) !== a.digest) throw new OACError("authority_mismatch", "this is not the token the receipt names");
  const [typ, check] = AUTHORITY[a.kind];
  if (!binds(r, check(verify(token, keys, typ)))) throw new OACError("authority_mismatch", "the token does not cover this action and preview");
  return "bound";
}

function effectOf(outcome: string, obs: Record<string, any>[]): string {
  const seen = obs.filter((o) => o.effect === "seen");
  if (new Set(seen.filter((o) => Object.hasOwn(o, "subject")).map((o) => o.subject)).size > 1) return "duplicate";
  if (seen.length) return outcome === "failed" ? "contradicted" : "observed";
  if (outcome === "failed") return "absent";
  return outcome === "ok" && obs.some((o) => o.effect === "not_seen") ? "not_observed" : "cannot_establish";
}

/** Route, decision and effect of one receipt as three separate answers, then a verdict (spec 8.5). */
export function assess(receiptToken: string, o: {
  keys: KeySet; executor: string; observations?: string[]; observerKeys?: KeySet | null; authorityToken?: string | null; authorityKeys?: KeySet | null;
}): Record<string, any> {
  const r = verify(receiptToken, o.keys, RECEIPT_TYP);
  shapes.receipt(r);
  checkSemantics(r);
  if (r.iss !== o.executor) throw new OACError("chain_issuer");
  const effect = effectOf(r.outcome, observed(r, receiptToken, o.observations ?? [], o.observerKeys, o.executor));
  const decision = decide(r, o.authorityToken, o.authorityKeys);
  let verdict = "cannot_establish";
  if (["not_observed", "contradicted", "duplicate"].includes(effect)) verdict = "fail";
  else if (decision !== "unverified" && ["observed", "absent"].includes(effect)) verdict = "pass";
  return { route: r.route ?? null, decision, effect, verdict };
}
