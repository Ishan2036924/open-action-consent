// Mandates (spec section 7): standing, bounded, expiring permission. Covers tier C only; never tier D; never waives
// the taint floor; a pay tool needs caps and a payee list. Mirrors mandate.py, check for check.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { canonical } from "./jcs.ts";
import { KeySet, sign, verify, type SigningKey } from "./jws.ts";
import { checkTime } from "./consent.ts";
import { tierFor } from "./tiers.ts";

export const TYP = "oac-mandate+jws";
export const MAX_S = 30 * 86400;

export function makeMandate(key: SigningKey, payload: Record<string, any>): string {
  return sign(shapes.mandate({ oac: shapes.VERSION, type: "mandate", ...payload }), key, TYP);
}

function recipientOk(addr: string, allowed: string[]): boolean {
  const a = addr.toLowerCase();
  if (!a.includes("@")) return false;
  const domain = a.slice(a.lastIndexOf("@") + 1);
  return allowed.some((rule) => { const r = rule.toLowerCase(); return r === a || (r.startsWith("@") && r.slice(1) === domain); });
}

export type Usage = { calls_today?: number; calls_this_run?: number; amount_today_minor?: number };

export function checkMandate(token: string, o: {
  keys: KeySet; action: Record<string, any>; profile: Record<string, any>; holder: Record<string, any>; sub: string;
  now: number; tainted: boolean; usage?: Usage | null; revoked?: Iterable<string>; policyFloor?: string;
}): Record<string, any> {
  const p = verify(token, o.keys, TYP);
  shapes.mandate(p);
  if (canonical(p.holder) !== canonical(o.holder)) throw new OACError("holder_mismatch");
  if (p.sub !== o.sub) throw new OACError("subject_mismatch", "the mandate is another person's");
  if (new Set(o.revoked ?? []).has(p.id)) throw new OACError("revoked");
  checkTime(p, o.now, MAX_S);
  shapes.action(o.action);
  const { action, profile } = o;
  if (!p.tools.includes(action.tool) || action.tool !== profile.tool) throw new OACError("tool_not_covered");
  shapes.profile(profile);
  if (tierFor(profile, { policyFloor: o.policyFloor }) === "D") throw new OACError("tier_d");
  if (o.tainted !== false) throw new OACError("tainted", "outside text reached this run (or the host could not say); ask the person");
  shapes.checkAction(action, profile);
  const u = shapes.usage(o.usage);
  const b = p.bounds, args = action.args, binds: Record<string, string> = profile.binds ?? {};
  const val = (field: string): any => (Object.hasOwn(binds, field) && Object.hasOwn(args, binds[field]) ? args[binds[field]] : null);
  if (profile.effect === "pay") {
    const amt = b.amount ?? {};
    if (!("per_call_minor" in amt) || !("per_day_minor" in amt) || !("payees" in b)) throw new OACError("pay_without_caps");
  }
  if (Object.hasOwn(binds, "to")) {
    const to = val("to") ?? [];
    if (!("recipients" in b) || !to.every((x: string) => recipientOk(x, b.recipients))) throw new OACError("recipient_not_allowed");
  }
  const payee = val("payee");
  if (payee !== null && "payees" in b && !b.payees.includes(payee)) throw new OACError("payee_not_allowed");
  const site = val("site");
  if (site !== null && "sites" in b && !b.sites.includes(site)) throw new OACError("site_not_allowed");
  const amount = val("amount_minor");
  if (amount !== null) {
    const amt = b.amount;
    if (amt === undefined) throw new OACError("over_amount", "the mandate allows no amount");
    if (val("currency") !== amt.currency) throw new OACError("currency_mismatch");
    if ("per_call_minor" in amt && amount > amt.per_call_minor) throw new OACError("over_amount");
    if ("per_day_minor" in amt && (u.amount_today_minor ?? 0) + amount > amt.per_day_minor) throw new OACError("over_daily_amount");
  }
  const calls = b.calls;
  if ((u.calls_today ?? 0) + 1 > calls.per_day) throw new OACError("over_calls");
  if ("per_run" in calls && (u.calls_this_run ?? 0) + 1 > calls.per_run) throw new OACError("over_calls");
  return p;
}

/** What a replacement mandate allows that the old one did not; non-empty = the signer needs fresh proof (spec 7.4). */
export function loosens(old: Record<string, any>, nw: Record<string, any>): string[] {
  shapes.mandate(old);
  shapes.mandate(nw);
  const out: string[] = [];
  const newOnes = (n: string[], o: string[]) => n.some((x) => !o.includes(x));
  if (canonical(nw.holder) !== canonical(old.holder)) out.push("holder");
  if (nw.sub !== old.sub) out.push("sub");
  if (nw.iss !== old.iss) out.push("iss");
  if (old.signer.kind === "device" && nw.signer.kind !== "device") out.push("signer");
  if (newOnes(nw.tools, old.tools)) out.push("tools");
  if (nw.exp > old.exp) out.push("exp");
  const ob = old.bounds, nb = nw.bounds;
  for (const key of ["per_day", "per_run"]) {
    const o = ob.calls[key], n = nb.calls[key];
    if (o !== undefined && (n === undefined || n > o)) out.push(`calls.${key}`);
  }
  const oa = ob.amount, na = nb.amount;
  if (na !== undefined && oa === undefined) out.push("amount");
  else if (oa !== undefined) {
    if (na === undefined) out.push("amount");
    else {
      if (na.currency !== oa.currency) out.push("amount.currency");
      for (const key of ["per_call_minor", "per_day_minor"]) {
        const o = oa[key], n = na[key];
        if (o !== undefined && (n === undefined || n > o)) out.push(`amount.${key}`);
      }
    }
  }
  // recipients: no list means nobody, so any list where there was none, or a new entry, loosens.
  // payees and sites: no list means no limit, so dropping the list, or a new entry, loosens.
  if (nb.recipients !== undefined && (ob.recipients === undefined || newOnes(nb.recipients, ob.recipients))) out.push("recipients");
  for (const key of ["payees", "sites"]) {
    const o = ob[key], n = nb[key];
    if (o !== undefined && (n === undefined || newOnes(n, o))) out.push(key);
  }
  return out;
}
