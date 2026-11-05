// Approval tiers (spec section 4): A runs, B runs with a receipt and an Undo, C needs a Consent or a Mandate, D never
// runs. tier = max(implied by the effect, profile floor, executor policy, taint floor, any hint); a hint can only raise.

import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";

const ORDER = "ABCD";

export function higher(...tiers: string[]): string {
  return tiers.reduce((a, b) => (ORDER.indexOf(b) > ORDER.indexOf(a) ? b : a));
}

export function implied(profile: Record<string, any>): string {
  const effect = profile.effect, kind = profile.undo.kind;
  if (effect === "read") return "A";
  if ((effect === "write" || effect === "delete") && kind === "native") return "B";
  return "C";
}

export function tierFor(profile: Record<string, any>, opts: { policyFloor?: string; tainted?: boolean; hint?: string | null } = {}): string {
  shapes.profile(profile);
  const tiers = [implied(profile), profile.tier_floor, opts.policyFloor ?? "A"];
  if (opts.tainted && profile.effect !== "read") tiers.push("C");
  if (opts.hint != null) tiers.push(opts.hint);
  for (const t of tiers) if (!["A", "B", "C", "D"].includes(t)) throw new OACError("malformed", `unknown tier ${t}`);
  return higher(...tiers);
}
