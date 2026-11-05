// Executor gate shared by the framework adapters. Same behaviour as gate.py.

import * as crypto from "node:crypto";
import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { digest, KeySet, tokenDigest, verify, type SigningKey } from "./jws.ts";
import { MemoryNonces, verifyConsent, type NonceStore } from "./consent.ts";
import { checkOpen, claim, MemoryOccurrences, occurrenceKey, resolve, type OccurrenceKey, type OccurrenceStore } from "./occurrence.ts";
import { actionDigest, buildPreview } from "./preview.ts";
import { makeReceipt } from "./receipts.ts";
import { tierFor } from "./tiers.ts";

export class NeedsConsent extends Error {
  readonly preview: Record<string, any>;
  constructor(preview: Record<string, any>) { super("the person must approve this preview"); this.preview = preview; }
}

/** Throw from a tool when the action surely did not happen. Other errors count as unknown. */
export class ActionFailed extends Error {}

export type ProfileSpec = {
  effect: string; undo?: string; windowS?: number; tierFloor?: string; binds?: Record<string, string>; otherArgs?: string[];
  occurrence?: string;
};

export class Gate {
  readonly executor: string; readonly key: SigningKey; readonly signers: KeySet; readonly nonces: NonceStore;
  readonly occurrences: OccurrenceStore;
  readonly policyFloor: string;
  readonly profiles: Record<string, Record<string, any>> = {};
  readonly pending = new Map<string, Record<string, any>>(); // person \0 action digest -> preview
  readonly consents = new Map<string, string>();
  readonly receipts = new Map<string, string[]>();
  readonly tokens = new Map<string, string>(); // authority digest in a receipt -> the exact token
  private readonly clock: () => number;
  private readonly summarize: (a: Record<string, any>) => string;

  constructor(o: { executor: string; key: SigningKey; signers: KeySet; nonces?: NonceStore; occurrences?: OccurrenceStore;
    policyFloor?: string; summarize?: (a: Record<string, any>) => string; clock?: () => number }) {
    this.executor = o.executor; this.key = o.key; this.signers = o.signers; this.nonces = o.nonces ?? new MemoryNonces();
    this.occurrences = o.occurrences ?? new MemoryOccurrences();
    this.policyFloor = o.policyFloor ?? "A"; this.clock = o.clock ?? (() => Math.floor(Date.now() / 1000));
    this.summarize = o.summarize ?? ((a) => `${a.tool}: ` + Object.keys(a.args).sort().map((k) => `${k}=${JSON.stringify(a.args[k])}`).join(", ").slice(0, 480));
  }

  profile(tool: string, p: ProfileSpec): Record<string, any> {
    const doc: Record<string, any> = { oac: "0.1", type: "action-profile", tool, effect: p.effect, undo: { kind: p.undo ?? "none", window_s: p.windowS ?? 0 },
      tier_floor: p.tierFloor ?? "A", binds: { ...(p.binds ?? {}) } };
    if (p.otherArgs?.length) doc.other_args = [...p.otherArgs];
    if (p.occurrence) doc.occurrence = p.occurrence;
    this.profiles[tool] = shapes.profile(doc);
    return doc;
  }

  private prof(tool: string): Record<string, any> {
    const p = Object.hasOwn(this.profiles, tool) ? this.profiles[tool] : undefined;
    if (!p) throw new OACError("unknown_tool", `${tool} has no OAC profile`);
    return p;
  }

  tier(tool: string, args: Record<string, unknown>, tainted = true): string {
    const profile = this.prof(tool);
    shapes.checkAction({ tool, args: { ...args } }, profile);
    return tierFor(profile, { policyFloor: this.policyFloor, tainted });
  }

  preview(tool: string, args: Record<string, unknown>, person: string, evidence?: Record<string, any>): Record<string, any> {
    const action = { tool, args: { ...args } };
    const key = person + "\0" + actionDigest(action);
    const now = this.clock();
    let p = this.pending.get(key);
    if (!p || now >= p.exp) {
      p = buildPreview({ profile: this.prof(tool), action, executor: this.executor, sub: person, summary: this.summarize(action), now,
        previewId: "pv_" + crypto.randomBytes(12).toString("base64url"), evidence });
      this.pending.set(key, p);
    }
    return p;
  }

  previewById(id: string): Record<string, any> | undefined { return [...this.pending.values()].find((p) => p.id === id); }

  acceptConsent(token: string): boolean {
    let c: Record<string, any>;
    try { c = verify(token, this.signers, "oac-consent+jws"); shapes.consent(c); } catch { return false; }
    const pending = new Set([...this.pending.values()].map(digest));
    let kept = false;
    for (const item of c.aud === this.executor ? c.items : []) {
      if (pending.has(item.preview) && !this.consents.has(item.preview)) { this.consents.set(item.preview, token); kept = true; }
    }
    return kept;
  }

  private authorize(tool: string, args: Record<string, unknown>, person: string,
    tainted: boolean): [string, Record<string, unknown>, string | null, OccurrenceKey | null] {
    const tier = this.tier(tool, args, tainted);
    if (tier === "D") throw new OACError("tier_d", "this action never runs");
    const occurrence = occurrenceKey(person, this.profiles[tool], args);
    if (tier === "A" || tier === "B") return [tier, { kind: "tier" }, null, claim(this.occurrences, occurrence)];
    const action = { tool, args: { ...args } };
    const preview = this.preview(tool, args, person);
    const pd = digest(preview);
    const token = this.consents.get(pd);
    if (!token) {
      checkOpen(this.occurrences, occurrence);
      throw new NeedsConsent(preview);
    }
    const claimed = claim(this.occurrences, occurrence);
    let c: Record<string, any>;
    try {
      c = verifyConsent(token, { keys: this.signers, executor: this.executor, sub: person, previews: [preview], actions: [action],
        profiles: this.profiles, now: this.clock(), nonces: this.nonces, policyFloor: this.policyFloor, tainted });
    } catch (e) {
      if (claimed) this.occurrences.release(claimed);
      throw e;
    }
    this.pending.delete(person + "\0" + actionDigest(action));
    this.tokens.set(tokenDigest(token), token);
    return ["C", { kind: "consent", ref: c.jti, digest: tokenDigest(token) }, pd, claimed];
  }

  private outcome(claimed: OccurrenceKey | null, error: unknown): string {
    const outcome = error === undefined ? "ok" : claimed === null || error instanceof ActionFailed ? "failed" : "unknown";
    if (claimed) this.occurrences.finish(claimed, outcome);
    return outcome;
  }

  async run<T>(tool: string, args: Record<string, unknown>, fn: (args: Record<string, unknown>) => T | Promise<T>,
    o: { person: string; tainted?: boolean }): Promise<[T, string]> {
    const [tier, authority, pd, claimed] = this.authorize(tool, args, o.person, o.tainted ?? true);
    let result: T;
    try {
      result = await fn(args);
    } catch (e) {
      this.receipt(o.person, tool, args, tier, authority, pd, null, this.outcome(claimed, e ?? new Error("thrown")));
      throw e;
    }
    return [result, this.receipt(o.person, tool, args, tier, authority, pd, result, this.outcome(claimed, undefined))];
  }

  /** Record what the provider says happened to an unknown attempt: ok or failed. */
  resolve(tool: string, occurrence: string, o: { person: string; outcome: "ok" | "failed" }): void {
    resolve(this.occurrences, [o.person, tool, occurrence], o.outcome);
  }

  private receipt(person: string, tool: string, args: Record<string, unknown>, tier: string, authority: Record<string, unknown>,
    pd: string | null, result: unknown, outcome: string): string {
    const profile = this.profiles[tool];
    const chain = this.receipts.get(person) ?? [];
    this.receipts.set(person, chain);
    const now = this.clock();
    const undo: Record<string, unknown> = { kind: profile.undo.kind };
    if (undo.kind !== "none" && outcome === "ok") {
      undo.until = now + profile.undo.window_s;
      if (undo.kind === "native") undo.token = "u_" + crypto.randomBytes(12).toString("base64url");
    }
    let rd: string;
    try { rd = digest(result ?? null); } catch { rd = digest(String(result)); }
    const payload: Record<string, unknown> = { iss: this.executor, sub: person, seq: chain.length + 1, prev: chain.length ? tokenDigest(chain[chain.length - 1]) : null,
      iat: now, tool, tier, authority, action: actionDigest({ tool, args: { ...args } }), outcome, result: rd, undo };
    if (pd) payload.preview = pd;
    if (Object.hasOwn(profile, "occurrence")) payload.occurrence = args[profile.occurrence];
    const r = makeReceipt(this.key, payload);
    chain.push(r);
    return r;
  }
}
