// A framework-neutral executor gate (twin of gate.py): tier, Preview, Consent hand-over, verification right before
// the action, run, signed Receipt. A pending Preview is reused for the same person and action until it expires, so
// a framework that re-runs a step after an interruption gets the Preview the person approved.

import * as crypto from "node:crypto";
import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { digest, KeySet, tokenDigest, verify, type SigningKey } from "./jws.ts";
import { MemoryNonces, verifyConsent, type NonceStore } from "./consent.ts";
import { actionDigest, buildPreview } from "./preview.ts";
import { makeReceipt } from "./receipts.ts";
import { tierFor } from "./tiers.ts";

export class NeedsConsent extends Error {
  readonly preview: Record<string, any>;
  constructor(preview: Record<string, any>) { super("the person must approve this preview"); this.preview = preview; }
}

export type ProfileSpec = { effect: string; undo?: string; windowS?: number; tierFloor?: string; binds?: Record<string, string>; otherArgs?: string[] };

export class Gate {
  readonly executor: string; readonly key: SigningKey; readonly signers: KeySet; readonly nonces: NonceStore;
  readonly policyFloor: string;
  readonly profiles: Record<string, Record<string, any>> = {};
  readonly pending = new Map<string, Record<string, any>>(); // person \0 action digest -> preview
  readonly consents = new Map<string, string>();
  readonly receipts = new Map<string, string[]>();
  private readonly clock: () => number;
  private readonly summarize: (a: Record<string, any>) => string;

  constructor(o: { executor: string; key: SigningKey; signers: KeySet; nonces?: NonceStore; policyFloor?: string;
    summarize?: (a: Record<string, any>) => string; clock?: () => number }) {
    this.executor = o.executor; this.key = o.key; this.signers = o.signers; this.nonces = o.nonces ?? new MemoryNonces();
    this.policyFloor = o.policyFloor ?? "A"; this.clock = o.clock ?? (() => Math.floor(Date.now() / 1000));
    this.summarize = o.summarize ?? ((a) => `${a.tool}: ` + Object.keys(a.args).sort().map((k) => `${k}=${JSON.stringify(a.args[k])}`).join(", ").slice(0, 480));
  }

  profile(tool: string, p: ProfileSpec): Record<string, any> {
    const doc: Record<string, any> = { oac: "0.1", type: "action-profile", tool, effect: p.effect, undo: { kind: p.undo ?? "none", window_s: p.windowS ?? 0 },
      tier_floor: p.tierFloor ?? "A", binds: { ...(p.binds ?? {}) } };
    if (p.otherArgs?.length) doc.other_args = [...p.otherArgs];
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

  private authorize(tool: string, args: Record<string, unknown>, person: string, tainted: boolean): [string, Record<string, unknown>, string | null] {
    const tier = this.tier(tool, args, tainted);
    if (tier === "D") throw new OACError("tier_d", "this action never runs");
    if (tier === "A" || tier === "B") return [tier, { kind: "tier" }, null];
    const action = { tool, args: { ...args } };
    const preview = this.preview(tool, args, person);
    const pd = digest(preview);
    const token = this.consents.get(pd);
    if (!token) throw new NeedsConsent(preview);
    const c = verifyConsent(token, { keys: this.signers, executor: this.executor, sub: person, previews: [preview], actions: [action],
      profiles: this.profiles, now: this.clock(), nonces: this.nonces, policyFloor: this.policyFloor, tainted });
    this.pending.delete(person + "\0" + actionDigest(action));
    return ["C", { kind: "consent", ref: c.jti }, pd];
  }

  async run<T>(tool: string, args: Record<string, unknown>, fn: (args: Record<string, unknown>) => T | Promise<T>,
    o: { person: string; tainted?: boolean }): Promise<[T, string]> {
    const [tier, authority, pd] = this.authorize(tool, args, o.person, o.tainted ?? true);
    let result: T;
    try { result = await fn(args); } catch (e) { this.receipt(o.person, tool, args, tier, authority, pd, null, true); throw e; }
    return [result, this.receipt(o.person, tool, args, tier, authority, pd, result, false)];
  }

  private receipt(person: string, tool: string, args: Record<string, unknown>, tier: string, authority: Record<string, unknown>,
    pd: string | null, result: unknown, failed: boolean): string {
    const profile = this.profiles[tool];
    const chain = this.receipts.get(person) ?? [];
    this.receipts.set(person, chain);
    const now = this.clock();
    const undo: Record<string, unknown> = { kind: profile.undo.kind };
    if (undo.kind !== "none" && !failed) {
      undo.until = now + profile.undo.window_s;
      if (undo.kind === "native") undo.token = "u_" + crypto.randomBytes(12).toString("base64url");
    }
    let rd: string;
    try { rd = digest(result ?? null); } catch { rd = digest(String(result)); }
    const payload: Record<string, unknown> = { iss: this.executor, sub: person, seq: chain.length + 1, prev: chain.length ? tokenDigest(chain[chain.length - 1]) : null,
      iat: now, tool, tier, authority, action: actionDigest({ tool, args: { ...args } }), outcome: failed ? "failed" : "ok", result: rd, undo };
    if (pd) payload.preview = pd;
    const r = makeReceipt(this.key, payload);
    chain.push(r);
    return r;
  }
}
