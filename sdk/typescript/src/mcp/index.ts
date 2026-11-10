// OAC for the MCP TypeScript SDK v2. The SDK has no interceptor, so this wraps each tool. See guides/mcp-typescript.md.

import * as crypto from "node:crypto";
import { inputRequired, inputResponse, type McpServer } from "@modelcontextprotocol/server";
import { actionDigest, buildPreview, digest, KeySet, makeReceipt, MemoryNonces, OACError, shapes, tierFor, tokenDigest, verify, verifyConsent, type SigningKey } from "../index.ts";
import { fits, type DevicePolicy } from "../gate.ts";
import { checkOpen, checkScopeChange, claim, MemoryOccurrences, occurrenceKey, resolve, scope, type OccurrenceKey, type OccurrenceStore } from "../occurrence.ts";

export const ID = "com.atlasiw/oac";
export const PROFILE_KEY = `${ID}-profile`, PREVIEW_KEY = `${ID}-preview`, RECEIPT_KEY = `${ID}-receipt`, CONSENT_KEY = `${ID}-consent`;
export const OUTCOME_KEY = `${ID}-outcome`, DEVICE_KEY = `${ID}-device-proof`;
const ASK = "oac_consent";
const STATE_TTL_S = 900;

type Ctx = any;
type Result = { content: { type: string; text: string }[]; isError?: boolean; _meta?: Record<string, unknown> };
const refused = (text: string): Result => ({ content: [{ type: "text", text }], isError: true });

export interface OACOptions {
  executor: string; key: SigningKey; signers: KeySet;
  consentUrl: (preview: Record<string, any>) => string;
  person: (ctx: Ctx) => string;
  /** From the host, never the model. Defaults to tainted. */
  tainted?: (ctx: Ctx) => boolean;
  summarize?: (action: Record<string, any>) => string;
  policyFloor?: string;
  clock?: () => number;
  occurrences?: OccurrenceStore;
  /** The passkey check a tier C action needs (its proof is filled in here), or null when none is needed. */
  device?: DevicePolicy;
}

export class OAC {
  readonly profiles: Record<string, Record<string, any>> = {};
  readonly previews = new Map<string, Record<string, any>>();
  readonly consents = new Map<string, string>();
  readonly nonces = new MemoryNonces();
  readonly receipts = new Map<string, string[]>();
  readonly tokens = new Map<string, string>(); // authority digest in a receipt -> the exact token
  readonly proofs = new Map<string, Record<string, any>>(); // preview digest -> device proof sent with the consent
  readonly deviceProofs = new Map<string, Record<string, any>>(); // authority digest -> the passkey proof that came with it
  readonly occurrences: OccurrenceStore;
  private readonly stateKey = crypto.randomBytes(32);
  readonly o: OACOptions;
  constructor(o: OACOptions) { this.o = o; this.occurrences = o.occurrences ?? new MemoryOccurrences(); }

  private now(): number { return (this.o.clock ?? (() => Math.floor(Date.now() / 1000)))(); }

  /** Capability settings to put under `capabilities.extensions[ID]`. */
  settings(): Record<string, unknown> { return { version: shapes.VERSION, executor: this.o.executor }; }

  profile(tool: string, p: {
    effect: string; undo?: string; windowS?: number; tierFloor?: string; binds?: Record<string, string>; otherArgs?: string[];
    occurrence?: string; occurrenceScope?: string;
  }): Record<string, unknown> {
    const doc: Record<string, any> = { oac: shapes.VERSION, type: "action-profile", tool, effect: p.effect, undo: { kind: p.undo ?? "none", window_s: p.windowS ?? 0 },
      tier_floor: p.tierFloor ?? "A", binds: { ...(p.binds ?? {}) } };
    if (p.otherArgs?.length) doc.other_args = [...p.otherArgs];
    if (p.occurrence) doc.occurrence = p.occurrence;
    if (p.occurrenceScope) doc.occurrence_scope = p.occurrenceScope;
    const checked = shapes.profile(doc);
    checkScopeChange(this.occurrences, Object.hasOwn(this.profiles, tool) ? this.profiles[tool] : null, checked);
    this.profiles[tool] = checked;
    return { [PROFILE_KEY]: doc };
  }

  /** Register a tool on an McpServer with its OAC profile; every call goes through `guard`. */
  registerTool(server: McpServer, name: string, config: Record<string, any>, profile: Parameters<OAC["profile"]>[1], handler: (args: any, ctx: Ctx) => Promise<Result>): void {
    const meta = this.profile(name, profile);
    const caps = (ctx: Ctx) => ctx?.mcpReq?._meta?.["io.modelcontextprotocol/clientCapabilities"] ?? (server as any).server?.getClientCapabilities?.();
    (server as any).registerTool(name, { ...config, _meta: { ...(config._meta ?? {}), ...meta } },
      (args: any, ctx: Ctx) => this.guard(name, args ?? {}, ctx, handler, caps(ctx)));
  }

  preview(id: string): Record<string, any> | undefined { return [...this.previews.values()].find((p) => p.id === id); }

  /** Keep a valid Consent, and the passkey proof sent with it, for a pending preview.
   * Never replaces a different token already kept; the same token may bring a new proof. */
  acceptConsent(token: string, proof?: Record<string, any> | null): boolean {
    let p: Record<string, any>;
    try { p = verify(token, this.o.signers, "oac-consent+jws"); shapes.consent(p); } catch { return false; }
    let kept = false;
    for (const item of p.aud === this.o.executor ? p.items : []) {
      if (this.previews.has(item.preview) && (this.consents.get(item.preview) ?? token) === token) {
        this.consents.set(item.preview, token);
        if (fits(proof, token)) this.proofs.set(item.preview, proof!);
        kept = true;
      }
    }
    return kept;
  }

  private seal(state: Record<string, unknown>): string {
    const body = Buffer.from(JSON.stringify({ ...state, exp: this.now() + STATE_TTL_S })).toString("base64url");
    return body + "." + crypto.createHmac("sha256", this.stateKey).update(body).digest("base64url");
  }

  private unseal(raw: unknown, person: string): Record<string, any> | null {
    if (typeof raw !== "string") return null;
    const [body, mac] = raw.split(".");
    const good = crypto.createHmac("sha256", this.stateKey).update(body ?? "").digest();
    const got = Buffer.from(mac ?? "", "base64url");
    if (got.length !== good.length || !crypto.timingSafeEqual(got, good)) return null;
    const s = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return s.sub === person && this.now() < s.exp ? s : null;
  }

  async guard(name: string, args: Record<string, unknown>, ctx: Ctx, handler: (args: any, ctx: Ctx) => Promise<Result>,
    clientCaps: Record<string, any> | undefined = { elicitation: { url: {} }, extensions: { [ID]: {} } }): Promise<any> {
    const profile = this.profiles[name];
    if (!profile) return refused(`${name} has no OAC profile, so it never runs.`);
    const action = { tool: name, args: { ...args } };
    const person = this.o.person(ctx);
    const tainted = this.o.tainted ? this.o.tainted(ctx) : true;
    let tier: string;
    try { shapes.checkAction(action, profile); tier = tierFor(profile, { policyFloor: this.o.policyFloor, tainted }); } catch (e) {
      return refused(`Refused (${e instanceof OACError ? e.code : "error"}).`);
    }
    if (tier === "D") return refused("Refused: this action is never allowed (tier D).");
    if (tier === "A" || tier === "B") {
      let claimed: OccurrenceKey | null;
      try { claimed = claim(this.occurrences, occurrenceKey(person, profile, args)); } catch (e) {
        return refused(`Refused (${e instanceof OACError ? e.code : "error"}). Nothing ran.`);
      }
      return this.run(handler, args, ctx, person, profile, action, tier, { kind: "tier" }, null, claimed);
    }
    const missing: Record<string, any> = {};
    if (!clientCaps?.extensions?.[ID]) missing.extensions = { [ID]: {} };
    if (!clientCaps?.elicitation?.url) missing.elicitation = { url: {} };
    if (Object.keys(missing).length) {
      // the v2 SDK turns thrown errors into tool results, so -32021 travels in the refusal
      return { ...refused("Refused (-32021): this client cannot show an approval page (needs the OAC extension and URL elicitation). Nothing ran."),
        _meta: { [`${ID}-missing`]: missing } };
    }
    const state = this.unseal(ctx.mcpReq?.requestState?.(), person);
    if (!state) return this.ask(action, profile, person);
    if (state.action !== actionDigest(action)) return refused("Refused (action_mismatch). Nothing ran.");
    const answer = inputResponse(ctx.mcpReq?.inputResponses, ASK);
    if (answer.kind !== "elicit" || answer.action !== "accept") return refused("The person did not approve. Nothing ran.");
    const preview = this.previews.get(state.preview);
    const token = this.consents.get(state.preview) ?? ctx.mcpReq?._meta?.[CONSENT_KEY];
    if (!preview || !token) return this.ask(action, profile, person);
    const need = this.o.device?.(person, action) ?? null;
    const proof = this.proofs.get(state.preview) ?? ctx.mcpReq?._meta?.[DEVICE_KEY] ?? null;
    const device = need ? { ...need, proof } : undefined;
    let consent: Record<string, any>;
    let claimed: OccurrenceKey | null = null;
    try {
      claimed = claim(this.occurrences, occurrenceKey(person, profile, args));
      consent = verifyConsent(token, { keys: this.o.signers, executor: this.o.executor, sub: person, previews: [preview], actions: [action],
        profiles: this.profiles, now: this.now(), nonces: this.nonces, policyFloor: this.o.policyFloor, tainted, device });
    } catch (e) {
      if (claimed) this.occurrences.release(claimed);
      return refused(`Refused (${e instanceof OACError ? e.code : "error"}). Nothing ran.`);
    }
    this.tokens.set(tokenDigest(token), token);
    if (device?.proof) this.deviceProofs.set(tokenDigest(token), device.proof);
    const authority = { kind: "consent", ref: consent.jti, digest: tokenDigest(token) };
    return this.run(handler, args, ctx, person, profile, action, "C", authority, digest(preview), claimed);
  }

  // a timed-out payment may still have gone through, so an error is "unknown" unless the tool says "failed"
  private async run(handler: (args: any, ctx: Ctx) => Promise<Result>, args: Record<string, unknown>, ctx: Ctx, person: string,
    profile: Record<string, any>, action: Record<string, any>, tier: string, authority: Record<string, unknown>,
    previewDigest: string | null, claimed: OccurrenceKey | null): Promise<Result> {
    let result: Result;
    try {
      result = await handler(args, ctx);
    } catch (e) {
      this.withReceipt(null, person, profile, action, tier, authority, previewDigest, this.finish(claimed, claimed ? "unknown" : "failed"));
      throw e;
    }
    let outcome = "ok";
    if (result?.isError === true) outcome = claimed && result._meta?.[OUTCOME_KEY] !== "failed" ? "unknown" : "failed";
    return this.withReceipt(result, person, profile, action, tier, authority, previewDigest, this.finish(claimed, outcome))!;
  }

  private finish(claimed: OccurrenceKey | null, outcome: string): string {
    if (claimed) this.occurrences.finish(claimed, outcome);
    return outcome;
  }

  /** Record what the provider says happened to an unknown attempt: ok or failed. */
  resolve(tool: string, occurrence: string, o: { person: string; outcome: "ok" | "failed" }): void {
    const profile = Object.hasOwn(this.profiles, tool) ? this.profiles[tool] : undefined;
    if (!profile) throw new OACError("unknown_tool", `${tool} has no OAC profile`);
    resolve(this.occurrences, [o.person, scope(profile), occurrence], o.outcome);
  }

  private ask(action: Record<string, any>, profile: Record<string, any>, person: string): any {
    try { checkOpen(this.occurrences, occurrenceKey(person, profile, action.args)); } catch (e) {
      return refused(`Refused (${e instanceof OACError ? e.code : "error"}). Nothing ran.`);
    }
    const summarize = this.o.summarize ?? ((a) => `${a.tool} with ${JSON.stringify(a.args)}`.slice(0, 500));
    const p = buildPreview({ profile, action, executor: this.o.executor, sub: person, summary: summarize(action), now: this.now() });
    const d = digest(p);
    this.previews.set(d, p);
    const result = inputRequired({
      inputRequests: { [ASK]: inputRequired.elicitUrl({ message: "Approve: " + p.summary, url: this.o.consentUrl(p) }) },
      requestState: this.seal({ sub: person, preview: d, action: actionDigest(action) }),
    }) as any;
    return { ...result, _meta: { ...(result._meta ?? {}), [PREVIEW_KEY]: p } };
  }

  private withReceipt(result: Result | null, person: string, profile: Record<string, any>, action: Record<string, any>, tier: string,
    authority: Record<string, unknown>, previewDigest: string | null, outcome: string): Result | null {
    const chain = this.receipts.get(person) ?? [];
    this.receipts.set(person, chain);
    const now = this.now();
    const undo: Record<string, unknown> = { kind: profile.undo.kind };
    if (undo.kind !== "none" && outcome === "ok") {
      undo.until = now + profile.undo.window_s;
      if (undo.kind === "native") undo.token = "u_" + crypto.randomBytes(12).toString("base64url");
    }
    const payload: Record<string, unknown> = { iss: this.o.executor, sub: person, seq: chain.length + 1, prev: chain.length ? tokenDigest(chain[chain.length - 1]) : null,
      iat: now, tool: action.tool, tier, authority, action: actionDigest(action), outcome, undo,
      result: digest(JSON.parse(JSON.stringify(result?.content ?? []))) };
    if (previewDigest) payload.preview = previewDigest;
    if (Object.hasOwn(profile, "occurrence")) payload.occurrence = action.args[profile.occurrence];
    if (Object.hasOwn(profile, "occurrence_scope")) payload.occurrence_scope = profile.occurrence_scope;
    const receipt = makeReceipt(this.o.key, payload);
    chain.push(receipt);
    if (result === null) return null;
    return { ...result, _meta: { ...(result._meta ?? {}), [RECEIPT_KEY]: receipt } };
  }
}
