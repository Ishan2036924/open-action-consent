// OAC for the official MCP TypeScript SDK v2 (@modelcontextprotocol/server 2.4+). The SDK has no tool-call
// interceptor, so OAC wraps each tool: `oac.registerTool(server, name, config, profile, handler)`.
// Tier A/B run (B with a receipt and undo token); tier C answers input_required with a URL-mode elicitation and
// runs only with a valid signed Consent; tier D, unprofiled tools and undeclared arguments never run. Unlike the
// Python SDK, v2 does not integrity-protect requestState, so OAC signs its own (HMAC-SHA256, short expiry).

import * as crypto from "node:crypto";
import { inputRequired, inputResponse, type McpServer } from "@modelcontextprotocol/server";
import { actionDigest, buildPreview, digest, KeySet, makeReceipt, MemoryNonces, OACError, shapes, tierFor, tokenDigest, verify, verifyConsent, type SigningKey } from "@open-action-consent/sdk";

export const ID = "com.atlasiw/oac";
export const PROFILE_KEY = `${ID}-profile`, PREVIEW_KEY = `${ID}-preview`, RECEIPT_KEY = `${ID}-receipt`, CONSENT_KEY = `${ID}-consent`;
const ASK = "oac_consent";
const STATE_TTL_S = 900;

type Ctx = any;
type Result = { content: { type: string; text: string }[]; isError?: boolean; _meta?: Record<string, unknown> };
const refused = (text: string): Result => ({ content: [{ type: "text", text }], isError: true });

export interface OACOptions {
  executor: string; key: SigningKey; signers: KeySet;
  consentUrl: (preview: Record<string, any>) => string;
  person: (ctx: Ctx) => string;
  /** From the host runtime, never the model; default: tainted (spec section 4). */
  tainted?: (ctx: Ctx) => boolean;
  summarize?: (action: Record<string, any>) => string;
  policyFloor?: string;
  clock?: () => number;
}

export class OAC {
  readonly profiles: Record<string, Record<string, any>> = {};
  readonly previews = new Map<string, Record<string, any>>();
  readonly consents = new Map<string, string>();
  readonly nonces = new MemoryNonces();
  readonly receipts = new Map<string, string[]>();
  private readonly stateKey = crypto.randomBytes(32);
  readonly o: OACOptions;
  constructor(o: OACOptions) { this.o = o; }

  private now(): number { return (this.o.clock ?? (() => Math.floor(Date.now() / 1000)))(); }

  /** Capability settings to put under `capabilities.extensions[ID]`. */
  settings(): Record<string, unknown> { return { version: "0.1", executor: this.o.executor }; }

  profile(tool: string, p: { effect: string; undo?: string; windowS?: number; tierFloor?: string; binds?: Record<string, string>; otherArgs?: string[] }): Record<string, unknown> {
    const doc: Record<string, any> = { oac: "0.1", type: "action-profile", tool, effect: p.effect, undo: { kind: p.undo ?? "none", window_s: p.windowS ?? 0 },
      tier_floor: p.tierFloor ?? "A", binds: { ...(p.binds ?? {}) } };
    if (p.otherArgs?.length) doc.other_args = [...p.otherArgs];
    this.profiles[tool] = shapes.profile(doc);
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

  /** The signer page hands over a Consent: kept only if valid for this executor over a pending preview, never replaced. */
  acceptConsent(token: string): boolean {
    let p: Record<string, any>;
    try { p = verify(token, this.o.signers, "oac-consent+jws"); shapes.consent(p); } catch { return false; }
    let kept = false;
    for (const item of p.aud === this.o.executor ? p.items : []) {
      if (this.previews.has(item.preview) && !this.consents.has(item.preview)) { this.consents.set(item.preview, token); kept = true; }
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
    if (tier === "A" || tier === "B") return this.withReceipt(await handler(args, ctx), person, profile, action, tier, { kind: "tier" }, null);
    const missing: Record<string, any> = {};
    if (!clientCaps?.extensions?.[ID]) missing.extensions = { [ID]: {} };
    if (!clientCaps?.elicitation?.url) missing.elicitation = { url: {} };
    if (Object.keys(missing).length) {
      // spec mcp-extension 6: never run without a consent page. The v2 SDK turns errors thrown in a tool into tool
      // results, so the -32021 data travels in the refusal instead of as a protocol error.
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
    let consent: Record<string, any>;
    try {
      consent = verifyConsent(token, { keys: this.o.signers, executor: this.o.executor, sub: person, previews: [preview], actions: [action],
        profiles: this.profiles, now: this.now(), nonces: this.nonces, policyFloor: this.o.policyFloor, tainted });
    } catch (e) {
      return refused(`Refused (${e instanceof OACError ? e.code : "error"}). Nothing ran.`);
    }
    return this.withReceipt(await handler(args, ctx), person, profile, action, "C", { kind: "consent", ref: consent.jti }, digest(preview));
  }

  private ask(action: Record<string, any>, profile: Record<string, any>, person: string): any {
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

  private withReceipt(result: Result, person: string, profile: Record<string, any>, action: Record<string, any>, tier: string,
    authority: Record<string, unknown>, previewDigest: string | null): Result {
    const failed = result?.isError === true;
    const chain = this.receipts.get(person) ?? [];
    this.receipts.set(person, chain);
    const now = this.now();
    const undo: Record<string, unknown> = { kind: profile.undo.kind };
    if (undo.kind !== "none" && !failed) {
      undo.until = now + profile.undo.window_s;
      if (undo.kind === "native") undo.token = "u_" + crypto.randomBytes(12).toString("base64url");
    }
    const payload: Record<string, unknown> = { iss: this.o.executor, sub: person, seq: chain.length + 1, prev: chain.length ? tokenDigest(chain[chain.length - 1]) : null,
      iat: now, tool: action.tool, tier, authority, action: actionDigest(action), outcome: failed ? "failed" : "ok", undo,
      result: digest(JSON.parse(JSON.stringify(result.content ?? []))) };
    if (previewDigest) payload.preview = previewDigest;
    const receipt = makeReceipt(this.o.key, payload);
    chain.push(receipt);
    return { ...result, _meta: { ...(result._meta ?? {}), [RECEIPT_KEY]: receipt } };
  }
}
