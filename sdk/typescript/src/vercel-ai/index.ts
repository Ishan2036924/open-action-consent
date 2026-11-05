// OAC for the Vercel AI SDK: an approval runs nothing without a signed Consent. See guides/vercel-ai.md.

import { Gate, NeedsConsent, OACError, type ProfileSpec } from "../index.ts";

export const NOT_APPROVED = "Not approved: the person has not signed a consent for exactly this action. Nothing ran.";

type AnyTool = { execute?: (input: any, options: any) => any; [k: string]: any };

export function withOAC<T extends Record<string, AnyTool>>(gate: Gate, tools: T, profiles: { [K in keyof T]: ProfileSpec },
  o: { person: string; tainted?: () => boolean }): { tools: T; toolApproval: (opts: { toolCall: any }) => Promise<any> } {
  const tainted = o.tainted ?? (() => true); // unknown means tainted
  const wrapped: Record<string, AnyTool> = {};
  for (const [name, t] of Object.entries(tools)) {
    gate.profile(name, profiles[name as keyof T]);
    wrapped[name] = {
      ...t,
      execute: async (input: any, options: any) => {
        try {
          const [result] = await gate.run(name, input ?? {}, (args) => t.execute!(args, options), { person: o.person, tainted: tainted() });
          return result;
        } catch (e) {
          if (e instanceof NeedsConsent) return NOT_APPROVED;
          if (e instanceof OACError) return `Refused (${e.code}). Nothing ran.`;
          throw e;
        }
      },
    };
  }
  const toolApproval = async ({ toolCall }: { toolCall: any }) => {
    try {
      if (gate.tier(toolCall.toolName, toolCall.input ?? {}, tainted()) !== "C") return "not-applicable";
    } catch {
      return "not-applicable"; // execute refuses it with the reason
    }
    const p = gate.preview(toolCall.toolName, toolCall.input ?? {}, o.person);
    return { type: "user-approval", reason: p.summary };
  };
  return { tools: wrapped as T, toolApproval };
}

/** The Preview to show for a `tool-approval-request` part. */
export function previewFor(gate: Gate, request: { toolCall: { toolName: string; input: any } }, person: string): Record<string, any> {
  return gate.preview(request.toolCall.toolName, request.toolCall.input ?? {}, person);
}

/** The tool message to send back: approved only when the signed Consent is valid for a pending Preview. */
export function approvalMessage(gate: Gate, approvalId: string, consentToken: string | null): any {
  const approved = consentToken !== null && gate.acceptConsent(consentToken);
  return { role: "tool", content: [{ type: "tool-approval-response", approvalId, approved, reason: approved ? "signed OAC consent" : "no valid signed consent" }] };
}
