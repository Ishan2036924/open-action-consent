// OAC for the Vercel AI SDK (ai 7). The SDK can pause a tool call for approval (`toolApproval` -> a
// `tool-approval-request`) and resume when a `tool-approval-response` with `approved: true` is sent back. That
// approval is a boolean (optionally HMAC-signed by the server). `withOAC` adds OAC: tier C (computed, not the
// model's say) asks for approval with the Preview's summary as the reason, and the tool's execute runs only if the
// person's signed Consent verifies for exactly this call; an approval without it runs nothing.

import { Gate, NeedsConsent, OACError, type ProfileSpec } from "../../../sdk/typescript/src/index.ts";

export const NOT_APPROVED = "Not approved: the person has not signed a consent for exactly this action. Nothing ran.";

type AnyTool = { execute?: (input: any, options: any) => any; [k: string]: any };

export function withOAC<T extends Record<string, AnyTool>>(gate: Gate, tools: T, profiles: { [K in keyof T]: ProfileSpec },
  o: { person: string; tainted?: () => boolean }): { tools: T; toolApproval: (opts: { toolCall: any }) => Promise<any> } {
  const tainted = o.tainted ?? (() => true); // spec section 4: unknown = tainted
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
