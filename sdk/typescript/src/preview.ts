// Actions and Previews (spec sections 3 and 5). Every structured Preview field is bound to one argument by the tool's
// Action Profile, so what the person reads is provably what will run.

import * as crypto from "node:crypto";
import * as shapes from "./shapes.ts";
import { OACError } from "./errors.ts";
import { canonical } from "./jcs.ts";
import { digest } from "./jws.ts";

export function actionDigest(action: Record<string, any>): string {
  const a = shapes.action(action);
  return digest({ tool: a.tool, args: a.args });
}

export function buildPreview(o: {
  profile: Record<string, any>; action: Record<string, any>; executor: string; sub: string; summary: string; now: number;
  ttl?: number; previewId?: string; cancelPolicy?: Record<string, any>; evidence?: Record<string, any>;
}): Record<string, any> {
  shapes.profile(o.profile);
  if (o.action.tool !== o.profile.tool) throw new OACError("unknown_tool", "action and profile name different tools");
  shapes.checkAction(o.action, o.profile);
  const fields: Record<string, unknown> = {}, details: Record<string, unknown> = {};
  for (const [f, a] of Object.entries(o.profile.binds ?? {})) if (Object.hasOwn(o.action.args, a as string)) fields[f] = o.action.args[a as string];
  for (const a of o.profile.other_args ?? []) if (Object.hasOwn(o.action.args, a)) details[a] = o.action.args[a];
  const doc: Record<string, any> = {
    oac: shapes.VERSION, type: "preview", id: o.previewId ?? "pv_" + crypto.randomBytes(12).toString("base64url"),
    executor: o.executor, sub: o.sub, tool: o.action.tool, action: actionDigest(o.action), summary: o.summary, fields,
    undo: { ...o.profile.undo }, iat: o.now, exp: o.now + (o.ttl ?? 600),
  };
  if (Object.keys(details).length) doc.details = details;
  if (o.cancelPolicy) doc.cancel_policy = { ...o.cancelPolicy };
  if (o.evidence) doc.evidence = { ...o.evidence };
  return shapes.preview(doc);
}

/** Throw binding_mismatch unless every Preview field equals its bound argument and the undo shown is the profile's. */
export function checkBinding(preview: Record<string, any>, action: Record<string, any>, profile: Record<string, any>): void {
  shapes.checkAction(action, profile);
  const binds: Record<string, string> = profile.binds ?? {};
  const fields: Record<string, unknown> = preview.fields;
  for (const f of Object.keys(fields)) if (!Object.hasOwn(binds, f)) throw new OACError("binding_mismatch", `field ${f} is not bound to an argument`);
  for (const [f, arg] of Object.entries(binds)) {
    const hasField = Object.hasOwn(fields, f), hasArg = Object.hasOwn(action.args, arg);
    if (hasField !== hasArg || (hasField && canonical(fields[f]) !== canonical(action.args[arg]))) {
      throw new OACError("binding_mismatch", `field ${f} does not match argument ${arg}`);
    }
  }
  const others: Record<string, unknown> = {};
  for (const a of profile.other_args ?? []) if (Object.hasOwn(action.args, a)) others[a] = action.args[a];
  if (canonical(preview.details ?? {}) !== canonical(others)) throw new OACError("binding_mismatch", "details differ from the other arguments");
  if (preview.tool !== action.tool || canonical(preview.undo) !== canonical(profile.undo)) {
    throw new OACError("binding_mismatch", "tool or undo differs from the profile");
  }
}
