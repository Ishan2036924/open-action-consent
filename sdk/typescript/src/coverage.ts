// Deployment coverage (spec 13.2): a coverage statement and the bypass-check attempts become one result per effect.

import * as shapes from "./shapes.ts";

function rowResult(row: Record<string, any>, tried: Record<string, any>[]): string {
  if (!tried.length) return "not_checked";
  if (tried.some((a) => a.effect_occurred === "yes")) return "bypass";
  const done = new Set(tried.map((a) => a.route));
  if (row.records === "memory" || row.routes.some((x: any) => !done.has(x.route)) || tried.some((a) => a.effect_occurred === "cannot_tell")) return "incomplete";
  return "covered";
}

/** Four results per effect and for the whole claim, never a score. `statement_wrong`: an effect happened on a route the statement does not list. */
export function coverage(statement: unknown, attempts: unknown): Record<string, any> {
  const rows = shapes.coverageStatement(statement), tried = shapes.coverageAttempts(attempts);
  const listed = new Map(rows.map((r) => [r.effect, new Set<string>(r.routes.map((x: any) => x.route))]));
  const happened = tried.filter((a) => a.effect_occurred === "yes");
  const effects: Record<string, string> = {};
  const put = (k: string, v: string) => Object.defineProperty(effects, k, { value: v, enumerable: true, writable: true, configurable: true }); // an effect may be named __proto__
  for (const r of rows) put(r.effect, rowResult(r, tried.filter((a) => a.effect === r.effect)));
  for (const a of happened) if (!listed.has(a.effect)) put(a.effect, "bypass");
  const kinds = new Set(Object.values(effects));
  let result = "incomplete";
  if (kinds.has("bypass")) result = "bypass";
  else if ([...kinds].every((k) => k === "not_checked")) result = "not_checked";
  else if ([...kinds].every((k) => k === "covered")) result = "covered";
  return { result, statement_wrong: happened.some((a) => !listed.get(a.effect)?.has(a.route)), effects };
}
