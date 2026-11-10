// Business occurrences (spec 5.1): one order or payment runs at most once.

import { OACError } from "./errors.ts";

export type OccurrenceKey = [person: string, scope: string, occurrence: string];

export interface OccurrenceStore {
  /** Mark the key running and return null, or return its blocking state. Must be atomic. */
  claim(key: OccurrenceKey): string | null;
  finish(key: OccurrenceKey, outcome: string): void;
  /** Drop a claim whose action never started. */
  release(key: OccurrenceKey): void;
  state(key: OccurrenceKey): string | null;
  /** Optional: whether any record uses this scope. Without it, a gate refuses every change to a tool's occurrence or scope. */
  hasScope?(scope: string): boolean;
}

/** For tests and examples. A real store keeps these states in a table with a unique key. */
export class MemoryOccurrences implements OccurrenceStore {
  private s = new Map<string, string>();
  constructor(states: Iterable<[OccurrenceKey, string]> = []) { for (const [k, v] of states) this.s.set(JSON.stringify(k), v); }
  claim(key: OccurrenceKey): string | null {
    const now = this.s.get(JSON.stringify(key));
    if (now === "running" || now === "unknown" || now === "ok") return now;
    this.s.set(JSON.stringify(key), "running");
    return null;
  }
  finish(key: OccurrenceKey, outcome: string): void { this.s.set(JSON.stringify(key), outcome); }
  release(key: OccurrenceKey): void { this.s.delete(JSON.stringify(key)); }
  state(key: OccurrenceKey): string | null { return this.s.get(JSON.stringify(key)) ?? null; }
  hasScope(scope: string): boolean { return [...this.s.keys()].some((k) => JSON.parse(k)[1] === scope); }
}

/** Where the profile's occurrence ids are unique: its occurrence_scope, else the tool itself.
 * The prefixes keep a scope from ever matching a tool's own records. */
export const scope = (profile: Record<string, any>): string =>
  Object.hasOwn(profile, "occurrence_scope") ? "scope:" + profile.occurrence_scope : "tool:" + profile.tool;

export function occurrenceKey(person: string, profile: Record<string, any>, args: Record<string, unknown>): OccurrenceKey | null {
  return Object.hasOwn(profile, "occurrence") ? [person, scope(profile), args[profile.occurrence] as string] : null;
}

/** Spec 5.1: while records exist in a tool's scope, the tool cannot move to another scope or drop its occurrence,
 * or an order that already ran could run again. Moving records is the store owner's job. `old` is the profile
 * registered earlier in this process. On a first registration, records under the tool's own name (it ran without a
 * scope before a restart) still block a named scope. A move between named scopes across a restart needs a durable
 * store that remembers each tool's scope. */
export function checkScopeChange(store: OccurrenceStore, old: Record<string, any> | null, next: Record<string, any>): void {
  const refuse = (tool: string, s: string) => { throw new Error(`${tool} has occurrence records in ${s}; move them before changing its occurrence or scope`); };
  if (old === null) {
    const own = scope({ tool: next.tool });
    if (Object.hasOwn(next, "occurrence_scope") && store.hasScope !== undefined && store.hasScope(own)) refuse(next.tool, own);
    return;
  }
  if (!Object.hasOwn(old, "occurrence")) return;
  if (scope(old) === scope(next) && Object.hasOwn(next, "occurrence")) return;
  if (store.hasScope === undefined || store.hasScope(scope(old))) refuse(old.tool, scope(old));
}

function refuse(state: string | null): void {
  if (state === "ok") throw new OACError("duplicate_occurrence", "this occurrence already ran");
  if (state === "running" || state === "unknown") throw new OACError("occurrence_unresolved", "an earlier attempt has no known outcome yet");
}

/** Refuse early, before the person is asked, when the occurrence cannot run now. */
export function checkOpen(store: OccurrenceStore, key: OccurrenceKey | null): void {
  if (key !== null) refuse(store.state(key));
}

export function claim(store: OccurrenceStore, key: OccurrenceKey | null): OccurrenceKey | null {
  if (key === null) return null;
  refuse(store.claim(key));
  return key;
}

/** Record what the provider says happened. A "running" record left by a crash counts as unknown. */
export function resolve(store: OccurrenceStore, key: OccurrenceKey, outcome: string): void {
  const state = store.state(key);
  if ((outcome !== "ok" && outcome !== "failed") || (state !== "running" && state !== "unknown")) {
    throw new Error("only an attempt with no known outcome can be resolved, to ok or failed");
  }
  store.finish(key, outcome);
}
