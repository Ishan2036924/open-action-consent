// Business occurrences (spec 5.1): one order or payment runs at most once.

import { OACError } from "./errors.ts";

export type OccurrenceKey = [person: string, tool: string, occurrence: string];

export interface OccurrenceStore {
  /** Mark the key running and return null, or return its blocking state. Must be atomic. */
  claim(key: OccurrenceKey): string | null;
  finish(key: OccurrenceKey, outcome: string): void;
  /** Drop a claim whose action never started. */
  release(key: OccurrenceKey): void;
  state(key: OccurrenceKey): string | null;
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
}

export function occurrenceKey(person: string, profile: Record<string, any>, args: Record<string, unknown>): OccurrenceKey | null {
  return Object.hasOwn(profile, "occurrence") ? [person, profile.tool, args[profile.occurrence] as string] : null;
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
