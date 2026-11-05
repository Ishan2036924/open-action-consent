// Business occurrences (spec 5.1): one order, one payment, one booking runs at most once, even across fresh
// Consents after a timeout.

import { OACError } from "./errors.ts";

export type OccurrenceKey = [person: string, tool: string, occurrence: string];

export interface OccurrenceStore {
  /** Atomically mark the key running and return null if it is new or its last attempt failed; otherwise change
   * nothing and return its state (running, unknown or ok). */
  claim(key: OccurrenceKey): string | null;
  finish(key: OccurrenceKey, outcome: string): void;
  /** Drop a claim whose action never started (for example, the Consent was refused). */
  release(key: OccurrenceKey): void;
  state(key: OccurrenceKey): string | null;
}

/** For tests and examples. A production store keeps the same states in a table with a unique key. */
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

export function claim(store: OccurrenceStore, key: OccurrenceKey | null): OccurrenceKey | null {
  if (key === null) return null;
  const state = store.claim(key);
  if (state === "ok") throw new OACError("duplicate_occurrence", "this occurrence already ran");
  if (state !== null) throw new OACError("occurrence_unresolved", "an earlier attempt has no known outcome yet");
  return key;
}
