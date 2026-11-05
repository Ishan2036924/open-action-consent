// Conformance runner: `node src/conformance.ts <vectors dir>`. Runs every case in vectors/*.json and exits non-zero
// if any result differs from the expected one. Same files as the Python runner.

import * as fs from "node:fs";
import * as path from "node:path";
import { OACError } from "./errors.ts";
import { canonical, parse } from "./jcs.ts";
import { digest, KeySet, sign } from "./jws.ts";
import * as shapes from "./shapes.ts";
import { tierFor } from "./tiers.ts";
import { checkBinding } from "./preview.ts";
import { MemoryNonces, verifyConsent } from "./consent.ts";
import { checkMandate, loosens } from "./mandate.ts";
import { verifyChain } from "./receipts.ts";
import { checkUndo } from "./undo.ts";
import { vectorKey } from "./testing.ts";

const OK = { ok: true };
const OPS: Record<string, (i: any) => unknown> = {
  jcs: (i) => ({ canonical: canonical(i.value) }),
  parse: (i) => ({ canonical: canonical(parse(i.text)) }),
  digest: (i) => ({ digest: digest(i.value) }),
  tier: (i) => ({ tier: tierFor(i.profile, { policyFloor: i.policy_floor, tainted: i.tainted, hint: i.hint }) }),
  sign: (i) => ({ token: sign(i.payload, vectorKey(i.key, i.alg ?? "EdDSA"), i.typ) }),
  profile: (i) => (shapes.profile(i.profile), OK),
  binding: (i) => (checkBinding(i.preview, i.action, i.profile), OK),
  verify_consent: (i) => (verifyConsent(i.token, {
    keys: new KeySet(i.keys), executor: i.executor, previews: i.previews, actions: i.actions, profiles: i.profiles,
    now: i.now, nonces: new MemoryNonces(i.seen_nonces ?? []), policyFloor: i.policy_floor, tainted: i.tainted ?? false,
  }), OK),
  check_mandate: (i) => (checkMandate(i.token, {
    keys: new KeySet(i.keys), action: i.action, profile: i.profile, holder: i.holder, now: i.now, usage: i.usage, tainted: i.tainted ?? false,
  }), OK),
  loosens: (i) => ({ reasons: loosens(i.old, i.new).sort() }),
  verify_chain: (i) => (verifyChain(i.tokens, { keys: new KeySet(i.keys), executor: i.executor, sub: i.sub }), OK),
  check_undo: (i) => (checkUndo(i.token, {
    keys: new KeySet(i.keys), executor: i.executor, receiptToken: i.receipt_token, receiptKeys: new KeySet(i.receipt_keys),
    now: i.now, nonces: new MemoryNonces(i.seen_nonces ?? []),
  }), OK),
};

export function runCase(c: any): unknown {
  try {
    return OPS[c.op](c.input);
  } catch (e) {
    if (e instanceof OACError) return { error: e.code };
    throw e;
  }
}

export function run(dir: string): { total: number; failures: string[] } {
  let total = 0;
  const failures: string[] = [];
  for (const name of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    for (const c of JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")).cases) {
      total += 1;
      let got: unknown;
      try { got = runCase(c); } catch (e) { got = { crash: String(e) }; }
      if (canonical(got) !== canonical(c.expect)) failures.push(`${name} :: ${c.name}: expected ${JSON.stringify(c.expect)}, got ${JSON.stringify(got)}`);
    }
  }
  return { total, failures };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { total, failures } = run(process.argv[2] ?? "vectors");
  for (const f of failures) console.log("FAIL", f);
  console.log(`oac conformance (typescript): ${total - failures.length}/${total} passed`);
  process.exit(failures.length ? 1 : 0);
}
