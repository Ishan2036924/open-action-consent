import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { run } from "../src/conformance.ts";

const VECTORS = fileURLToPath(new URL("../../../vectors", import.meta.url));

test("every shared vector passes", () => {
  const { total, failures } = run(VECTORS);
  assert.ok(total >= 100, `only ${total} cases`);
  assert.deepEqual(failures, []);
});
