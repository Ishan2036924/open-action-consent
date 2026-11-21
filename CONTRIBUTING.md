# Contributing

Thank you for helping. OAC is small on purpose; every rule must be checkable, and both SDKs must agree byte for byte.

## Run everything

```
tools/check_all.sh            # PYTHON=/path/to/python to choose an interpreter
```

Python needs `cryptography` and `pytest` (`hypothesis` for the fuzz tests, `jsonschema` for the schema check, `ruff`
for lint; `pip install --require-hashes -r ci/test.txt` gets all of them). TypeScript needs only Node 23.6+ (`npm ci`
in `sdk/typescript` adds fast-check for its fuzz tests). The fuzz tests are seeded; `OAC_FUZZ_EXAMPLES=5000` runs
them longer.

## How a change lands

Every change comes in as a pull request against `main`; nothing is pushed to `main` directly. The required CI checks
(`python`, `typescript`, `browser-tools`, `agent-frameworks`) must pass before a maintainer merges it; `fuzz` and
CodeQL run on every pull request too, and a failure there is fixed, not waved through. Security problems do
not go in a pull request or a public issue: report them privately as `SECURITY.md` says.

1. **Spec first.** Say in `spec/` what a verifier must do and which error code it reports, in which order.
2. **Vectors next.** Add cases to `tools/make_vectors.py` with the expected result written by hand from the spec,
   including at least one planted defect the new rule must refuse. Run it: it stops if the Python SDK disagrees.
3. **Both SDKs.** Implement in `sdk/python` and `sdk/typescript`. Both must pass every vector.
4. **Prove the check matters.** Add a mutation to `sdk/python/tests/test_conformance.py` that switches the new check
   off and names a vector that must then fail.
5. **Schemas.** Update `schemas/` if an object's shape changes; `tools/check_schemas.py` must pass.
6. **Changelog.** One line in `CHANGELOG.md`.

## Rules of thumb

- Integers only: money in minor units, time in unix seconds.
- No new dependency in the SDKs without a strong reason (Python: `cryptography` only; TypeScript: none).
- Match text, not parsed forms, wherever two languages could normalize differently (URLs, Unicode, gzip).
- Never let a model, an agent or a page set a tier, approve, or report its own taint.

By contributing you agree that code is licensed under Apache-2.0 and spec text under CC BY 4.0 (see `NOTICE`).
Be kind and constructive; we follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
