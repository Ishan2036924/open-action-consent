#!/usr/bin/env bash
# Every check. After a spec change, regenerate vectors first: python tools/make_vectors.py
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
PYTHONPATH=sdk/python/src "$PY" -m oac.conformance vectors
(cd sdk/python && "$PY" -m pytest -q)  # integrations without their extras installed are skipped
node sdk/typescript/src/conformance.ts vectors
if [ -d sdk/typescript/node_modules/typescript ]; then (cd sdk/typescript && npm run build --silent && node dist/conformance.js ../../vectors && npm test --silent); else echo "skip: TypeScript build and integration tests (npm ci in sdk/typescript)"; fi
if "$PY" -c "import jsonschema" 2>/dev/null; then "$PY" tools/check_schemas.py; else echo "skip: schemas (pip install jsonschema)"; fi
"$PY" tools/test_release_notes.py  # release pages come from the changelog; the SDK version needs a dated section
"$PY" tools/test_fetch_published.py 2>&1 | tail -1  # release signing takes only bytes matching the registries' digests
if "$PY" -c "import tomllib" 2>/dev/null; then "$PY" tools/check_ci_locks.py && "$PY" tools/test_check_ci_locks.py 2>&1 | tail -1; else echo "skip: CI lock check (Python 3.11+)"; fi
"$PY" examples/mcp-server/demo.py > /dev/null && echo "demo: ok"
if "$PY" -m ruff --version > /dev/null 2>&1; then "$PY" -m ruff check . && echo "ruff: ok"; else echo "skip: ruff (pip install --require-hashes -r ci/test.txt)"; fi
