#!/usr/bin/env bash
# Run every check: both SDKs' conformance + tests, schemas (needs jsonschema), the demo. Regenerating vectors is a
# separate step (python tools/make_vectors.py) after a spec change.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
PYTHONPATH=sdk/python/src "$PY" -m oac.conformance vectors
(cd sdk/python && "$PY" -m pytest -q)  # integrations without their extras installed are skipped
node sdk/typescript/src/conformance.ts vectors
if [ -d sdk/typescript/node_modules/typescript ]; then (cd sdk/typescript && npm run build --silent && node dist/conformance.js ../../vectors && npm test --silent); else echo "skip: TypeScript build and integration tests (npm ci in sdk/typescript)"; fi
if "$PY" -c "import jsonschema" 2>/dev/null; then "$PY" tools/check_schemas.py; else echo "skip: schemas (pip install jsonschema)"; fi
"$PY" examples/mcp-server/demo.py > /dev/null && echo "demo: ok"
