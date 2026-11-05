#!/usr/bin/env bash
# Run every check: both SDKs' conformance + tests, schemas (needs jsonschema), the demo. Regenerating vectors is a
# separate step (python tools/make_vectors.py) after a spec change.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
PYTHONPATH=sdk/python/src "$PY" -m oac.conformance vectors
(cd sdk/python && "$PY" -m pytest -q)
node sdk/typescript/src/conformance.ts vectors
if [ -d node_modules/typescript ]; then npm run build --workspaces --silent && node sdk/typescript/dist/conformance.js vectors && npm test --workspaces --silent; else (cd sdk/typescript && node --test test/*.test.ts); echo "skip: TypeScript build and plug-ins (npm ci at the repo root)"; fi
if "$PY" -c "import jsonschema" 2>/dev/null; then "$PY" tools/check_schemas.py; else echo "skip: schemas (pip install jsonschema)"; fi
"$PY" examples/mcp-server/demo.py > /dev/null && echo "demo: ok"
if "$PY" -c "import mcp" 2>/dev/null; then (cd integrations/mcp-python && "$PY" -m pytest -q -p anyio); else echo "skip: MCP Python plug-in (pip install mcp)"; fi
