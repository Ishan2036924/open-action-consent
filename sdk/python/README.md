# oac (Python)

Reference SDK for Open Action Consent 0.1. Needs Python 3.10+ and `cryptography`.

```python
from oac import build_preview, make_consent, verify_consent, KeySet, MemoryNonces
```

Tests: `python -m pytest -q` (from this folder). Conformance: `PYTHONPATH=src python -m oac.conformance ../../vectors`.
