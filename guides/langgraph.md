# OAC for LangGraph

Install: `pip install "open-action-consent[langgraph]"`.

Wrap the action inside any node with `gated`. Tier C pauses the graph with LangGraph's own `interrupt`, carrying the
OAC Preview; resume with the person's signed Consent.

```python
from langgraph.types import Command
from oac.gate import Gate
from oac.langgraph import gated

gate = Gate(executor="https://app.example/oac", key=executor_key, signers=signer_keys)
gate.profile("book_table", effect="write", undo="compensate", window_s=86400,
             binds={"payee": "restaurant", "when": "time", "count": "party"})

def book(state):
    return {"result": gated(gate, "book_table", state["args"], book_table, person=state["person"], tainted=state["tainted"])}

out = app.invoke({"args": args}, cfg)                       # -> out["__interrupt__"][0].value == {"oac": "consent", "preview": ...}
out = app.invoke(Command(resume={"consent": token}), cfg)   # runs only if the signed Consent verifies
```

A resume with anything else (`{"approved": True}`, a forged signature) returns `NOT_APPROVED` and nothing runs.
LangGraph re-runs the node from the top on resume; the Gate reuses the pending Preview so the signature still matches.
Tests run a real `StateGraph` with `InMemorySaver`.
