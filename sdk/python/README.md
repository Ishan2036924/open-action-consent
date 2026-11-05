# open-action-consent (Python)

**A verifiable "yes" for things AI agents do for people.** Before an agent sends, books, pays or deletes, the tool
shows a Preview of exactly what will happen; the person signs a Consent over it; the action runs only if the signature
and the limits check out; a signed Receipt says what ran and how to undo it.
Spec and source: <https://github.com/Ishan2036924/open-action-consent>

## Everything in this one package

| Part | Install | Use | Guide |
|---|---|---|---|
| Core: previews, consents, mandates, receipts, undo, status lists, key discovery, `Gate` | `pip install open-action-consent` | `import oac` | [README](https://github.com/Ishan2036924/open-action-consent#readme) |
| MCP servers (official MCP Python SDK, protocol 2026-07-28) | `pip install "open-action-consent[mcp]"` | `from oac.mcp import OACExtension` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/mcp-python.md) |
| Gated Browser (stops before every final click) | `pip install "open-action-consent[browser]"` then `playwright install chromium` | `oac-gated-browser` or `from oac.browser import build_server` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/gated-browser.md) |
| Approval page (the person's key stays in their browser) | `pip install "open-action-consent[approver]"` | `from oac.approver import Approver` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/approver.md) |
| OpenAI Agents SDK | `pip install "open-action-consent[openai-agents]"` | `from oac.openai_agents import oac_tool` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/openai-agents.md) |
| LangGraph | `pip install "open-action-consent[langgraph]"` | `from oac.langgraph import gated` | [guide](https://github.com/Ishan2036924/open-action-consent/blob/main/guides/langgraph.md) |
| All of the above | `pip install "open-action-consent[all]"` | | |

The core needs only `cryptography`. Each part pulls in its framework only when you install that option; importing a
part without it tells you exactly what to install. JavaScript/TypeScript: `npm install open-action-consent`.

Tests: `python -m pytest -q` (from this folder); conformance: `PYTHONPATH=src python -m oac.conformance ../../vectors`.
License: Apache-2.0 (code), CC BY 4.0 (spec text).
