"""Walk through OAC over MCP with the example server. Run: python examples/mcp-server/demo.py"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python" / "src"))

from oac import KeySet, generate, make_consent, make_undo, verify, verify_chain  # noqa: E402
from server import EXECUTOR, EXT, Server  # noqa: E402

PERSON = "person:demo"
SIGNER = "https://signer.example"
signer_key = generate()  # held by the person's signer; the "model" below never touches it
server = Server(person=PERSON, signers={SIGNER: [signer_key.jwk]})
CAPS = {"elicitation": {"url": {}}, "extensions": {EXT: {"version": "0.2"}}}
_id = 0


def call(method: str, params: dict[str, Any] | None = None, caps: dict[str, Any] = CAPS) -> dict[str, Any]:
    global _id
    _id += 1
    p = dict(params or {})
    p["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": caps}
    reply = json.loads(json.dumps(server.handle(json.loads(json.dumps({"jsonrpc": "2.0", "id": _id, "method": method, "params": p})))))
    return reply


def say(step: str, text: str) -> None:
    print(f"\n[{step}] {text}")


def consent_page(preview_id: str) -> None:
    """The person's signer: shows the Preview, proves the person is there, signs, posts to the executor."""
    p = server.preview_for_page(preview_id)
    print(f"    consent page shows: {p['summary']} | fields {p['fields']} | undo: {p['undo']['kind']}")
    junk = make_consent(key=generate(), iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[p], now=int(time.time()))
    print(f"    a stray post with an untrusted key arrives first -> kept: {server.receive_consent(junk)}")
    kept = server.receive_consent(make_consent(key=signer_key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, previews=[p], now=int(time.time())))
    print(f"    person taps Approve; the signer posts the signed Consent to the executor -> kept: {kept}")


disc = call("server/discover")["result"]
say("discover", f"server supports {disc['supportedVersions']} and extension {list(disc['capabilities']['extensions'])}")
tools = call("tools/list")["result"]["tools"]
say("tools", ", ".join(f"{t['name']} ({t['_meta'][EXT + '-profile']['effect']}, undo {t['_meta'][EXT + '-profile']['undo']['kind']})" for t in tools))

args = {"restaurant": "Nobu Boston", "time": "Fri 6 Nov 7:30 pm", "party": 2}
first = call("tools/call", {"name": "book_table", "arguments": args})["result"]
req = first["inputRequests"]["oac_consent"]["params"]
say("book 1/2", f"server answers {first['resultType']}: open {req['url']}")
consent_page(first["_meta"][EXT + "-preview"]["id"])
retry = {"name": "book_table", "arguments": args, "inputResponses": {"oac_consent": {"action": "accept"}}, "requestState": first["requestState"]}

attack = call("tools/call", {**retry, "arguments": {**args, "party": 20}})["result"]
say("attack 1", f"model retries with party 20 instead of 2 -> {attack['content'][0]['text']}")

done = call("tools/call", retry)["result"]
receipt = done["_meta"][EXT + "-receipt"]
say("book 2/2", f"{done['content'][0]['text']} Receipt tier {verify(receipt, KeySet({EXECUTOR: [server.key.jwk]}), 'oac-receipt+jws')['tier']}")

again = call("tools/call", retry)["result"]
say("attack 2", f"the same approval replayed -> {again['content'][0]['text']}")

no_ext = call("tools/call", {"name": "book_table", "arguments": args}, caps={})
say("old client", f"a client without the extension gets error {no_ext['error']['code']} ({no_ext['error']['message']}); nothing runs")

task = call("tools/call", {"name": "add_task", "arguments": {"title": "Call the dentist"}})["result"]
task_receipt = task["_meta"][EXT + "-receipt"]
say("task", f"{task['content'][0]['text']} (tier B: ran at once, receipt has an undo token); tasks now {list(server.tasks.values())}")
undo_req = make_undo(key=signer_key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, receipt_token=task_receipt, mode="native", now=int(time.time()))
undone = call("tools/call", {"name": "oac_undo", "arguments": {"request": undo_req, "receipt": task_receipt}})["result"]
say("undo", f"{undone['content'][0]['text']} tasks now {list(server.tasks.values())}")
undo_again = make_undo(key=signer_key, iss=SIGNER, sub=PERSON, aud=EXECUTOR, receipt_token=task_receipt, mode="native", now=int(time.time()))
twice = call("tools/call", {"name": "oac_undo", "arguments": {"request": undo_again, "receipt": task_receipt}})["result"]
say("attack 3", f"a second undo of the same task, with a fresh signed request -> {twice['content'][0]['text']}")

chain = verify_chain(server.receipts, keys=KeySet({EXECUTOR: [server.key.jwk]}), executor=EXECUTOR)
say("audit", f"receipt chain verifies offline: {len(chain)} receipts, " + ", ".join(f"#{r['seq']} {r['tool']}/{r['authority']['kind']}" for r in chain))
