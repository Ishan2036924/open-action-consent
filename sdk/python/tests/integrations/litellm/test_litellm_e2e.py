"""End to end: the real LiteLLM proxy from a config.yaml, its MCP gateway in front of a local stdio MCP server, and the
OAC guardrail deciding every tool call. The send tool writes to a file, so "it ran" and "it did not" are facts."""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

pytest.importorskip("litellm.proxy.proxy_server")
pytest.importorskip("mcp.server.mcpserver")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from oac import KeySet, generate, make_consent, verify_chain  # noqa: E402
from oac.jws import ed25519_key  # noqa: E402

MASTER = "sk-test-master-key"
EX, SIGNER = "https://gateway.example/oac", "https://signer.example"
PERSON = "user_id:default_user_id"  # who the master key acts for in LiteLLM
SERVER = '''
import sys
from mcp.server.mcpserver import MCPServer

OUT = sys.argv[1]
server = MCPServer("mail")


@server.tool()
def read_note(title: str) -> str:
    return "note " + title


@server.tool()
def send_email(to: list[str], subject: str, body: str) -> str:
    with open(OUT, "a") as fh:
        fh.write(",".join(to) + "|" + subject + "\\n")
    return "sent"


server.run("stdio")
'''


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    folder = tmp_path_factory.mktemp("oac-litellm")
    (folder / "server.py").write_text(SERVER)
    sent = folder / "sent.txt"
    private = Ed25519PrivateKey.generate()
    (folder / "executor.pem").write_bytes(private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    signer = generate()
    (folder / "signers.json").write_text(json.dumps({SIGNER: [signer.jwk]}))
    (folder / "profiles.json").write_text(json.dumps({
        "mail/read_note": {"effect": "read", "binds": {"title": "title"}},
        "mail/send_email": {"effect": "send", "binds": {"to": "to", "title": "subject"}, "other_args": ["body"]},
    }))
    config = folder / "config.yaml"
    config.write_text(f"""
model_list: []
mcp_servers:
  mail:
    transport: stdio
    command: {sys.executable}
    args: ["{folder / 'server.py'}", "{sent}"]
guardrails:
  - guardrail_name: oac
    litellm_params:
      guardrail: oac.litellm.OACGuardrail
      mode: [pre_mcp_call]
      default_on: true
      executor: {EX}
      key_file: {folder / 'executor.pem'}
      signers_file: {folder / 'signers.json'}
      profiles_file: {folder / 'profiles.json'}
      receipts_dir: {folder / 'receipts'}
      consent_url: "https://approve.example/consent?preview={{id}}"
general_settings:
  master_key: {MASTER}
""")
    env = {"CONFIG_FILE_PATH": str(config), "LITELLM_TELEMETRY": "False", "LITELLM_ENABLE_MCP_STDIO": "true"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    from litellm.proxy.proxy_server import app

    with TestClient(app) as client:
        yield client, signer, ed25519_key(private), folder, sent
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def tool(client, name, args, **headers):
    return client.post("/mcp-rest/tools/call", headers={"Authorization": f"Bearer {MASTER}", **headers},
                       json={"server_id": "mail", "name": f"mail-{name}", "arguments": args})


def chain(folder, executor_key):
    files = list((folder / "receipts").iterdir())
    assert len(files) == 1
    return verify_chain(files[0].read_text().split(), keys=KeySet({EX: [executor_key.jwk]}), executor=EX, sub=PERSON)


def wait_for(predicate, seconds=5.0):
    """Outcome events are logged just after the response; give them a moment."""
    end = time.time() + seconds
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_send_is_held_until_the_person_signs_then_runs_once(gateway):
    client, signer, executor_key, folder, sent = gateway
    mail = {"to": ["pat@example.org"], "subject": "Lunch", "body": "Friday at noon?"}

    first = tool(client, "send_email", mail)
    assert first.status_code == 403, first.text
    ask = first.json()["detail"]
    assert ask["error"] == "oac_consent_required" and ask["consent_url"].endswith(ask["preview"]["id"])
    assert not sent.exists()  # nothing ran

    # the model swaps the recipient after the person saw the Preview: a new action, still held
    token = make_consent(key=signer, iss=SIGNER, sub=PERSON, aud=EX, previews=[ask["preview"]], now=int(time.time()))
    swapped = tool(client, "send_email", {**mail, "to": ["attacker@evil.example"]}, **{"x-oac-consent": token})
    assert swapped.status_code == 403 and not sent.exists()

    ok = tool(client, "send_email", mail, **{"x-oac-consent": token})
    assert ok.status_code == 200, ok.text
    assert sent.read_text() == "pat@example.org|Lunch\n"

    replay = tool(client, "send_email", mail, **{"x-oac-consent": token})
    assert replay.status_code == 403
    assert sent.read_text() == "pat@example.org|Lunch\n"  # still exactly once

    assert wait_for(lambda: (folder / "receipts").exists() and len(chain(folder, executor_key)) >= 1)
    receipts = chain(folder, executor_key)
    assert [(r["tool"], r["tier"], r["authority"]["kind"], r["outcome"]) for r in receipts] == [
        ("mail/send_email", "C", "consent", "ok")]


def test_a_read_runs_and_an_unprofiled_or_malformed_call_does_not(gateway):
    client, _, executor_key, folder, _ = gateway
    before = len(chain(folder, executor_key)) if (folder / "receipts").exists() else 0
    r = tool(client, "read_note", {"title": "plan"})
    assert r.status_code == 200, r.text and "note plan" in r.text
    assert tool(client, "read_note", {"title": "plan", "approved": True}).status_code == 403
    assert wait_for(lambda: len(chain(folder, executor_key)) == before + 1)
    assert chain(folder, executor_key)[-1]["tier"] == "A"


def test_the_outcome_event_carries_this_call_s_own_ticket(gateway, monkeypatch):
    """Several tool calls can share one LiteLLM call id, so each outcome must find its ticket on the call itself."""
    import litellm

    from oac.litellm import OACGuardrail

    client, _, _, _, _ = gateway
    (g,) = [cb for cb in litellm.callbacks if isinstance(cb, OACGuardrail)]
    seen = []
    take = OACGuardrail._take

    def spy(self, kwargs):
        seen.append("oac_ticket" in kwargs)
        return take(self, kwargs)

    monkeypatch.setattr(OACGuardrail, "_take", spy)
    assert tool(client, "read_note", {"title": "x"}).status_code == 200
    assert wait_for(lambda: seen == [True])
    assert wait_for(lambda: g.tickets == {} and g.by_call == {})
