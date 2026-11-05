"""A tiny MCP 2026-07-28 server that uses the OAC extension (spec/mcp-extension.md). Illustration only: one person,
an in-memory store, fake bookings.

Tools:
  book_table  tier C (compensate undo): asks for a Consent through a URL-mode elicitation, then books
  add_task    tier B (native undo): runs at once and returns a receipt with an undo token
  oac_undo    takes a signed undo request and a receipt

`handle(message)` answers one JSON-RPC message; run this file to serve over stdio. The consent page is simulated by
`receive_consent`, standing in for the person's signer posting the signed Consent to the executor."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python" / "src"))

from oac import (  # noqa: E402
    KeySet,
    MemoryNonces,
    OACError,
    action_digest,
    build_preview,
    check_undo,
    digest,
    generate,
    make_receipt,
    parse,
    tier_for,
    token_digest,
    verify,
    verify_consent,
)
from oac.jcs import canonical_bytes  # noqa: E402
from oac.jws import b64url, b64url_decode  # noqa: E402

EXT = "com.atlasiw/oac"
VERSION = "2026-07-28"
EXECUTOR = "https://tables.example/oac"


def profile(tool: str, effect: str, kind: str, window: int, binds: dict[str, str]) -> dict[str, Any]:
    return {"oac": "0.1", "type": "action-profile", "tool": tool, "effect": effect,
            "undo": {"kind": kind, "window_s": window}, "tier_floor": "A", "binds": binds}


PROFILES = {
    "book_table": profile("book_table", "write", "compensate", 86400, {"payee": "restaurant", "when": "time", "count": "party"}),
    "add_task": profile("add_task", "write", "native", 600, {"title": "title"}),
    "oac_undo": profile("oac_undo", "write", "none", 0, {}),
}
PROFILES["oac_undo"]["other_args"] = ["request", "receipt"]
SCHEMAS = {
    "book_table": {"type": "object", "required": ["restaurant", "time", "party"],
                   "properties": {"restaurant": {"type": "string"}, "time": {"type": "string"}, "party": {"type": "integer"}}},
    "add_task": {"type": "object", "required": ["title"], "properties": {"title": {"type": "string"}}},
    "oac_undo": {"type": "object", "required": ["request", "receipt"],
                 "properties": {"request": {"type": "string"}, "receipt": {"type": "string"}}},
}


class Server:
    def __init__(self, *, person: str, signers: dict[str, list[dict[str, Any]]]) -> None:
        self.person = person  # stdio has no sign-in; a real server takes the principal from MCP authorization
        self.key = generate()
        self.signer_keys = KeySet(signers)  # {signer iss: [public JWK]}
        self.own_keys = KeySet({EXECUTOR: [self.key.jwk]})
        self.state_secret = secrets.token_bytes(32)
        self.previews: dict[str, dict[str, Any]] = {}  # preview id -> preview
        self.consents: dict[str, str] = {}  # preview digest -> consent token
        self.nonces = MemoryNonces()
        self.receipts: list[str] = []
        self.tasks: dict[str, str] = {}
        self.undo_tokens: dict[str, str] = {}  # undo token -> task id
        self.undone: set[str] = set()  # token digests of receipts already undone

    # ---- consent page stand-in (server-to-server, never through the MCP client or the model)
    def preview_for_page(self, preview_id: str) -> dict[str, Any]:
        return self.previews[preview_id]

    def receive_consent(self, token: str) -> bool:
        """Keep a Consent only if a trusted signer signed it, for this person and this executor, over a pending
        preview; never replace one already kept (so a stray post cannot block the person's approval)."""
        try:
            payload = verify(token, self.signer_keys, "oac-consent+jws")
        except OACError:
            return False
        if payload.get("aud") != EXECUTOR or payload.get("sub") != self.person:
            return False
        pending = {digest(p) for p in self.previews.values()}
        kept = False
        for item in payload.get("items", []):
            if item.get("preview") in pending and item["preview"] not in self.consents:
                self.consents[item["preview"]] = token
                kept = True
        return kept

    # ---- helpers
    def _state(self, fields: dict[str, Any]) -> str:
        body = b64url(canonical_bytes(fields))
        return body + "." + b64url(hmac.new(self.state_secret, body.encode(), hashlib.sha256).digest())

    def _read_state(self, state: str) -> dict[str, Any]:
        body, _, mac = state.partition(".")
        good = b64url(hmac.new(self.state_secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, good):
            raise OACError("malformed", "requestState failed its integrity check")
        fields = parse(b64url_decode(body))
        if fields["sub"] != self.person or time.time() > fields["exp"]:
            raise OACError("expired", "requestState is for someone else or too old")
        return fields

    def _receipt(self, tool: str, tier: str, authority: dict[str, Any], action: dict[str, Any], result: Any,
                 undo: dict[str, Any], **extra: Any) -> str:
        token = make_receipt(key=self.key, payload={
            "iss": EXECUTOR, "sub": self.person, "seq": len(self.receipts) + 1,
            "prev": token_digest(self.receipts[-1]) if self.receipts else None, "iat": int(time.time()), "tool": tool,
            "tier": tier, "authority": authority, "action": action_digest(action), "outcome": "ok",
            "result": digest(result), "undo": undo, **extra})
        self.receipts.append(token)
        return token

    @staticmethod
    def _done(text: str, receipt: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"resultType": "complete", "content": [{"type": "text", "text": text}]}
        if receipt:
            out["_meta"] = {f"{EXT}-receipt": receipt}
        return out

    @staticmethod
    def _refused(text: str) -> dict[str, Any]:
        return {"resultType": "complete", "isError": True, "content": [{"type": "text", "text": text}]}

    # ---- tools
    def _book(self, params: dict[str, Any], caps: dict[str, Any]) -> dict[str, Any]:
        action = {"tool": "book_table", "args": params["arguments"]}
        now = int(time.time())
        if "requestState" not in params:
            p = build_preview(profile=PROFILES["book_table"], action=action, executor=EXECUTOR, sub=self.person, now=now,
                              summary=f"Book {action['args']['restaurant']}, {action['args']['time']}, {action['args']['party']} people.",
                              cancel_policy={"text": "Free cancellation until 24 h before."})
            self.previews[p["id"]] = p
            state = self._state({"sub": self.person, "preview": digest(p), "preview_id": p["id"],
                                 "action": action_digest(action), "exp": now + 600})
            return {"resultType": "input_required",
                    "inputRequests": {"oac_consent": {"method": "elicitation/create", "params": {
                        "mode": "url", "url": f"https://signer.example/oac/consent?r={p['id']}", "message": "Approve: " + p["summary"]}}},
                    "requestState": state, "_meta": {f"{EXT}-preview": p}}
        st = self._read_state(params["requestState"])
        if params.get("inputResponses", {}).get("oac_consent", {}).get("action") != "accept":
            return self._refused("The person did not approve. Nothing was booked.")
        token = self.consents.get(st["preview"])
        if token is None:
            return self._refused("No signed approval has arrived yet. Nothing was booked.")
        try:
            consent = verify_consent(token, keys=self.signer_keys, executor=EXECUTOR, sub=self.person,
                                     previews=[self.previews[st["preview_id"]]],
                                     actions=[action], profiles=PROFILES, now=now, nonces=self.nonces)
        except OACError as e:
            return self._refused(f"Refused ({e.code}). Nothing was booked.")
        receipt = self._receipt("book_table", "C", {"kind": "consent", "ref": consent["jti"]}, action,
                                {"confirmation": "NB-2231"}, {"kind": "compensate", "until": now + 86400},
                                preview=st["preview"])
        return self._done("Booked. Confirmation NB-2231.", receipt)

    def _add_task(self, params: dict[str, Any]) -> dict[str, Any]:
        action = {"tool": "add_task", "args": params["arguments"]}
        task_id, undo_token = "t" + secrets.token_hex(4), "u_" + secrets.token_urlsafe(9)
        self.tasks[task_id], self.undo_tokens[undo_token] = action["args"]["title"], task_id
        receipt = self._receipt("add_task", tier_for(PROFILES["add_task"]), {"kind": "tier"}, action, {"id": task_id},
                                {"kind": "native", "until": int(time.time()) + 600, "token": undo_token})
        return self._done(f"Added task {task_id}.", receipt)

    def _undo(self, params: dict[str, Any]) -> dict[str, Any]:
        args = params["arguments"]
        try:
            r = verify(args["receipt"], self.own_keys, "oac-receipt+jws")
            if r["undo"]["kind"] != "native":
                return self._refused("This example only undoes native actions; a cancel goes through its own approval.")
            req = check_undo(args["request"], keys=self.signer_keys, executor=EXECUTOR, receipt_token=args["receipt"],
                             receipt_keys=self.own_keys, now=int(time.time()), nonces=self.nonces, undone=self.undone)
        except OACError as e:
            return self._refused(f"Undo refused ({e.code}).")
        self.undone.add(req["receipt"])
        self.tasks.pop(self.undo_tokens.pop(r["undo"]["token"]), None)
        receipt = self._receipt(r["tool"], r["tier"], {"kind": "undo", "ref": req["jti"]}, {"tool": "oac_undo", "args": {}},
                                {"undone": True}, {"kind": "none"}, undoes=req["receipt"])
        return self._done("Undone.", receipt)

    # ---- JSON-RPC
    def handle(self, msg: dict[str, Any]) -> dict[str, Any]:
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params", {})
        meta = params.get("_meta", {})
        if meta.get("io.modelcontextprotocol/protocolVersion") is None or "io.modelcontextprotocol/clientCapabilities" not in meta:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "missing per-request _meta"}}
        if meta["io.modelcontextprotocol/protocolVersion"] != VERSION:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32022, "message": "Unsupported protocol version",
                                                           "data": {"supported": [VERSION], "requested": meta["io.modelcontextprotocol/protocolVersion"]}}}
        caps = meta["io.modelcontextprotocol/clientCapabilities"]
        if method == "server/discover":
            result = {"resultType": "complete", "supportedVersions": [VERSION],
                      "capabilities": {"tools": {}, "extensions": {EXT: {"version": "0.1", "executor": EXECUTOR}}},
                      "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "oac-example-tables", "version": "0.1.0"}}}
        elif method == "tools/list":
            result = {"resultType": "complete", "tools": [
                {"name": n, "description": n.replace("_", " "), "inputSchema": SCHEMAS[n], "_meta": {f"{EXT}-profile": PROFILES[n]}}
                for n in PROFILES]}
        elif method == "tools/call":
            name = params.get("name")
            tier = tier_for(PROFILES[name]) if name in PROFILES else None
            if tier == "C" and not (EXT in caps.get("extensions", {}) and "url" in caps.get("elicitation", {})):
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32021, "message": "Missing required client capability",
                        "data": {"requiredCapabilities": {"extensions": {EXT: {}}, "elicitation": {"url": {}}}}}}
            handler = {"book_table": lambda: self._book(params, caps), "add_task": lambda: self._add_task(params),
                       "oac_undo": lambda: self._undo(params)}.get(name)
            if handler is None:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
            result = handler()
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> None:  # stdio: one JSON-RPC message per line
    config = json.loads(Path(sys.argv[1]).read_text()) if len(sys.argv) > 1 else {"person": "person:demo", "signers": {}}
    server = Server(person=config["person"], signers=config["signers"])
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(server.handle(json.loads(line))), flush=True)


if __name__ == "__main__":
    main()
