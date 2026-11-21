"""OAC for MCP tool calls that pass through the LiteLLM proxy's MCP gateway. See guides/litellm.md.

    # config.yaml
    guardrails:
      - guardrail_name: oac
        litellm_params:
          guardrail: oac.litellm.OACGuardrail
          mode: [pre_mcp_call]
          default_on: true
          executor: https://gateway.example/oac
          key_file: /etc/oac/executor.pem       # Ed25519 private key (PEM) that signs receipts
          signers_file: /etc/oac/signers.json   # {issuer: [public JWK, ...]} allowed to sign Consents
          profiles_file: /etc/oac/profiles.json # {"server/tool": {effect, undo, window_s, tier_floor, binds, ...}}

Every MCP tool call LiteLLM is about to make is checked first:
  - no Action Profile for `server/tool`, or arguments outside it: refused
  - tier A or B: runs, with a signed receipt
  - tier C: runs only with the person's signed Consent for exactly these arguments; until then it is refused with the
    Preview to approve (the Consent reaches the gateway by the intake endpoint, `accept_consent`, or the
    `x-oac-consent` header of a retried call)
  - tier D: refused
The tool's outcome (ok, failed, unknown) closes the attempt with a hash-chained receipt. Every failure refuses.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

try:
    from fastapi import HTTPException
    from litellm.integrations.custom_guardrail import CustomGuardrail
    from litellm.types.guardrails import GuardrailEventHooks
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('oac.litellm needs the LiteLLM proxy: pip install "open-action-consent[litellm]"') from e

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from oac import KeySet, OACError, SigningKey
from oac.gate import ActionFailed, Gate, NeedsConsent, Ticket
from oac.jws import ed25519_key

TESTED = "1.108."  # the LiteLLM line these hooks were read and tested against
try:
    if not version("litellm").startswith(TESTED):
        logging.getLogger(__name__).warning("oac.litellm was tested with LiteLLM %sx, found %s; run its tests before "
                                            "relying on it", TESTED, version("litellm"))
except PackageNotFoundError:  # a source checkout of LiteLLM: nothing to compare
    pass

CALL, LIST = "call_mcp_tool", "list_mcp_tools"
CONSENT_HEADER = "x-oac-consent"
PERSON_FIELDS = {"user_id": "user_api_key_user_id", "team_id": "user_api_key_team_id"}


def _refuse(status: int, kind: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": kind, "message": message, **extra})


def _load_json(path: str | None, inline: Any) -> Any:
    if inline is not None:
        return inline
    if path:
        return json.loads(Path(path).expanduser().read_text())
    return None


def load_executor_key(path: str) -> SigningKey:
    """An Ed25519 private key in PEM, as `openssl genpkey -algorithm ed25519` writes it."""
    private = load_pem_private_key(Path(path).expanduser().read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("key_file must hold an Ed25519 private key")
    return ed25519_key(private)


def _person_file(person: str) -> str:
    return hashlib.sha256(person.encode("utf-8")).hexdigest()[:32] + ".jsonl"


class OACGuardrail(CustomGuardrail):
    def __init__(
        self,
        *,
        executor: str | None = None,
        key_file: str | None = None,
        signers_file: str | None = None,
        signers: Mapping[str, list[Mapping[str, Any]]] | None = None,
        profiles_file: str | None = None,
        profiles: Mapping[str, Mapping[str, Any]] | None = None,
        policy_floor: str = "A",
        tainted: bool = True,
        person_from: str = "user_id",
        consent_url: str | None = None,
        receipts_dir: str | None = None,
        consent_port: int | None = None,
        consent_host: str = "127.0.0.1",
        ticket_timeout_s: int = 900,
        gate: Gate | None = None,
        clock: Callable[[], int] | None = None,
        **kwargs: Any,
    ) -> None:
        """`tainted` says whether outside text (mail, web pages, documents) can reach the agents calling through this
        gateway. Unknown means yes, so the default is True: every action that is not a read then needs a Consent.
        `person_from` names whose action it is: LiteLLM's `user_id` (default) or `team_id` of the calling key, never
        anything the caller writes in a request."""
        if person_from not in PERSON_FIELDS:
            raise ValueError(f"person_from must be one of {sorted(PERSON_FIELDS)}")
        if gate is None:
            if not executor or not key_file:
                raise ValueError("OACGuardrail needs executor and key_file")
            keys = _load_json(signers_file, signers)
            if not keys:
                raise ValueError("OACGuardrail needs signers or signers_file: who may sign a Consent")
            gate = Gate(executor=executor, key=load_executor_key(key_file), signers=KeySet(keys),
                        policy_floor=policy_floor, **({"clock": clock} if clock else {}))
        self.gate = gate
        for tool, spec in (_load_json(profiles_file, profiles) or {}).items():
            gate.profile(tool, **dict(spec))
        if not gate.profiles:
            raise ValueError("OACGuardrail needs profiles or profiles_file: without them every tool call is refused")
        self.tainted = bool(tainted)
        self.person_field = PERSON_FIELDS[person_from]
        self.consent_url = consent_url
        self.receipts_dir = Path(receipts_dir).expanduser() if receipts_dir else None
        self.ticket_timeout_s = ticket_timeout_s
        self._clock = clock or (lambda: int(time.time()))
        self.tickets: OrderedDict[str, tuple[Ticket, int]] = OrderedDict()
        self.by_call: dict[str, list[str]] = {}  # LiteLLM call id -> ticket ids, when the logging object is missing
        self._lock = threading.Lock()
        self._loaded: set[str] = set()
        super().__init__(**kwargs)
        self.intake = None
        if consent_port:
            self.intake = self._serve_intake(consent_host, int(consent_port))

    # Consents arrive here: from the intake endpoint, a retried call's header, or the host app directly

    def accept_consent(self, token: str, device_proof: Mapping[str, Any] | None = None) -> bool:
        """Keep a valid Consent for a pending Preview. False when it is not valid or matches nothing pending."""
        with self._lock:
            return self.gate.accept_consent(token, device_proof)

    def preview(self, preview_id: str) -> dict[str, Any] | None:
        return self.gate.preview_by_id(preview_id)

    # Before a tool call

    def _later_guardrails(self, data: dict) -> list[str]:
        """Guardrails that run after this one on MCP calls. They could still change the arguments, so the approved
        action would not be the one that runs: refuse instead."""
        try:
            from litellm.proxy.utils import ProxyLogging

            chain = list(ProxyLogging.callback_capabilities().resolved_callbacks)
        except Exception:  # outside the proxy (unit tests): only litellm.callbacks
            import litellm

            chain = list(litellm.callbacks)
        if self not in chain:
            return []
        later = []
        for cb in chain[chain.index(self) + 1:]:
            if isinstance(cb, CustomGuardrail) and cb.should_run_guardrail(
                    data=data, event_type=GuardrailEventHooks.pre_mcp_call) is True:
                later.append(cb.guardrail_name or type(cb).__name__)
        return later

    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any, data: dict, call_type: Any) -> dict:
        kind = getattr(call_type, "value", call_type)
        if kind == LIST or kind != CALL:
            return data  # listings and model calls are not actions
        self._sweep()
        later = self._later_guardrails(data)
        if later:
            raise _refuse(500, "oac_misconfigured", "OAC must be the last pre_mcp_call guardrail; after it: "
                          + ", ".join(sorted(later)))
        server, name = data.get("mcp_server_name"), data.get("mcp_tool_name")
        if not isinstance(server, str) or not isinstance(name, str):
            raise _refuse(403, "oac_refused", "tool call without a server and tool name", code="unknown_tool")
        tool = f"{server}/{name}"
        # what will run: another guardrail before this one may have rewritten the arguments
        args = data.get("modified_arguments") or data.get("mcp_arguments") or {}
        if not isinstance(args, Mapping):
            raise _refuse(403, "oac_refused", "arguments are not an object", code="malformed")
        args = json.loads(json.dumps(args))  # a private copy: what is approved is what is pinned below
        metadata = data.get("metadata") if isinstance(data.get("metadata"), Mapping) else {}
        person = data.get(self.person_field) or metadata.get(self.person_field)
        if not isinstance(person, str) or not person:
            raise _refuse(403, "oac_refused", "no person: the calling key has no " + self.person_field.split("_key_")[1],
                          code="malformed")
        person = f"{self.person_field.split('_key_')[1]}:{person}"
        self._load_chain(person)
        headers = metadata.get("headers") if isinstance(metadata.get("headers"), Mapping) else {}
        token = next((v for k, v in headers.items() if str(k).lower() == CONSENT_HEADER), None)
        try:
            with self._lock:
                if isinstance(token, str) and token:
                    self.gate.accept_consent(token)
                ticket = self.gate.begin(tool, args, person=person, tainted=self.tainted)
        except NeedsConsent as ask:
            p = ask.preview
            raise _refuse(403, "oac_consent_required",
                          f"Needs the person's approval: {p['summary']}. Nothing ran. Approve, then call again.",
                          preview=p, consent_url=self.consent_url.format(id=p["id"]) if self.consent_url else None) from None
        except OACError as e:
            raise _refuse(403, "oac_refused", f"Refused ({e.code}). Nothing ran.", code=e.code) from None
        ticket_id = uuid.uuid4().hex
        with self._lock:
            self.tickets[ticket_id] = (ticket, self._clock())
        logging_obj = data.get("litellm_logging_obj")
        details = getattr(logging_obj, "model_call_details", None)
        if isinstance(details, dict):
            details["oac_ticket"] = ticket_id  # comes back in the outcome event of this very call
        call_id = getattr(logging_obj, "litellm_call_id", None) or data.get("litellm_call_id")
        if call_id:
            with self._lock:
                self.by_call.setdefault(str(call_id), []).append(ticket_id)
        data["modified_arguments"] = args  # pin: the tool runs with exactly what was approved
        return data

    # After a tool call: close the attempt with a receipt

    def _take(self, kwargs: Mapping[str, Any]) -> Ticket | None:
        with self._lock:
            ticket_id = kwargs.get("oac_ticket")
            if not isinstance(ticket_id, str):  # only this guardrail writes it, as a hex string
                ticket_id = None
            call_id = str(kwargs.get("litellm_call_id") or "")
            ids = self.by_call.get(call_id, [])
            if ticket_id is None and len(ids) == 1:
                ticket_id = ids[0]  # only when unambiguous: several tool calls may share one call id
            if ticket_id in ids:
                ids.remove(ticket_id)
            if not ids:
                self.by_call.pop(call_id, None)
            entry = self.tickets.pop(ticket_id, None) if ticket_id else None
        return entry[0] if entry else None

    async def async_log_success_event(self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any) -> None:
        if kwargs.get("call_type") != CALL:
            return
        ticket = self._take(kwargs)
        if ticket is None:
            return
        error = None
        if getattr(response_obj, "isError", None) or getattr(response_obj, "is_error", None):
            error = RuntimeError("the tool reported an error")
        self._finish(ticket, response_obj, error)

    async def async_log_failure_event(self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any) -> None:
        if kwargs.get("call_type") != CALL:
            return
        ticket = self._take(kwargs)
        if ticket is None:
            return  # our own refusal, or a call we never authorized
        exc = kwargs.get("exception")
        status = getattr(exc, "status_code", None)
        if isinstance(status, int) and 400 <= status < 500:
            # refused by the gateway after us (a rate limit, a permission check) before the tool ran: it did not happen
            error: BaseException = ActionFailed(f"refused before the tool ran ({status})")
        else:
            error = exc if isinstance(exc, BaseException) else RuntimeError("tool call failed")
        self._finish(ticket, None, error)

    def _finish(self, ticket: Ticket, result: Any, error: BaseException | None) -> str:
        if hasattr(result, "model_dump"):
            result = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        with self._lock:
            receipt = self.gate.finish(ticket, result, error)
            if self.receipts_dir is not None:
                self.receipts_dir.mkdir(parents=True, exist_ok=True)
                with open(self.receipts_dir / _person_file(ticket.person), "a", encoding="ascii") as fh:
                    fh.write(receipt + "\n")
        return receipt

    def _sweep(self) -> None:
        """An attempt whose outcome never arrived (the client hung up, the worker stopped) is closed as unknown: it
        may have happened. Its occurrence stays unknown until `gate.resolve` says what the provider saw."""
        now = self._clock()
        stale = []
        with self._lock:
            for ticket_id, (ticket, born) in list(self.tickets.items()):
                if now - born < self.ticket_timeout_s:
                    break
                stale.append(self.tickets.pop(ticket_id)[0])
        for ticket in stale:
            self._finish(ticket, None, TimeoutError("no outcome reported"))

    def _load_chain(self, person: str) -> None:
        """Receipts already written for this person continue the same chain after a restart."""
        if self.receipts_dir is None or person in self._loaded:
            return
        with self._lock:
            path = self.receipts_dir / _person_file(person)
            if person not in self.gate.receipts and path.exists():
                self.gate.receipts[person] = [line for line in path.read_text().splitlines() if line]
            self._loaded.add(person)

    # The intake endpoint: where the person's signer delivers a Consent

    def _serve_intake(self, host: str, port: int) -> Any:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def get_preview(request: Request) -> JSONResponse:
            p = self.preview(request.path_params["preview_id"])
            return JSONResponse(p) if p else JSONResponse({"error": "not found"}, status_code=404)

        async def post_consent(request: Request) -> JSONResponse:
            try:
                body = await request.json()
            except ValueError:
                return JSONResponse({"error": "body must be JSON"}, status_code=400)
            token = body.get("consent") if isinstance(body, dict) else None
            if not isinstance(token, str):
                return JSONResponse({"error": "consent missing"}, status_code=400)
            kept = self.accept_consent(token, body.get("device_proof"))
            return JSONResponse({"kept": kept}, status_code=200 if kept else 422)

        app = Starlette(routes=[Route("/oac/previews/{preview_id}", get_preview, methods=["GET"]),
                                Route("/oac/consents", post_consent, methods=["POST"])])
        server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
        threading.Thread(target=server.run, daemon=True, name="oac-consent-intake").start()
        return server
