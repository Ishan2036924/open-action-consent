"""OAC extension for the official MCP Python SDK. See guides/mcp-python.md."""

from __future__ import annotations

import inspect as _inspect
import json
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

try:
    from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
    from mcp.server.extension import Extension
    from mcp.server.mcpserver.server import require_client_extension
    from mcp.shared.exceptions import MCPError
    from mcp_types import (CallToolRequestParams, CallToolResult, ClientCapabilities, ElicitationCapability, ElicitRequest,
                           ElicitRequestURLParams, InputRequiredResult, MissingRequiredClientCapabilityErrorData,
                           TextContent, UrlElicitationCapability)
    from mcp_types.jsonrpc import MISSING_REQUIRED_CLIENT_CAPABILITY
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('oac.mcp needs the MCP SDK: pip install "open-action-consent[mcp]"') from e

from oac import KeySet, MemoryNonces, OACError, SigningKey, digest, make_receipt, shapes, tier_for, token_digest, verify, verify_consent
from oac.occurrence import Key, MemoryOccurrences, OccurrenceStore, claim, occurrence_key
from oac.preview import action_digest, build_preview

ID = "com.atlasiw/oac"
PROFILE_KEY, PREVIEW_KEY, RECEIPT_KEY, CONSENT_KEY, RUN_KEY = (f"{ID}-profile", f"{ID}-preview", f"{ID}-receipt",
                                                              f"{ID}-consent", f"{ID}-run")
OUTCOME_KEY = f"{ID}-outcome"
ASK = "oac_consent"


def _refused(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


class OACExtension(Extension):
    identifier = ID

    def __init__(
        self,
        *,
        executor: str,
        key: SigningKey,
        signers: KeySet,
        consent_url: Callable[[Mapping[str, Any]], str],
        person: Callable[[ServerRequestContext[Any, Any]], str],
        summarize: Callable[[Mapping[str, Any]], str] | None = None,
        tainted: Callable[[ServerRequestContext[Any, Any]], bool] | None = None,
        policy_floor: str = "A",
        clock: Callable[[], int] = lambda: int(time.time()),
        inspect: Callable[[Mapping[str, Any], ServerRequestContext[Any, Any]], Any] | None = None,
        occurrences: OccurrenceStore | None = None,
    ) -> None:
        """inspect(action, ctx) may return {"evidence": ...} or {"refuse": reason}. It runs before
        asking and again before running; a changed page is refused."""
        self.executor, self.key, self.signers = executor, key, signers
        self._consent_url, self._person, self._clock = consent_url, person, clock
        self._summarize = summarize or (lambda a: f"{a['tool']} with {json.dumps(a['args'], sort_keys=True)}"[:500])
        # taint comes from the host, never the model; unknown means tainted
        self._tainted = tainted or (lambda ctx: True)
        self.policy_floor = policy_floor
        self._inspect_fn = inspect
        self.profiles: dict[str, dict[str, Any]] = {}
        self.previews: dict[str, dict[str, Any]] = {}  # preview digest -> preview
        self.consents: dict[str, str] = {}  # preview digest -> consent token
        self.nonces = MemoryNonces()
        self.occurrences = occurrences or MemoryOccurrences()
        self.receipts: dict[str, list[str]] = {}  # person -> chain

    # setup
    def settings(self) -> dict[str, Any]:
        return {"version": "0.1", "executor": self.executor}

    def profile(self, tool: str, *, effect: str, undo: str = "none", window_s: int = 0, tier_floor: str = "A",
                binds: Mapping[str, str] | None = None, other_args: list[str] | None = None,
                occurrence: str | None = None) -> dict[str, Any]:
        """Register a tool's Action Profile and return the `_meta` to pass to `@server.tool(meta=...)`."""
        doc: dict[str, Any] = {"oac": "0.1", "type": "action-profile", "tool": tool, "effect": effect,
                               "undo": {"kind": undo, "window_s": window_s}, "tier_floor": tier_floor, "binds": dict(binds or {})}
        if other_args:
            doc["other_args"] = list(other_args)
        if occurrence:
            doc["occurrence"] = occurrence
        self.profiles[tool] = shapes.profile(doc)
        return {PROFILE_KEY: doc}

    # the consent page / signer side calls these
    def preview(self, preview_id: str) -> dict[str, Any] | None:
        return next((p for p in self.previews.values() if p["id"] == preview_id), None)

    def accept_consent(self, token: str) -> bool:
        """Keep a valid Consent for a pending preview. Never replaces one already kept."""
        try:
            p = verify(token, self.signers, "oac-consent+jws")
            shapes.consent(p)
        except OACError:
            return False
        kept = False
        for item in p["items"] if p["aud"] == self.executor else []:
            if item["preview"] in self.previews and item["preview"] not in self.consents:
                self.consents[item["preview"]] = token
                kept = True
        return kept

    # the interceptor
    async def intercept_tool_call(self, params: CallToolRequestParams, ctx: ServerRequestContext[Any, Any],
                                  call_next: CallNext) -> HandlerResult:
        profile = self.profiles.get(params.name)
        if profile is None:
            return _refused(f"{params.name} has no OAC profile, so it never runs.")
        action = {"tool": params.name, "args": dict(params.arguments or {})}
        try:
            shapes.check_action(action, profile)
            tier = tier_for(profile, policy_floor=self.policy_floor, tainted=self._tainted(ctx))
        except OACError as e:
            return _refused(f"Refused ({e.code}).")
        person = self._person(ctx)
        if tier == "D":
            return _refused("Refused: this action is never allowed (tier D).")
        if tier in ("A", "B"):
            try:
                claimed = claim(self.occurrences, occurrence_key(person, profile, action["args"]))
            except OACError as e:
                return _refused(f"Refused ({e.code}). Nothing ran.")
            return await self._run(ctx, call_next, person, profile, action, tier, {"kind": "tier"}, None, claimed)
        require_client_extension(ctx, ID)  # -32021 when the client does not speak OAC (spec 6)
        caps = ctx.session.client_capabilities
        if not (caps and caps.elicitation and caps.elicitation.url):
            data = MissingRequiredClientCapabilityErrorData(
                required_capabilities=ClientCapabilities(elicitation=ElicitationCapability(url=UrlElicitationCapability())))
            raise MCPError(code=MISSING_REQUIRED_CLIENT_CAPABILITY, message="OAC needs URL-mode elicitation",
                           data=data.model_dump(by_alias=True, mode="json", exclude_none=True))
        seen = await self._look(action, ctx)
        if "refuse" in seen:
            return _refused(f"Refused: {seen['refuse']}. Nothing ran.")
        if params.request_state is None:
            return self._ask(action, profile, person, seen.get("evidence"))
        try:
            state = json.loads(params.request_state)
        except ValueError:
            return _refused("Refused (malformed state). Nothing ran.")
        answer = (params.input_responses or {}).get(ASK)
        if getattr(answer, "action", None) != "accept":
            return _refused("The person did not approve. Nothing ran.")
        preview = self.previews.get(state.get("preview", ""))
        token = self.consents.get(state.get("preview", ""))
        meta = dict(ctx.meta or {})
        token = token or meta.get(CONSENT_KEY)
        if preview is None or token is None:
            return self._ask(action, profile, person, seen.get("evidence"))
        # compare the DOM, not the screenshot: pixels differ between two captures
        if (seen.get("evidence") or {}).get("dom") != (preview.get("evidence") or {}).get("dom"):
            return _refused("Refused (page_changed): what is there now is not what the person approved. Nothing ran.")
        claimed = None
        try:
            claimed = claim(self.occurrences, occurrence_key(person, profile, action["args"]))
            consent = verify_consent(token, keys=self.signers, executor=self.executor, sub=person, previews=[preview],
                                     actions=[action], profiles=self.profiles, now=self._clock(), nonces=self.nonces,
                                     policy_floor=self.policy_floor, tainted=self._tainted(ctx))
        except OACError as e:
            if claimed:
                self.occurrences.release(claimed)
            return _refused(f"Refused ({e.code}). Nothing ran.")
        authority = {"kind": "consent", "ref": consent["jti"], "digest": token_digest(token)}
        return await self._run(ctx, call_next, person, profile, action, "C", authority, digest(preview), claimed)

    async def _run(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext, person: str,
                   profile: Mapping[str, Any], action: Mapping[str, Any], tier: str, authority: dict[str, Any],
                   preview_digest: str | None, claimed: Key | None) -> HandlerResult:
        # a timed-out payment may still have gone through, so an error is "unknown" unless the tool says "failed"
        try:
            result = await call_next(ctx)
        except Exception:
            self._with_receipt(None, person, profile, action, tier, authority, preview_digest,
                               self._finish(claimed, "unknown" if claimed else "failed"))
            raise
        if isinstance(result, CallToolResult) and result.is_error:
            sure = (result.meta or {}).get(OUTCOME_KEY) == "failed"
            outcome = self._finish(claimed, "unknown" if claimed and not sure else "failed")
        else:
            outcome = self._finish(claimed, "ok")
        return self._with_receipt(result, person, profile, action, tier, authority, preview_digest, outcome)

    def _finish(self, claimed: Key | None, outcome: str) -> str:
        if claimed:
            self.occurrences.finish(claimed, outcome)
        return outcome

    def resolve(self, tool: str, occurrence: str, *, person: str, outcome: str) -> None:
        """Record what the provider says happened to an attempt whose outcome was unknown."""
        key = (person, tool, occurrence)
        if outcome not in ("ok", "failed") or self.occurrences.state(key) != "unknown":
            raise ValueError("only an unknown outcome can be resolved, to ok or failed")
        self.occurrences.finish(key, outcome)

    async def _look(self, action: Mapping[str, Any], ctx: ServerRequestContext[Any, Any]) -> dict[str, Any]:
        if self._inspect_fn is None:
            return {}
        out = self._inspect_fn(action, ctx)
        return (await out if _inspect.isawaitable(out) else out) or {}

    def _ask(self, action: dict[str, Any], profile: Mapping[str, Any], person: str,
             evidence: Mapping[str, Any] | None = None) -> InputRequiredResult:
        p = build_preview(profile=profile, action=action, executor=self.executor, sub=person,
                          summary=self._summarize(action), now=self._clock(), evidence=evidence)
        d = digest(p)
        self.previews[d] = p
        ask = ElicitRequest(params=ElicitRequestURLParams(message="Approve: " + p["summary"], url=self._consent_url(p)))
        return InputRequiredResult(input_requests={ASK: ask}, request_state=json.dumps({"preview": d}),
                                   _meta={PREVIEW_KEY: p})

    def _with_receipt(self, result: HandlerResult | None, person: str, profile: Mapping[str, Any],
                      action: Mapping[str, Any], tier: str, authority: dict[str, Any], preview_digest: str | None,
                      outcome: str) -> HandlerResult | None:
        chain = self.receipts.setdefault(person, [])
        now = self._clock()
        undo: dict[str, Any] = {"kind": profile["undo"]["kind"]}
        if undo["kind"] != "none" and outcome == "ok":
            undo["until"] = now + profile["undo"]["window_s"]
            if undo["kind"] == "native":
                undo["token"] = "u_" + token_digest(f"{person}.{len(chain)}.{now}")[8:30]
        payload: dict[str, Any] = {
            "iss": self.executor, "sub": person, "seq": len(chain) + 1, "prev": token_digest(chain[-1]) if chain else None,
            "iat": now, "tool": action["tool"], "tier": tier, "authority": authority, "action": action_digest(action),
            "outcome": outcome, "undo": undo,
            "result": digest(result.model_dump(mode="json", by_alias=True, exclude_none=True) if hasattr(result, "model_dump") else result),
        }
        if preview_digest:
            payload["preview"] = preview_digest
        if "occurrence" in profile:
            payload["occurrence"] = action["args"][profile["occurrence"]]
        receipt = make_receipt(key=self.key, payload=payload)
        chain.append(receipt)
        if isinstance(result, CallToolResult):
            return result.model_copy(update={"meta": {**(result.meta or {}), RECEIPT_KEY: receipt}})
        return result
