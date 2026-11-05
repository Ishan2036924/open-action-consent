"""A framework-neutral executor gate: the part every agent framework adapter shares (OpenAI Agents SDK, LangGraph,
custom loops). It decides the tier, builds and remembers the Preview, keeps Consents handed over by the person's
signer, verifies the Consent right before the action, runs it, and appends the signed Receipt.

    gate = Gate(executor="https://app.example/oac", key=executor_key, signers=signer_keys)
    gate.profile("send_email", effect="send", binds={"to": "to", "title": "subject"}, other_args=["body"])
    try:
        result, receipt = gate.run("send_email", args, send, person="person:1", tainted=True)
    except NeedsConsent as ask:
        show(ask.preview)  # the person's signer signs a Consent over it -> gate.accept_consent(token) -> run again

A pending Preview is reused for the same person and action until it expires, so a framework that re-runs a step
after an interruption gets the same Preview the person approved."""

from __future__ import annotations

import inspect
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from oac import shapes
from oac.consent import MemoryNonces, NonceStore, verify_consent
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, digest, token_digest, verify
from oac.preview import action_digest, build_preview
from oac.receipts import make_receipt
from oac.tiers import tier_for


class NeedsConsent(Exception):
    """The action is tier C and no valid Consent is held yet: show `preview` to the person."""

    def __init__(self, preview: dict[str, Any]) -> None:
        super().__init__("the person must approve this preview")
        self.preview = preview


class Gate:
    def __init__(
        self,
        *,
        executor: str,
        key: SigningKey,
        signers: KeySet,
        nonces: NonceStore | None = None,
        policy_floor: str = "A",
        summarize: Callable[[Mapping[str, Any]], str] | None = None,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self.executor, self.key, self.signers = executor, key, signers
        self.nonces = nonces or MemoryNonces()
        self.policy_floor, self._clock = policy_floor, clock
        self._summarize = summarize or (lambda a: f"{a['tool']}: " + ", ".join(f"{k}={a['args'][k]}" for k in sorted(a["args"]))[:480])
        self.profiles: dict[str, dict[str, Any]] = {}
        self.pending: dict[tuple[str, str], dict[str, Any]] = {}  # (person, action digest) -> preview
        self.consents: dict[str, str] = {}  # preview digest -> consent token
        self.receipts: dict[str, list[str]] = {}  # person -> chain

    def profile(self, tool: str, *, effect: str, undo: str = "none", window_s: int = 0, tier_floor: str = "A",
                binds: Mapping[str, str] | None = None, other_args: list[str] | None = None) -> dict[str, Any]:
        doc: dict[str, Any] = {"oac": "0.1", "type": "action-profile", "tool": tool, "effect": effect,
                               "undo": {"kind": undo, "window_s": window_s}, "tier_floor": tier_floor, "binds": dict(binds or {})}
        if other_args:
            doc["other_args"] = list(other_args)
        self.profiles[tool] = shapes.profile(doc)
        return doc

    def _profile(self, tool: str) -> dict[str, Any]:
        p = self.profiles.get(tool)
        if p is None:
            raise OACError("unknown_tool", f"{tool} has no OAC profile")
        return p

    def tier(self, tool: str, args: Mapping[str, Any], *, tainted: bool = True) -> str:
        profile = self._profile(tool)
        shapes.check_action({"tool": tool, "args": dict(args)}, profile)
        return tier_for(profile, policy_floor=self.policy_floor, tainted=tainted)

    def preview(self, tool: str, args: Mapping[str, Any], *, person: str, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
        action = {"tool": tool, "args": dict(args)}
        key = (person, action_digest(action))
        now = self._clock()
        p = self.pending.get(key)
        if p is None or now >= p["exp"]:
            p = build_preview(profile=self._profile(tool), action=action, executor=self.executor, sub=person,
                              summary=self._summarize(action), now=now, preview_id="pv_" + secrets.token_urlsafe(12),
                              evidence=evidence)
            self.pending[key] = p
        return p

    def preview_by_id(self, preview_id: str) -> dict[str, Any] | None:
        return next((p for p in self.pending.values() if p["id"] == preview_id), None)

    def accept_consent(self, token: str) -> bool:
        """Keep a Consent only if a trusted signer signed it for this executor over a pending Preview; never
        replace one already kept."""
        try:
            c = verify(token, self.signers, "oac-consent+jws")
            shapes.consent(c)
        except OACError:
            return False
        pending = {digest(p) for p in self.pending.values()}
        kept = False
        for item in c["items"] if c["aud"] == self.executor else []:
            if item["preview"] in pending and item["preview"] not in self.consents:
                self.consents[item["preview"]] = token
                kept = True
        return kept

    def _authorize(self, tool: str, args: Mapping[str, Any], person: str, tainted: bool) -> tuple[str, dict[str, Any], str | None]:
        tier = self.tier(tool, args, tainted=tainted)
        if tier == "D":
            raise OACError("tier_d", "this action never runs")
        if tier in ("A", "B"):
            return tier, {"kind": "tier"}, None
        action = {"tool": tool, "args": dict(args)}
        preview = self.preview(tool, args, person=person)
        pd = digest(preview)
        token = self.consents.get(pd)
        if token is None:
            raise NeedsConsent(preview)
        c = verify_consent(token, keys=self.signers, executor=self.executor, sub=person, previews=[preview], actions=[action],
                           profiles=self.profiles, now=self._clock(), nonces=self.nonces, policy_floor=self.policy_floor,
                           tainted=tainted)
        self.pending.pop((person, action_digest(action)), None)
        return "C", {"kind": "consent", "ref": c["jti"]}, pd

    def run(self, tool: str, args: Mapping[str, Any], fn: Callable[..., Any], *, person: str,
            tainted: bool = True) -> tuple[Any, str]:
        tier, authority, pd = self._authorize(tool, args, person, tainted)
        try:
            result, failed = fn(**dict(args)), False
        except Exception:
            self._receipt(person, tool, args, tier, authority, pd, None, failed=True)
            raise
        return result, self._receipt(person, tool, args, tier, authority, pd, result, failed=failed)

    async def arun(self, tool: str, args: Mapping[str, Any], fn: Callable[..., Awaitable[Any] | Any], *, person: str,
                   tainted: bool = True) -> tuple[Any, str]:
        tier, authority, pd = self._authorize(tool, args, person, tainted)
        try:
            out = fn(**dict(args))
            result = await out if inspect.isawaitable(out) else out
        except Exception:
            self._receipt(person, tool, args, tier, authority, pd, None, failed=True)
            raise
        return result, self._receipt(person, tool, args, tier, authority, pd, result, failed=False)

    def _receipt(self, person: str, tool: str, args: Mapping[str, Any], tier: str, authority: dict[str, Any],
                 preview_digest: str | None, result: Any, *, failed: bool) -> str:
        profile = self.profiles[tool]
        chain = self.receipts.setdefault(person, [])
        now = self._clock()
        undo: dict[str, Any] = {"kind": profile["undo"]["kind"]}
        if undo["kind"] != "none" and not failed:
            undo["until"] = now + profile["undo"]["window_s"]
            if undo["kind"] == "native":
                undo["token"] = "u_" + secrets.token_urlsafe(12)
        try:
            result_digest = digest(result)
        except OACError:  # a non-JSON or float result: record its text form
            result_digest = digest(repr(result))
        payload: dict[str, Any] = {
            "iss": self.executor, "sub": person, "seq": len(chain) + 1, "prev": token_digest(chain[-1]) if chain else None,
            "iat": now, "tool": tool, "tier": tier, "authority": authority, "action": action_digest({"tool": tool, "args": dict(args)}),
            "outcome": "failed" if failed else "ok", "result": result_digest, "undo": undo,
        }
        if preview_digest:
            payload["preview"] = preview_digest
        receipt = make_receipt(key=self.key, payload=payload)
        chain.append(receipt)
        return receipt
