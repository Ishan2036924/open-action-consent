"""Executor gate shared by the framework adapters.

    gate = Gate(executor="https://app.example/oac", key=executor_key, signers=signer_keys)
    gate.profile("send_email", effect="send", binds={"to": "to", "title": "subject"}, other_args=["body"])
    try:
        result, receipt = gate.run("send_email", args, send, person="person:1")
    except NeedsConsent as ask:
        show(ask.preview)  # then gate.accept_consent(token) and run again
"""

from __future__ import annotations

import inspect
import secrets
import time
from dataclasses import replace
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from oac import shapes
from oac.consent import MemoryNonces, NonceStore, verify_consent
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, digest, token_digest, verify
from oac.occurrence import Key, MemoryOccurrences, OccurrenceStore, check_open, claim, occurrence_key, resolve, scope
from oac.preview import action_digest, build_preview
from oac.receipts import make_receipt
from oac.tiers import tier_for
from oac.webauthn import DeviceCheck


def _fits(proof: Any, token: str) -> bool:
    """A well-formed device proof made for this token; anything else is not kept."""
    try:
        return proof is not None and shapes.device_proof(proof)["consent"] == token_digest(token)
    except OACError:
        return False

class NeedsConsent(Exception):
    """The action is tier C and no valid Consent is held yet: show `preview` to the person."""

    def __init__(self, preview: dict[str, Any]) -> None:
        super().__init__("the person must approve this preview")
        self.preview = preview


class ActionFailed(Exception):
    """Raise from a tool when the action surely did not happen. Other errors count as unknown."""


class Gate:
    def __init__(
        self,
        *,
        executor: str,
        key: SigningKey,
        signers: KeySet,
        nonces: NonceStore | None = None,
        occurrences: OccurrenceStore | None = None,
        policy_floor: str = "A",
        summarize: Callable[[Mapping[str, Any]], str] | None = None,
        clock: Callable[[], int] = lambda: int(time.time()),
        device: Callable[[str, Mapping[str, Any]], DeviceCheck | None] | None = None,
    ) -> None:
        """device(person, action) returns the passkey check a tier C action needs (its proof is
        filled in here), or None when no passkey is needed."""
        self.executor, self.key, self.signers = executor, key, signers
        self._device = device
        self.nonces = nonces or MemoryNonces()
        self.occurrences = occurrences or MemoryOccurrences()
        self.policy_floor, self._clock = policy_floor, clock
        self._summarize = summarize or (lambda a: f"{a['tool']}: " + ", ".join(f"{k}={a['args'][k]}" for k in sorted(a["args"]))[:480])
        self.profiles: dict[str, dict[str, Any]] = {}
        self.pending: dict[tuple[str, str], dict[str, Any]] = {}  # (person, action digest) -> preview
        self.consents: dict[str, str] = {}  # preview digest -> consent token
        self.proofs: dict[str, Mapping[str, Any]] = {}  # preview digest -> device proof sent with the consent
        self.receipts: dict[str, list[str]] = {}  # person -> chain
        self.tokens: dict[str, str] = {}  # authority digest in a receipt -> the exact token
        self.device_proofs: dict[str, Any] = {}  # same digest -> the passkey proof that came with it

    def profile(self, tool: str, *, effect: str, undo: str = "none", window_s: int = 0, tier_floor: str = "A",
                binds: Mapping[str, str] | None = None, other_args: list[str] | None = None,
                occurrence: str | None = None, occurrence_scope: str | None = None) -> dict[str, Any]:
        doc: dict[str, Any] = {"oac": shapes.VERSION, "type": "action-profile", "tool": tool, "effect": effect,
                               "undo": {"kind": undo, "window_s": window_s}, "tier_floor": tier_floor, "binds": dict(binds or {})}
        if other_args:
            doc["other_args"] = list(other_args)
        if occurrence:
            doc["occurrence"] = occurrence
        if occurrence_scope:
            doc["occurrence_scope"] = occurrence_scope
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

    def accept_consent(self, token: str, proof: Mapping[str, Any] | None = None) -> bool:
        """Keep a valid Consent, and the passkey proof sent with it, for a pending Preview.
        Never replaces a different token already kept; the same token may bring a new proof."""
        try:
            c = verify(token, self.signers, "oac-consent+jws")
            shapes.consent(c)
        except OACError:
            return False
        pending = {digest(p) for p in self.pending.values()}
        kept = False
        for item in c["items"] if c["aud"] == self.executor else []:
            if item["preview"] in pending and self.consents.get(item["preview"], token) == token:
                self.consents[item["preview"]] = token
                if _fits(proof, token):
                    self.proofs[item["preview"]] = proof
                kept = True
        return kept

    def _authorize(self, tool: str, args: Mapping[str, Any], person: str,
                   tainted: bool) -> tuple[str, dict[str, Any], str | None, Key | None]:
        tier = self.tier(tool, args, tainted=tainted)
        if tier == "D":
            raise OACError("tier_d", "this action never runs")
        occurrence = occurrence_key(person, self.profiles[tool], args)
        if tier in ("A", "B"):
            return tier, {"kind": "tier"}, None, claim(self.occurrences, occurrence)
        action = {"tool": tool, "args": dict(args)}
        preview = self.preview(tool, args, person=person)
        pd = digest(preview)
        token = self.consents.get(pd)
        if token is None:
            check_open(self.occurrences, occurrence)
            raise NeedsConsent(preview)
        need = self._device(person, action) if self._device else None
        device = replace(need, proof=self.proofs.get(pd)) if need else None
        claimed = claim(self.occurrences, occurrence)
        try:
            c = verify_consent(token, keys=self.signers, executor=self.executor, sub=person, previews=[preview],
                               actions=[action], profiles=self.profiles, now=self._clock(), nonces=self.nonces,
                               policy_floor=self.policy_floor, tainted=tainted, device=device)
        except BaseException:
            if claimed:
                self.occurrences.release(claimed)
            raise
        self.pending.pop((person, action_digest(action)), None)
        self.tokens[token_digest(token)] = token
        if device:
            self.device_proofs[token_digest(token)] = device.proof
        return "C", {"kind": "consent", "ref": c["jti"], "digest": token_digest(token)}, pd, claimed

    def _outcome(self, claimed: Key | None, error: BaseException | None) -> str:
        if error is None:
            outcome = "ok"
        else:
            outcome = "failed" if claimed is None or isinstance(error, ActionFailed) else "unknown"
        if claimed:
            self.occurrences.finish(claimed, outcome)
        return outcome

    def run(self, tool: str, args: Mapping[str, Any], fn: Callable[..., Any], *, person: str,
            tainted: bool = True) -> tuple[Any, str]:
        tier, authority, pd, claimed = self._authorize(tool, args, person, tainted)
        try:
            result = fn(**dict(args))
        except BaseException as e:
            self._receipt(person, tool, args, tier, authority, pd, None, self._outcome(claimed, e))
            raise
        return result, self._receipt(person, tool, args, tier, authority, pd, result, self._outcome(claimed, None))

    async def arun(self, tool: str, args: Mapping[str, Any], fn: Callable[..., Awaitable[Any] | Any], *, person: str,
                   tainted: bool = True) -> tuple[Any, str]:
        tier, authority, pd, claimed = self._authorize(tool, args, person, tainted)
        try:
            out = fn(**dict(args))
            result = await out if inspect.isawaitable(out) else out
        except BaseException as e:  # a cancelled call may still have happened
            self._receipt(person, tool, args, tier, authority, pd, None, self._outcome(claimed, e))
            raise
        return result, self._receipt(person, tool, args, tier, authority, pd, result, self._outcome(claimed, None))

    def resolve(self, tool: str, occurrence: str, *, person: str, outcome: str) -> None:
        """Record what the provider says happened to an unknown attempt: ok or failed."""
        resolve(self.occurrences, (person, scope(self._profile(tool)), occurrence), outcome)

    def _receipt(self, person: str, tool: str, args: Mapping[str, Any], tier: str, authority: dict[str, Any],
                 preview_digest: str | None, result: Any, outcome: str) -> str:
        profile = self.profiles[tool]
        chain = self.receipts.setdefault(person, [])
        now = self._clock()
        undo: dict[str, Any] = {"kind": profile["undo"]["kind"]}
        if undo["kind"] != "none" and outcome == "ok":
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
            "outcome": outcome, "result": result_digest, "undo": undo,
        }
        if "occurrence" in profile:
            payload["occurrence"] = args[profile["occurrence"]]
        if "occurrence_scope" in profile:
            payload["occurrence_scope"] = profile["occurrence_scope"]
        if preview_digest:
            payload["preview"] = preview_digest
        receipt = make_receipt(key=self.key, payload=payload)
        chain.append(receipt)
        return receipt
