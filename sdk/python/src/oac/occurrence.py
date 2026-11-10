"""Business occurrences (spec 5.1): one order or payment runs at most once."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any, Protocol

from oac.errors import OACError

Key = tuple[str, str, str]  # (person, scope, occurrence)


class OccurrenceStore(Protocol):
    def claim(self, key: Key) -> str | None:
        """Mark the key running and return None, or return its blocking state. Must be atomic."""
        ...

    def finish(self, key: Key, outcome: str) -> None: ...

    def release(self, key: Key) -> None:
        """Drop a claim whose action never started."""
        ...

    def state(self, key: Key) -> str | None: ...

    # Optional: has_scope(scope) -> bool, whether any record uses that scope. A gate whose store lacks it
    # refuses every change to a tool's occurrence scope (see check_scope_change).


class MemoryOccurrences:
    """For tests and examples. A production store keeps the same states in a table with a unique key."""

    def __init__(self, states: Mapping[Key, str] | None = None) -> None:
        self._states: dict[Key, str] = dict(states or {})
        self._lock = threading.Lock()

    def claim(self, key: Key) -> str | None:
        with self._lock:
            now = self._states.get(key)
            if now in ("running", "unknown", "ok"):
                return now
            self._states[key] = "running"
            return None

    def finish(self, key: Key, outcome: str) -> None:
        with self._lock:
            self._states[key] = outcome

    def release(self, key: Key) -> None:
        with self._lock:
            self._states.pop(key, None)

    def state(self, key: Key) -> str | None:
        return self._states.get(key)

    def has_scope(self, scope: str) -> bool:
        with self._lock:
            return any(k[1] == scope for k in self._states)


def scope(profile: Mapping[str, Any]) -> str:
    """Where the profile's occurrence ids are unique: its occurrence_scope, else the tool itself.
    The prefixes keep a scope from ever matching a tool's own records."""
    s = profile.get("occurrence_scope")
    return "tool:" + profile["tool"] if s is None else "scope:" + s


def occurrence_key(person: str, profile: Mapping[str, Any], args: Mapping[str, Any]) -> Key | None:
    name = profile.get("occurrence")
    return None if name is None else (person, scope(profile), args[name])


def check_scope_change(store: OccurrenceStore, old: Mapping[str, Any] | None, new: Mapping[str, Any]) -> None:
    """Spec 5.1: a tool's occurrence scope cannot change while records exist in the old one, or an order
    that already ran could run again under the new scope. Moving records is the store owner's job."""
    if old is None or old.get("occurrence") is None or scope(old) == scope(new):
        return
    has_scope = getattr(store, "has_scope", None)
    if has_scope is None or has_scope(scope(old)):
        raise ValueError(f"{old['tool']} has occurrence records in {scope(old)}; move them before changing its scope")


def _refuse(state: str | None) -> None:
    if state == "ok":
        raise OACError("duplicate_occurrence", "this occurrence already ran")
    if state in ("running", "unknown"):
        raise OACError("occurrence_unresolved", "an earlier attempt has no known outcome yet")


def check_open(store: OccurrenceStore, key: Key | None) -> None:
    """Refuse early, before the person is asked, when the occurrence cannot run now."""
    if key is not None:
        _refuse(store.state(key))


def claim(store: OccurrenceStore, key: Key | None) -> Key | None:
    if key is None:
        return None
    _refuse(store.claim(key))
    return key


def resolve(store: OccurrenceStore, key: Key, outcome: str) -> None:
    """Record what the provider says happened. A "running" record left by a crash counts as unknown."""
    if outcome not in ("ok", "failed") or store.state(key) not in ("running", "unknown"):
        raise ValueError("only an attempt with no known outcome can be resolved, to ok or failed")
    store.finish(key, outcome)
