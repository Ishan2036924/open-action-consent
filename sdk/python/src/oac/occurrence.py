"""Business occurrences (spec 5.1): one order, one payment, one booking runs at most once, even across fresh
Consents after a timeout."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any, Protocol

from oac.errors import OACError

Key = tuple[str, str, str]  # (person, tool, occurrence)


class OccurrenceStore(Protocol):
    def claim(self, key: Key) -> str | None:
        """Atomically mark the key running and return None if it is new or its last attempt failed; otherwise
        change nothing and return its state (running, unknown or ok)."""
        ...

    def finish(self, key: Key, outcome: str) -> None: ...

    def release(self, key: Key) -> None:
        """Drop a claim whose action never started (for example, the Consent was refused)."""
        ...

    def state(self, key: Key) -> str | None: ...


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


def occurrence_key(person: str, profile: Mapping[str, Any], args: Mapping[str, Any]) -> Key | None:
    name = profile.get("occurrence")
    return None if name is None else (person, profile["tool"], args[name])


def claim(store: OccurrenceStore, key: Key | None) -> Key | None:
    if key is None:
        return None
    state = store.claim(key)
    if state == "ok":
        raise OACError("duplicate_occurrence", "this occurrence already ran")
    if state is not None:
        raise OACError("occurrence_unresolved", "an earlier attempt has no known outcome yet")
    return key
