"""RFC 8785 (JCS) canonical JSON for the OAC subset, plus a strict parser.

OAC objects carry no non-integer numbers: money is integer minor units, times are integer unix seconds. With that rule
JCS reduces to: object keys sorted by their UTF-16 code units, no whitespace, strings escaped as ECMAScript
JSON.stringify does, integers in plain decimal. Integers must stay within +-(2**53 - 1) so every language reads them
exactly."""

from __future__ import annotations

import json
from typing import Any

from oac.errors import OACError

MAX_SAFE = 2**53 - 1


def _string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as e:  # a lone surrogate
        raise OACError("malformed", "string is not valid Unicode") from e
    return json.dumps(s, ensure_ascii=False)


def _enc(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if not -MAX_SAFE <= v <= MAX_SAFE:
            raise OACError("malformed", "integer out of the safe range")
        out.append(str(v))
    elif isinstance(v, float):
        raise OACError("malformed", "non-integer numbers are not allowed")
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _enc(x, out)
        out.append("]")
    elif isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise OACError("malformed", "object keys must be strings")
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _enc(v[k], out)
        out.append("}")
    else:
        raise OACError("malformed", f"type {type(v).__name__} cannot be canonicalized")


def canonical(value: Any) -> str:
    out: list[str] = []
    _enc(value, out)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    return canonical(value).encode("utf-8")


def _no_float(text: str) -> Any:
    raise OACError("malformed", "non-integer numbers are not allowed")


def _no_constant(text: str) -> Any:
    raise OACError("malformed", f"{text} is not JSON")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise OACError("malformed", f"duplicate key {k!r}")
        out[k] = v
    return out


def parse(data: str | bytes) -> Any:
    """Parse JSON strictly: no duplicate keys, no non-integer numbers, no NaN/Infinity, integers in the safe range."""
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        value = json.loads(
            text, parse_float=_no_float, parse_constant=_no_constant, object_pairs_hook=_no_duplicates
        )
    except OACError:
        raise
    except (ValueError, UnicodeDecodeError) as e:
        raise OACError("malformed", "not JSON") from e
    canonical(value)  # range and Unicode checks
    return value
