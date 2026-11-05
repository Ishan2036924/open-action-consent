"""Status lists (spec 7.5): which Mandates a signer revoked, as a W3C bitstring."""

from __future__ import annotations

import gzip
import zlib
from collections.abc import Iterable, Mapping
from typing import Any

from oac import shapes
from oac.errors import OACError
from oac.jws import KeySet, SigningKey, b64url, b64url_decode, sign, verify

TYP = "oac-status+jws"
MIN_BYTES = 16 * 1024  # W3C Bitstring Status List: at least 16 KB uncompressed (131,072 entries)
MAX_BYTES = 2 * 1024 * 1024  # refuse anything that inflates beyond 2 MB (16.7M entries): no zip bombs


def encode(revoked: Iterable[int], size_bytes: int = MIN_BYTES) -> str:
    bits = bytearray(size_bytes)
    for i in revoked:
        if not 0 <= i < size_bytes * 8:
            raise OACError("malformed", "index outside the list")
        bits[i // 8] |= 0x80 >> (i % 8)
    return "u" + b64url(gzip.compress(bytes(bits), mtime=0))


def decode(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not encoded.startswith("u"):
        raise OACError("malformed", "encoded list must be multibase base64url (prefix u)")
    raw = b64url_decode(encoded[1:])
    try:
        d = zlib.decompressobj(wbits=31)  # gzip only
        out = d.decompress(raw, MAX_BYTES + 1)
        if len(out) > MAX_BYTES or d.unconsumed_tail or not d.eof:
            raise OACError("malformed", "status list too large or truncated")
        if d.unused_data:  # exactly one gzip member and nothing after it
            raise OACError("malformed", "data after the gzip member")
    except zlib.error as e:
        raise OACError("malformed", "status list is not gzip") from e
    if len(out) < MIN_BYTES:
        raise OACError("malformed", "status list shorter than 16 KB")
    return out


def bit(bits: bytes, index: int) -> bool:
    if not 0 <= index < len(bits) * 8:
        raise OACError("malformed", "status index outside the list")
    return bool(bits[index // 8] & (0x80 >> (index % 8)))


def make_status_list(*, key: SigningKey, iss: str, list_id: str, revoked: Iterable[int], now: int, ttl: int = 3600,
                     size_bytes: int = MIN_BYTES) -> str:
    doc = {"oac": shapes.VERSION, "type": "status-list", "iss": iss, "id": list_id, "purpose": "revocation",
           "encoded_list": encode(revoked, size_bytes), "iat": now, "exp": now + ttl}
    return sign(shapes.status_list(doc), key, TYP)


def is_revoked(mandate: Mapping[str, Any], *, lists: Mapping[str, str], keys: KeySet, now: int) -> bool:
    """A missing, stale or foreign list is status_unknown, never a pass."""
    entry = mandate.get("status")
    if entry is None:
        return False
    token = lists.get(entry["list"])
    if token is None:
        raise OACError("status_unknown", "the mandate's status list is not available")
    s = verify(token, keys, TYP)
    shapes.status_list(s)
    if s["id"] != entry["list"] or s["iss"] != mandate["iss"]:
        raise OACError("status_unknown", "the status list is not this mandate's")
    if not s["iat"] <= now < s["exp"]:
        raise OACError("status_unknown", "the status list is stale")
    return bit(decode(s["encoded_list"]), entry["index"])
