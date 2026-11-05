"""Issuer metadata (spec 3.5): where an issuer publishes its public keys."""

from __future__ import annotations

import re
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from oac import shapes
from oac.errors import OACError
from oac.jcs import parse
from oac.jws import KeySet

MAX_DOC = 64 * 1024
# matched as text, not with a URL parser, so every language agrees
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_ISSUER = re.compile(rf"^https://({_LABEL}(\.{_LABEL})*)(:[0-9]{{1,5}})?((/(?!\.\.?(/|$))[A-Za-z0-9._~-]+)*)/?$")


def metadata_url(iss: str) -> str:
    m = _ISSUER.fullmatch(iss) if isinstance(iss, str) else None
    if m is None:
        raise OACError("malformed", "an issuer is https://host[:port][/path] in lowercase ASCII, without query or fragment")
    host, port, path = m.group(1), m.group(5) or "", m.group(6)
    return f"https://{host}{port}/.well-known/oac-issuer{path}"


def keyset_from(docs: Iterable[tuple[str, Mapping[str, Any]]]) -> KeySet:
    """docs = (expected issuer, metadata document) pairs. Refuses a document that names another issuer."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for iss, doc in docs:
        metadata_url(iss)
        shapes.issuer_metadata(doc)
        if doc["issuer"] != iss:
            raise OACError("wrong_issuer", "the metadata names another issuer")
        grouped.setdefault(iss, []).extend(doc["keys"])
    return KeySet(grouped)


def _default_get(url: str) -> bytes:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a: Any, **k: Any) -> None:  # a redirect could point anywhere
            raise OACError("malformed", "issuer metadata must not redirect")

    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=5) as r:
        body = r.read(MAX_DOC + 1)
    if len(body) > MAX_DOC:
        raise OACError("malformed", "issuer metadata too large")
    return body


def fetch_metadata(iss: str, *, get: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    body = (get or _default_get)(metadata_url(iss))
    doc = parse(body)
    shapes.issuer_metadata(doc)
    if doc["issuer"] != iss:
        raise OACError("wrong_issuer", "the metadata names another issuer")
    return doc
