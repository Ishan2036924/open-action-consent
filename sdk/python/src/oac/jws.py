"""Keys, digests and the JWS envelope (RFC 7515 compact) every signed OAC object uses.

Header = exactly {alg, kid, typ}, itself JCS-canonical. Payload = JCS-canonical JSON. A verifier refuses a token whose
header or payload bytes are not the canonical form of what they parse to, so one object has one encoding.
Algorithms: EdDSA (Ed25519, RFC 8037) and ES256 (P-256, raw r||s, low-S only so one payload has one signature).
kid = the RFC 7638 JWK thumbprint. Every trusted key belongs to exactly one issuer, and a token's `iss` must be its
key's issuer."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from oac.errors import OACError
from oac.jcs import canonical_bytes, parse

ALGS = ("EdDSA", "ES256")
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not _B64URL.match(text) or len(text) % 4 == 1:
        raise OACError("malformed", "not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as e:
        raise OACError("malformed", "not base64url") from e
    if b64url(raw) != text:  # non-zero padding bits: two spellings of one value
        raise OACError("malformed", "non-canonical base64url")
    return raw


def digest_bytes(data: bytes) -> str:
    return "sha-256:" + b64url(hashlib.sha256(data).digest())


def digest(value: Any) -> str:
    """The digest of a JSON value: sha-256 over its JCS bytes."""
    return digest_bytes(canonical_bytes(value))


def thumbprint(jwk: Mapping[str, Any]) -> str:
    if jwk.get("kty") == "OKP":
        members = {k: jwk[k] for k in ("crv", "kty", "x")}
    elif jwk.get("kty") == "EC":
        members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    else:
        raise OACError("malformed", "unsupported key type")
    return b64url(hashlib.sha256(canonical_bytes(members)).digest())


@dataclass(frozen=True)
class SigningKey:
    alg: str
    private: Any
    jwk: dict[str, Any]  # the public JWK, with kid

    @property
    def kid(self) -> str:
        return str(self.jwk["kid"])


def _with_kid(jwk: dict[str, Any]) -> dict[str, Any]:
    return {**jwk, "kid": thumbprint(jwk)}


def ed25519_key(private: Ed25519PrivateKey) -> SigningKey:
    x = private.public_key().public_bytes_raw()
    return SigningKey("EdDSA", private, _with_kid({"kty": "OKP", "crv": "Ed25519", "x": b64url(x)}))


def ed25519_from_seed(seed: bytes) -> SigningKey:
    return ed25519_key(Ed25519PrivateKey.from_private_bytes(seed))


def p256_key(private: ec.EllipticCurvePrivateKey) -> SigningKey:
    nums = private.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64url(nums.x.to_bytes(32, "big")), "y": b64url(nums.y.to_bytes(32, "big"))}
    return SigningKey("ES256", private, _with_kid(jwk))


def p256_from_seed(seed: bytes) -> SigningKey:
    return p256_key(ec.derive_private_key(int.from_bytes(seed, "big") % (_P256_ORDER - 1) + 1, ec.SECP256R1()))


def generate(alg: str = "EdDSA") -> SigningKey:
    if alg == "EdDSA":
        return ed25519_key(Ed25519PrivateKey.generate())
    if alg == "ES256":
        return p256_key(ec.generate_private_key(ec.SECP256R1()))
    raise OACError("bad_alg", alg)


class KeySet:
    """Public keys a verifier trusts, grouped by the issuer each belongs to: {iss: [jwk, ...]}. A kid maps to one
    key and one issuer; a token signed by that key must name that issuer."""

    def __init__(self, by_issuer: Mapping[str, Iterable[Mapping[str, Any]]]) -> None:
        self._keys: dict[str, tuple[dict[str, Any], str]] = {}
        if not isinstance(by_issuer, Mapping):
            raise OACError("malformed", "keys are grouped by issuer: {iss: [jwk, ...]}")
        for iss, jwks in by_issuer.items():
            for jwk in jwks:
                j = dict(jwk)
                kid = thumbprint(j)
                if j.get("kid", kid) != kid:
                    raise OACError("malformed", "kid is not the key's thumbprint")
                if kid in self._keys and self._keys[kid][1] != iss:
                    raise OACError("malformed", "one key cannot belong to two issuers")
                self._keys[kid] = ({**j, "kid": kid}, iss)

    def get(self, kid: str) -> dict[str, Any] | None:
        hit = self._keys.get(kid)
        return hit[0] if hit else None

    def issuer(self, kid: str) -> str | None:
        hit = self._keys.get(kid)
        return hit[1] if hit else None


def _signature(key: SigningKey, data: bytes) -> bytes:
    if key.alg == "EdDSA":
        return key.private.sign(data)
    r, s = decode_dss_signature(key.private.sign(data, ec.ECDSA(hashes.SHA256())))
    if s > _P256_ORDER // 2:  # low-S: the other spelling of the same signature
        s = _P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign(payload: Mapping[str, Any], key: SigningKey, typ: str) -> str:
    header = {"alg": key.alg, "kid": key.kid, "typ": typ}
    signing_input = b64url(canonical_bytes(header)) + "." + b64url(canonical_bytes(dict(payload)))
    return signing_input + "." + b64url(_signature(key, signing_input.encode("ascii")))


def _check_sig(jwk: Mapping[str, Any], alg: str, data: bytes, sig: bytes) -> None:
    try:
        if alg == "EdDSA":
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                raise OACError("bad_alg", "key is not Ed25519")
            Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"])).verify(sig, data)
        else:
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
                raise OACError("bad_alg", "key is not P-256")
            if len(sig) != 64:
                raise OACError("bad_signature", "ES256 signature must be 64 bytes")
            if int.from_bytes(sig[32:], "big") > _P256_ORDER // 2:
                raise OACError("bad_signature", "ES256 signature must be low-S")
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(b64url_decode(jwk["x"]), "big"),
                int.from_bytes(b64url_decode(jwk["y"]), "big"),
                ec.SECP256R1(),
            ).public_key()
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise OACError("bad_signature") from e
    except ValueError as e:
        raise OACError("bad_signature", "invalid key or signature encoding") from e


def _canonical_part(part: str) -> Any:
    raw = b64url_decode(part)
    value = parse(raw)
    if canonical_bytes(value) != raw:
        raise OACError("not_canonical")
    return value


def verify(token: str, keys: KeySet, typ: str) -> dict[str, Any]:
    """Check the envelope and signature; return the payload. Field checks are the caller's (consent, mandate...)."""
    if not isinstance(token, str) or not token.isascii():
        raise OACError("malformed", "token must be an ASCII string")
    parts = token.split(".")
    if len(parts) != 3:
        raise OACError("malformed", "a compact JWS has three parts")
    header = _canonical_part(parts[0])
    if not isinstance(header, dict) or set(header) != {"alg", "kid", "typ"}:
        raise OACError("malformed", "header must be exactly alg, kid, typ")
    if header["typ"] != typ:
        raise OACError("bad_type", f"expected {typ}")
    if header["alg"] not in ALGS:
        raise OACError("bad_alg", str(header["alg"]))
    jwk = keys.get(header["kid"]) if isinstance(header["kid"], str) else None
    if jwk is None:
        raise OACError("unknown_key")
    _check_sig(jwk, header["alg"], (parts[0] + "." + parts[1]).encode("ascii"), b64url_decode(parts[2]))
    payload = _canonical_part(parts[1])
    if not isinstance(payload, dict):
        raise OACError("malformed", "payload must be an object")
    if payload.get("iss") != keys.issuer(header["kid"]):
        raise OACError("wrong_issuer", "the token names another issuer than its key's")
    return payload


def token_digest(token: str) -> str:
    """The digest a later object uses to name a signed token (receipt chains, undo requests)."""
    if not isinstance(token, str) or not token.isascii():
        raise OACError("malformed", "token must be an ASCII string")
    return digest_bytes(token.encode("ascii"))
