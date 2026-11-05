"""Device proofs (spec 3.6): a WebAuthn assertion from the person's passkey over one exact Consent token."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from oac import shapes
from oac.errors import OACError
from oac.jcs import parse
from oac.jws import b64url, b64url_decode, token_digest

USER_PRESENT, USER_VERIFIED = 0x01, 0x04


@dataclass(frozen=True)
class DeviceCheck:
    """What an executor that requires a passkey knows about the person and itself."""

    proof: Mapping[str, Any] | None
    credentials: Mapping[str, Mapping[str, Any]]
    rp_id: str
    origins: Sequence[str]


def challenge(consent_token: str) -> str:
    """The WebAuthn challenge for a Consent: SHA-256 of the token's ASCII bytes, base64url."""
    return b64url(hashlib.sha256(consent_token.encode("ascii")).digest())


def _verify_es256_der(jwk: Mapping[str, Any], data: bytes, sig: bytes) -> None:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise OACError("bad_alg", "a credential key is P-256")
    try:
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64url_decode(jwk["x"]), "big"),
            int.from_bytes(b64url_decode(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as e:
        raise OACError("bad_signature") from e


def verify_device_proof(consent_token: str, check: DeviceCheck) -> None:
    proof = check.proof
    if proof is None:
        raise OACError("device_proof_missing")
    shapes.device_proof(proof)
    if proof["consent"] != token_digest(consent_token):
        raise OACError("device_proof_mismatch", "the proof is for another consent")
    jwk = check.credentials.get(proof["credential"])
    if jwk is None:
        raise OACError("unknown_credential")
    auth = b64url_decode(proof["authenticator_data"])
    client = b64url_decode(proof["client_data_json"])
    if len(auth) < 37:
        raise OACError("malformed", "authenticator data is too short")
    _verify_es256_der(jwk, auth + hashlib.sha256(client).digest(), b64url_decode(proof["signature"]))
    data = parse(client)
    if not isinstance(data, dict) or data.get("type") != "webauthn.get":
        raise OACError("malformed", "client data is not an assertion")
    if data.get("challenge") != challenge(consent_token):
        raise OACError("challenge_mismatch")
    if data.get("origin") not in check.origins or data.get("crossOrigin") is True:
        raise OACError("wrong_origin")
    if auth[:32] != hashlib.sha256(check.rp_id.encode()).digest():
        raise OACError("rp_mismatch")
    if not auth[32] & USER_PRESENT:
        raise OACError("user_not_present")
    if not auth[32] & USER_VERIFIED:
        raise OACError("user_not_verified")
