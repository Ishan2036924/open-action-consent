"""Fixed keys for tests and vectors. The seeds are public: never use them for anything real."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from oac.shapes import VERSION
from oac.jws import SigningKey, b64url, ed25519_from_seed, p256_from_seed, token_digest
from oac.webauthn import USER_PRESENT, USER_VERIFIED, challenge


def vector_key(label: str, alg: str = "EdDSA") -> SigningKey:
    seed = hashlib.sha256(f"oac-v0.1 test key: {label}".encode()).digest()
    return ed25519_from_seed(seed) if alg == "EdDSA" else p256_from_seed(seed)


def passkey_proof(consent_token: str, key: SigningKey, *, credential: str = "cred-1", rp_id: str = "app.example",
                  origin: str = "https://app.example", flags: int = USER_PRESENT | USER_VERIFIED,
                  challenge_for: str | None = None, type_: str = "webauthn.get") -> dict[str, Any]:
    """A fake passkey assertion over a Consent. The keyword arguments plant defects."""
    auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
    client = json.dumps({"type": type_, "challenge": challenge(challenge_for or consent_token), "origin": origin,
                         "crossOrigin": False}, separators=(",", ":")).encode()
    sig = key.private.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    return {"oac": VERSION, "type": "device-proof", "consent": token_digest(consent_token), "credential": credential,
            "authenticator_data": b64url(auth), "client_data_json": b64url(client), "signature": b64url(sig)}
