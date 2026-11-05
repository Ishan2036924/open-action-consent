"""Deterministic keys for test vectors and examples ONLY. Each seed is sha-256 of a public label, so anyone can
rebuild them; never use them for anything real."""

from __future__ import annotations

import hashlib

from oac.jws import SigningKey, ed25519_from_seed, p256_from_seed


def vector_key(label: str, alg: str = "EdDSA") -> SigningKey:
    seed = hashlib.sha256(f"oac-v0.1 test key: {label}".encode()).digest()
    return ed25519_from_seed(seed) if alg == "EdDSA" else p256_from_seed(seed)
