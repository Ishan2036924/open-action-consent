"""OAC (Open Action Consent) v0.1 reference SDK: previews, signed consents, mandates, receipts and undo for actions
agents take for people. Spec: spec/oac-v0.1.md."""

from oac.consent import MemoryNonces, make_consent, verify_consent
from oac.errors import CODES, OACError
from oac.jcs import canonical, parse
from oac.jws import KeySet, SigningKey, digest, generate, sign, token_digest, verify
from oac.mandate import check_mandate, loosens, make_mandate
from oac.preview import action_digest, build_preview, check_binding
from oac.receipts import make_receipt, verify_chain
from oac.tiers import tier_for
from oac.undo import check_undo, make_undo

__version__ = "0.1.0"
__all__ = [
    "CODES",
    "KeySet",
    "MemoryNonces",
    "OACError",
    "SigningKey",
    "action_digest",
    "build_preview",
    "canonical",
    "check_binding",
    "check_mandate",
    "check_undo",
    "digest",
    "generate",
    "loosens",
    "make_consent",
    "make_mandate",
    "make_receipt",
    "make_undo",
    "parse",
    "sign",
    "tier_for",
    "token_digest",
    "verify",
    "verify_chain",
    "verify_consent",
]
