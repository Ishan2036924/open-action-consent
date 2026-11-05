"""Error codes shared by every OAC implementation (spec section 9). A verifier reports exactly one code: the first
check that fails, in the order the spec lists them."""

from __future__ import annotations

CODES = frozenset(
    {
        # envelope
        "malformed",
        "not_canonical",
        "bad_type",
        "bad_alg",
        "unknown_key",
        "bad_signature",
        # time and audience
        "wrong_audience",
        "not_yet_valid",
        "expired",
        "lifetime_too_long",
        "replay",
        # consent binding
        "preview_mismatch",
        "action_mismatch",
        "binding_mismatch",
        "subject_mismatch",
        "executor_mismatch",
        "preview_expired",
        "unknown_tool",
        "tier_d",
        "payment_missing",
        "payment_mismatch",
        # mandate
        "holder_mismatch",
        "tool_not_covered",
        "tainted",
        "pay_without_caps",
        "recipient_not_allowed",
        "payee_not_allowed",
        "site_not_allowed",
        "currency_mismatch",
        "over_amount",
        "over_daily_amount",
        "over_calls",
        # receipts and undo
        "chain_broken",
        "chain_seq",
        "chain_issuer",
        "receipt_invalid",
        "receipt_mismatch",
        "not_reversible",
        "undo_mode_mismatch",
        "undo_window_closed",
        # added after the 2026-11-04 review
        "wrong_issuer",
        "undeclared_argument",
        "revoked",
        "already_undone",
        "compensation_mismatch",
    }
)


class OACError(Exception):
    """A refusal. `code` is one of CODES; `detail` is for logs, never for deciding anything."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in CODES:
            raise ValueError(f"unknown OAC error code {code!r}")
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
