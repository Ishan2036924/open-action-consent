// Error codes shared by every OAC implementation.

export const CODES = new Set([
  "malformed", "not_canonical", "bad_type", "bad_alg", "unknown_key", "bad_signature",
  "wrong_audience", "not_yet_valid", "expired", "lifetime_too_long", "replay",
  "preview_mismatch", "action_mismatch", "binding_mismatch", "subject_mismatch", "executor_mismatch",
  "preview_expired", "unknown_tool", "tier_d", "payment_missing", "payment_mismatch",
  "holder_mismatch", "tool_not_covered", "tainted", "pay_without_caps", "recipient_not_allowed",
  "payee_not_allowed", "site_not_allowed", "currency_mismatch", "over_amount", "over_daily_amount", "over_calls",
  "chain_broken", "chain_seq", "chain_issuer", "receipt_invalid", "receipt_mismatch", "not_reversible",
  "undo_mode_mismatch", "undo_window_closed",
  // identity, arguments, revocation, undo
  "wrong_issuer", "undeclared_argument", "revoked", "already_undone", "compensation_mismatch",
  // status lists and seals
  "status_unknown", "seal_mismatch",
  // device proofs (WebAuthn)
  "device_proof_missing", "device_proof_mismatch", "unknown_credential", "challenge_mismatch", "wrong_origin",
  "rp_mismatch", "user_not_present", "user_not_verified",
  // business occurrences
  "occurrence_unresolved", "duplicate_occurrence",
]);

/** A refusal. `code` is one of CODES; `detail` is for logs, never for deciding anything. */
export class OACError extends Error {
  readonly code: string;
  readonly detail: string;
  constructor(code: string, detail = "") {
    if (!CODES.has(code)) throw new Error(`unknown OAC error code ${code}`);
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.detail = detail;
  }
}
