// OAC (Open Action Consent) v0.1 reference SDK for TypeScript. Spec: spec/oac-v0.1.md.

export { CODES, OACError } from "./errors.ts";
export { canonical, parse } from "./jcs.ts";
export { digest, generate, KeySet, sign, tokenDigest, verify, type Jwk, type SigningKey } from "./jws.ts";
export { tierFor } from "./tiers.ts";
export { actionDigest, buildPreview, checkBinding } from "./preview.ts";
export { makeConsent, MemoryNonces, verifyConsent, type NonceStore } from "./consent.ts";
export { checkMandate, loosens, makeMandate } from "./mandate.ts";
export { makeReceipt, verifyChain } from "./receipts.ts";
export { checkUndo, makeUndo } from "./undo.ts";
export { Gate, NeedsConsent, type ProfileSpec } from "./gate.ts";
export const VERSION = "0.1.0";
