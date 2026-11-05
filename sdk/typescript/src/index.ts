// Open Action Consent for TypeScript. Spec: spec/oac.md

export { CODES, OACError } from "./errors.ts";
export { canonical, parse } from "./jcs.ts";
export { digest, generate, KeySet, sign, tokenDigest, verify, type Jwk, type SigningKey } from "./jws.ts";
export { tierFor } from "./tiers.ts";
export * as shapes from "./shapes.ts";
export { actionDigest, buildPreview, checkBinding } from "./preview.ts";
export { makeConsent, MemoryNonces, verifyConsent, type NonceStore } from "./consent.ts";
export { checkMandate, loosens, makeMandate } from "./mandate.ts";
export { makeReceipt, verifyChain } from "./receipts.ts";
export { checkUndo, makeUndo } from "./undo.ts";
export { ActionFailed, Gate, NeedsConsent, type DevicePolicy, type ProfileSpec } from "./gate.ts";
export { MemoryOccurrences, type OccurrenceStore } from "./occurrence.ts";
export { verifyDeviceProof, type DeviceCheck } from "./webauthn.ts";
export const VERSION = "0.4.0";
