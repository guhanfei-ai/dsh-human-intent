/**
 * IntentReceipt: the proof that a human authorized one exact action.
 *
 * SECURITY MODEL
 * - An approved receipt embeds the full IntentRequest it authorizes and the
 *   raw WebAuthn assertion that was produced for it.
 * - The WebAuthn challenge is the intentHash, so the authenticator's
 *   signature covers every semantic field of the action.
 * - Consumption re-verifies the assertion against the stored credential
 *   public key before execution is permitted. A forged receipt without a
 *   valid authenticator signature can never pass.
 * - Denied receipts carry no signature and can never authorize execution.
 */
import { PROTOCOL_VERSION } from './hash.js'

export class IntentReceiptError extends Error {
  constructor(message) {
    super(message)
    this.name = 'IntentReceiptError'
  }
}

const ASSERTION_RESPONSE_KEYS = ['clientDataJSON', 'authenticatorData', 'signature']
const ALLOWED_DECISIONS = ['approved', 'denied']

/**
 * Build an approved receipt from a verified WebAuthn assertion.
 * `verification` is the normalized result of WebAuthnAuthenticator.verify.
 */
export function buildApprovedReceipt(request, verification) {
  if (!verification?.verified) throw new IntentReceiptError('cannot build an approved receipt from an unverified assertion')
  const assertion = verification.assertion
  for (const key of ASSERTION_RESPONSE_KEYS) {
    if (typeof assertion?.response?.[key] !== 'string') {
      throw new IntentReceiptError(`assertion.response.${key} is required to build a receipt`)
    }
  }
  return {
    kind: 'IntentReceipt',
    version: PROTOCOL_VERSION,
    protocol: 'human-intent',
    requestId: request.requestId,
    intentHash: request.intentHash,
    decision: 'approved',
    intent: { ...request },
    authenticator: {
      type: 'webauthn',
      credentialId: verification.credentialId,
    },
    verification: {
      method: 'webauthn',
      userVerified: verification.userVerified === true,
      ...(verification.credentialDeviceType ? { credentialDeviceType: verification.credentialDeviceType } : {}),
      ...(typeof verification.credentialBackedUp === 'boolean' ? { credentialBackedUp: verification.credentialBackedUp } : {}),
    },
    signedAt: new Date().toISOString(),
    expiresAt: request.expiresAt,
    nonce: request.nonce,
    assertion: {
      id: assertion.id,
      rawId: assertion.rawId,
      type: assertion.type,
      response: {
        clientDataJSON: assertion.response.clientDataJSON,
        authenticatorData: assertion.response.authenticatorData,
        signature: assertion.response.signature,
        ...(assertion.response.userHandle ? { userHandle: assertion.response.userHandle } : {}),
      },
    },
  }
}

/** Build a denied receipt. Denied receipts never authorize execution. */
export function buildDeniedReceipt(request, { reason = '' } = {}) {
  return {
    kind: 'IntentReceipt',
    version: PROTOCOL_VERSION,
    protocol: 'human-intent',
    requestId: request.requestId,
    intentHash: request.intentHash,
    decision: 'denied',
    intent: { ...request },
    authenticator: { type: 'human' },
    verification: { method: 'explicit-deny', userVerified: false },
    signedAt: new Date().toISOString(),
    expiresAt: request.expiresAt,
    nonce: request.nonce,
    ...(reason ? { deniedReason: reason } : {}),
  }
}

/** Deterministic serialization for storage and transfer. */
export function serializeReceipt(receipt) {
  return JSON.stringify(receipt, null, 2)
}

/**
 * Parse and structurally validate a receipt. Full cryptographic
 * verification happens in the verifier against the credential store;
 * this only guarantees shape integrity.
 */
export function parseReceipt(value) {
  let receipt = value
  if (typeof value === 'string') {
    try {
      receipt = JSON.parse(value)
    } catch {
      throw new IntentReceiptError('receipt is not valid JSON')
    }
  }
  if (!receipt || typeof receipt !== 'object') throw new IntentReceiptError('receipt must be an object')
  if (receipt.kind !== 'IntentReceipt') throw new IntentReceiptError('receipt.kind must be "IntentReceipt"')
  if (receipt.version !== PROTOCOL_VERSION) {
    throw new IntentReceiptError(`unsupported receipt version ${JSON.stringify(receipt.version)}`)
  }
  if (!ALLOWED_DECISIONS.includes(receipt.decision)) {
    throw new IntentReceiptError('receipt.decision must be "approved" or "denied"')
  }
  for (const field of ['requestId', 'intentHash', 'nonce', 'signedAt', 'expiresAt']) {
    if (typeof receipt[field] !== 'string' || receipt[field].length === 0) {
      throw new IntentReceiptError(`receipt.${field} must be a non-empty string`)
    }
  }
  if (!/^[0-9a-f]{64}$/.test(receipt.intentHash)) {
    throw new IntentReceiptError('receipt.intentHash must be a 64-character hex digest')
  }
  if (!receipt.intent || typeof receipt.intent !== 'object') {
    throw new IntentReceiptError('receipt.intent (the authorized IntentRequest) is required')
  }
  if (receipt.decision === 'approved') {
    for (const key of ASSERTION_RESPONSE_KEYS) {
      if (typeof receipt.assertion?.response?.[key] !== 'string') {
        throw new IntentReceiptError(`approved receipt is missing assertion.response.${key}`)
      }
    }
    if (typeof receipt.authenticator?.credentialId !== 'string') {
      throw new IntentReceiptError('approved receipt is missing authenticator.credentialId')
    }
    if (receipt.verification?.userVerified !== true) {
      throw new IntentReceiptError('approved receipt must record userVerified=true')
    }
  }
  return receipt
}

/** True while the receipt window (the originating request window) is open. */
export function isReceiptExpired(receipt, now = Date.now()) {
  return new Date(receipt.expiresAt).getTime() <= now
}
