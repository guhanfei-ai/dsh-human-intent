/**
 * IntentService: the orchestration core of the human intent protocol.
 *
 *   Agent proposes action
 *         |
 *   createIntent()        -> IntentRequest + intentHash (pending human)
 *         |
 *   approve() / deny()    -> human decision, verified WebAuthn assertion
 *         |
 *   consumeReceipt()      -> full re-verification before execution:
 *                             decision, expiry, exact action binding,
 *                             one-shot consumption, credential signature
 *
 * SECURITY: every branch fails closed. Unknown requests, expired windows,
 * mismatched actions, consumed receipts and unverifiable signatures all
 * reject with a machine-readable reason.
 */
import { CredentialStore, credentialRef } from './auth/credential-store.js'
import { WebAuthnAuthenticator } from './auth/webauthn.js'
import { AuditLog } from './audit/audit.js'
import { compilePolicy } from './policy/policy.js'
import { parseReceipt, buildApprovedReceipt, buildDeniedReceipt, isReceiptExpired } from './intent/receipt.js'
import { createIntentRequest, isExpired, validateIntentRequest, DEFAULT_REQUEST_TTL_MS } from './intent/request.js'
import { computeIntentHash, verifyIntentHash } from './intent/hash.js'

export const REGISTRATION_CHALLENGE_TTL_MS = 5 * 60_000

export class IntentConsumptionError extends Error {
  constructor(message, code) {
    super(message)
    this.name = 'IntentConsumptionError'
    this.code = code
  }
}

export class IntentServiceError extends Error {
  constructor(message) {
    super(message)
    this.name = 'IntentServiceError'
  }
}

/**
 * @param {object} options
 * @param {WebAuthnAuthenticator} options.authenticator
 * @param {CredentialStore} options.credentialStore
 * @param {AuditLog} options.audit
 * @param {ReturnType<typeof compilePolicy>} [options.policy]
 * @param {number} [options.requestTtlMs]
 */
export class IntentService {
  constructor({ authenticator, credentialStore, audit, policy = compilePolicy({}), requestTtlMs = DEFAULT_REQUEST_TTL_MS } = {}) {
    if (!authenticator) throw new IntentServiceError('authenticator is required')
    if (!credentialStore) throw new IntentServiceError('credentialStore is required')
    if (!audit) throw new IntentServiceError('audit is required')
    this.authenticator = authenticator
    this.credentials = credentialStore
    this.audit = audit
    this.policy = policy
    this.requestTtlMs = requestTtlMs
    this.pending = new Map()
    this.consumed = new Map()
    this.registrationChallenges = new Map()
    this.listeners = new Set()
    this.initialized = false
  }

  async init() {
    if (this.initialized) return this
    await this.credentials.load()
    this.consumed = await this.audit.loadConsumedMap()
    this.initialized = true
    return this
  }

  #assertReady() {
    if (!this.initialized) throw new IntentServiceError('service not initialized; call init() first')
  }

  onIntentEvent(listener) {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  #emit(event) {
    for (const listener of this.listeners) {
      try { listener(event) } catch { /* listeners must not break the service */ }
    }
  }

  #auditEntryFor(request, extra = {}) {
    return {
      requestId: request.requestId,
      intentHash: request.intentHash,
      tool: request.action.tool,
      ...(request.action.operation ? { operation: request.action.operation } : {}),
      ...(request.action.target ? { target: request.action.target } : {}),
      ...(request.context?.risk ? { risk: request.context.risk } : {}),
      expiresAt: request.expiresAt,
      ...extra,
    }
  }

  /**
   * Create a pending human-intent request for one exact action.
   * Returns the request plus a promise that settles with the human decision.
   */
  async createIntent(spec, { ttlMs } = {}) {
    this.#assertReady()
    const request = createIntentRequest({ ...spec, ttlMs: ttlMs ?? this.requestTtlMs })
    if (this.pending.has(request.requestId)) {
      throw new IntentServiceError('requestId collision; retry')
    }
    let settleResult
    const result = new Promise((resolve) => { settleResult = resolve })
    const expiresAtMs = new Date(request.expiresAt).getTime()
    const timer = setTimeout(() => { this.#settle(request.requestId, { status: 'expired', reason: 'request window elapsed' }, 'expired') }, Math.max(0, expiresAtMs - Date.now()))
    if (timer.unref) timer.unref()
    this.pending.set(request.requestId, { request, settleResult, timer })
    await this.audit.record({ event: 'request-created', ...this.#auditEntryFor(request), ...(spec?.agent?.id ? { agentId: spec.agent.id } : {}) })
    this.#emit({ type: 'request-created', request })
    return { request, result }
  }

  /** Settle a pending request and stop its expiry timer. */
  #settle(requestId, value, auditEvent, extraAudit = {}) {
    const entry = this.pending.get(requestId)
    if (!entry) return false
    this.pending.delete(requestId)
    clearTimeout(entry.timer)
    entry.settleResult(value)
    if (auditEvent) {
      this.audit
        .record({ event: auditEvent, ...this.#auditEntryFor(entry.request, extraAudit), ...(value?.receipt ? { decision: value.receipt.decision } : {}), ...(value?.reason ? { reason: value.reason } : {}) })
        .catch((error) => console.error('[dsh-human-intent] audit write failed:', error.message))
    }
    this.#emit({ type: 'request-settled', requestId, status: value.status, decision: value.receipt?.decision ?? null })
    return true
  }

  /** Public intent view for UIs. */
  async getIntent(requestId) {
    const entry = this.pending.get(requestId)
    if (!entry) return null
    return { request: entry.request, expiresAt: entry.request.expiresAt }
  }

  listPending() {
    return [...this.pending.values()].map((entry) => entry.request)
  }

  /**
   * WebAuthn authentication options for one pending request. The challenge
   * is derived from the intentHash, binding the signature to the action.
   */
  async authenticationOptions(requestId) {
    this.#assertReady()
    const entry = this.pending.get(requestId)
    if (!entry) throw new IntentServiceError('unknown or settled request')
    if (isExpired(entry.request)) {
      this.#settle(requestId, { status: 'expired', reason: 'request window elapsed' }, 'expired')
      throw new IntentServiceError('request expired')
    }
    const credentials = await this.credentials.list()
    const options = await this.authenticator.authorizationChallenge(entry.request, credentials)
    return options
  }

  /** Begin passkey registration; returns options with a one-shot challenge. */
  async registrationOptions({ userName } = {}) {
    this.#assertReady()
    const options = await this.authenticator.registrationOptions({ userName })
    this.registrationChallenges.set(options.challenge, Date.now())
    return options
  }

  /** Verify and persist a newly registered credential. */
  async registerCredential(attestation) {
    this.#assertReady()
    const challenge = this.#challengeOf(attestation)
    const issued = this.registrationChallenges.get(challenge)
    if (!issued || Date.now() - issued > REGISTRATION_CHALLENGE_TTL_MS) {
      throw new IntentServiceError('registration challenge is unknown or expired; restart registration')
    }
    this.registrationChallenges.delete(challenge)
    const record = await this.authenticator.verifyRegistration(attestation, challenge)
    await this.credentials.save(record)
    await this.audit.record({ event: 'credential-registered', credentialRef: credentialRef(record.id), expiresAt: new Date(Date.now() + 86_400_000).toISOString() })
    this.#emit({ type: 'state-changed' })
    return { credentialId: record.id, credentialRef: credentialRef(record.id) }
  }

  #challengeOf(attestation) {
    try {
      const clientData = JSON.parse(Buffer.from(String(attestation?.response?.clientDataJSON ?? ''), 'base64url').toString('utf8'))
      return typeof clientData.challenge === 'string' ? clientData.challenge : ''
    } catch {
      return ''
    }
  }

  /**
   * Human approved through a WebAuthn assertion. The assertion is verified
   * server-side (challenge=intentHash, origin, RP ID, signature, counter,
   * UV flag). On success the pending request settles as approved.
   * Verification failures leave the request pending for retry.
   */
  async approve(requestId, assertion) {
    this.#assertReady()
    const entry = this.pending.get(requestId)
    if (!entry) throw new IntentServiceError('unknown or settled request')
    if (isExpired(entry.request)) {
      this.#settle(requestId, { status: 'expired', reason: 'request window elapsed' }, 'expired')
      throw new IntentServiceError('request expired')
    }
    const credential = await this.credentials.get(String(assertion?.id ?? ''))
    if (!credential) {
      await this.audit.record({ event: 'assertion-rejected', ...this.#auditEntryFor(entry.request), reason: 'unknown credential' })
      throw new IntentServiceError('unknown credential; register a passkey first')
    }
    const verification = await this.authenticator.verifyAuthorization(entry.request, assertion, credential)
    const receipt = buildApprovedReceipt(entry.request, verification)
    this.#settle(requestId, { status: 'approved', receipt, verification }, 'approved', {
      verificationMethod: 'webauthn',
      credentialRef: credentialRef(verification.credentialId),
    })
    return { status: 'approved', receipt }
  }

  /** Human explicitly denied the action. */
  async deny(requestId, { reason = '' } = {}) {
    this.#assertReady()
    const entry = this.pending.get(requestId)
    if (!entry) throw new IntentServiceError('unknown or settled request')
    const receipt = buildDeniedReceipt(entry.request, { reason })
    this.#settle(requestId, { status: 'denied', receipt }, 'denied', { verificationMethod: 'explicit-deny' })
    return { status: 'denied', receipt }
  }

  /** Agent or client cancelled before a human decision. */
  async cancel(requestId) {
    this.#assertReady()
    const entry = this.pending.get(requestId)
    if (!entry) throw new IntentServiceError('unknown or settled request')
    this.#settle(requestId, { status: 'cancelled', reason: 'cancelled before human decision' }, 'cancelled')
    return { status: 'cancelled' }
  }

  #rejectConsumption(request, code, message) {
    this.audit
      .record({ event: 'consumption-rejected', ...this.#auditEntryFor(request), rejectionReason: message })
      .catch((error) => console.error('[dsh-human-intent] audit write failed:', error.message))
    throw new IntentConsumptionError(message, code)
  }

  /**
   * THE SECURITY GATE. Verify that a receipt authorizes exactly `action`,
   * then consume it (one-shot). Every check must pass:
   *
   *  1. receipt structure parses (parseReceipt)
   *  2. decision is "approved"
   *  3. receipt window is open
   *  4. embedded intent hashes to intentHash (no tampered fields)
   *  5. recomputing the hash with the SUBMITTED action yields the same
   *     intentHash  (this is the action-mutation defense: tool B or args Y
   *     produce a different hash and are rejected)
   *  6. the request was never consumed before (replay defense)
   *  7. the embedded WebAuthn assertion still verifies against the stored
   *     credential public key (forged receipts cannot pass)
   *
   * Only after all of this does execution proceed.
   */
  async consumeReceipt(receiptInput, action) {
    this.#assertReady()
    let receipt
    try {
      receipt = parseReceipt(receiptInput)
    } catch (error) {
      throw new IntentConsumptionError(`invalid receipt: ${error.message}`, 'invalid_receipt')
    }
    if (receipt.decision !== 'approved') {
      this.#rejectConsumption(receipt.intent, 'decision_denied', `receipt decision is "${receipt.decision}"; only approved receipts authorize execution`)
    }
    if (isReceiptExpired(receipt)) {
      this.#rejectConsumption(receipt.intent, 'receipt_expired', 'receipt window has elapsed; request a fresh human authorization')
    }
    try {
      validateIntentRequest(receipt.intent)
    } catch (error) {
      this.#rejectConsumption(receipt.intent, 'tampered_intent', `embedded intent failed integrity validation: ${error.message}`)
    }
    if (receipt.intent.intentHash !== receipt.intentHash) {
      this.#rejectConsumption(receipt.intent, 'hash_mismatch', 'receipt intentHash does not match embedded intent')
    }
    const expectedHash = computeIntentHash({ ...receipt.intent, action: action ?? receipt.intent.action })
    if (expectedHash !== receipt.intentHash) {
      this.#rejectConsumption(receipt.intent, 'action_mismatch', 'submitted action does not hash to the authorized intentHash; the human authorized a different action')
    }
    if (this.consumed.has(receipt.requestId)) {
      this.#rejectConsumption(receipt.intent, 'already_consumed', 'receipt has already been consumed; one authorization authorizes one execution')
    }
    const credential = await this.credentials.get(receipt.authenticator.credentialId)
    if (!credential) {
      this.#rejectConsumption(receipt.intent, 'credential_unknown', 'authorizing credential no longer exists on this host')
    }
    let verification
    try {
      verification = await this.authenticator.verifyAuthorization(receipt.intent, receipt.assertion, credential)
    } catch (error) {
      this.#rejectConsumption(receipt.intent, 'verification_failed', `receipt signature verification failed: ${error.message}`)
    }
    // One-shot: mark consumed BEFORE any caller-visible success so concurrent
    // submissions cannot both pass the replay check (check-then-act race).
    this.consumed.set(receipt.requestId, { consumedAt: new Date().toISOString(), expiresAt: receipt.expiresAt })
    try {
      await this.credentials.updateCounter(credential.id, verification.newCounter)
    } catch (error) {
      this.consumed.delete(receipt.requestId)
      throw new IntentConsumptionError(`credential counter update failed: ${error.message}`, 'counter_update_failed')
    }
    await this.audit.record({
      event: 'consumed',
      ...this.#auditEntryFor(receipt.intent),
      decision: 'approved',
      executionStatus: 'authorized',
      verificationMethod: 'webauthn',
      credentialRef: credentialRef(credential.id),
    })
    this.#pruneConsumed()
    return {
      ok: true,
      requestId: receipt.requestId,
      intentHash: receipt.intentHash,
      tool: action?.tool ?? receipt.intent.action.tool,
      authorizedAction: receipt.intent.action,
    }
  }

  #pruneConsumed(now = Date.now()) {
    for (const [requestId, entry] of this.consumed) {
      if (new Date(entry.expiresAt).getTime() <= now) this.consumed.delete(requestId)
    }
  }

  async status() {
    this.#assertReady()
    return {
      pendingCount: this.pending.size,
      credentialCount: await this.credentials.size(),
      consumedCount: this.consumed.size,
      policy: this.policy.toJSON(),
      method: this.authenticator.method,
    }
  }
}

export { verifyIntentHash }
