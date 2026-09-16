/**
 * IntentRequest: the exact action an agent proposes, before any human
 * authorization exists.
 *
 * SECURITY: createIntentRequest() is the only sanctioned way to build a
 * request. It validates shapes, enforces limits, prunes empty optional
 * fields, and computes the intentHash. A request whose fields do not hash
 * to its intentHash must never reach a human.
 */
import { randomUUID } from 'node:crypto'
import { computeIntentHash, newNonce, PROTOCOL_VERSION } from './hash.js'
import { canonicalJson, CanonicalizationError } from './canonicalize.js'

export const DEFAULT_REQUEST_TTL_MS = 120_000
export const MIN_REQUEST_TTL_MS = 5_000
export const MAX_REQUEST_TTL_MS = 600_000
export const MAX_TOOL_NAME_LENGTH = 200
export const MAX_SCALAR_TEXT_LENGTH = 2_000
export const MAX_REQUEST_CANONICAL_BYTES = 256 * 1024
export const RISK_LEVELS = ['low', 'medium', 'high', 'critical']

export class IntentRequestError extends Error {
  constructor(message) {
    super(message)
    this.name = 'IntentRequestError'
  }
}

function text(value, name, { max = MAX_SCALAR_TEXT_LENGTH, required = true } = {}) {
  const result = typeof value === 'string' ? value : String(value ?? '')
  if (required && result.length === 0) throw new IntentRequestError(`${name} must be a non-empty string`)
  if (result.length > max) throw new IntentRequestError(`${name} must not exceed ${max} characters`)
  return result
}

function validateRisk(risk) {
  if (risk === undefined || risk === null || risk === '') return undefined
  if (!RISK_LEVELS.includes(risk)) {
    throw new IntentRequestError(`context.risk must be one of ${RISK_LEVELS.join(', ')}`)
  }
  return risk
}

function validateIsoTime(value, name) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) throw new IntentRequestError(`${name} must be an ISO 8601 timestamp`)
  return date.toISOString()
}

/**
 * Create a signed-shape IntentRequest. `action.arguments` may be any
 * JSON-safe structure; non-representable values (BigInt, cycles, ...) are
 * rejected because they cannot be hashed deterministically.
 */
export function createIntentRequest(input, { now = Date.now(), nonce = newNonce(), requestId = `req_${randomUUID()}` } = {}) {
  if (!input || typeof input !== 'object') throw new IntentRequestError('request input must be an object')
  const action = input.action ?? {}
  if (!action.tool) throw new IntentRequestError('action.tool is required')

  const ttlRaw = input.ttlMs ?? DEFAULT_REQUEST_TTL_MS
  if (!Number.isInteger(ttlRaw) || ttlRaw < MIN_REQUEST_TTL_MS || ttlRaw > MAX_REQUEST_TTL_MS) {
    throw new IntentRequestError(`ttlMs must be an integer between ${MIN_REQUEST_TTL_MS} and ${MAX_REQUEST_TTL_MS}`)
  }

  const context = input.context ?? {}
  const risk = validateRisk(context.risk)

  const request = {
    version: PROTOCOL_VERSION,
    requestId,
    nonce,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlRaw).toISOString(),
    action: {
      tool: text(action.tool, 'action.tool', { max: MAX_TOOL_NAME_LENGTH }),
      ...(action.operation ? { operation: text(action.operation, 'action.operation') } : {}),
      ...(action.target ? { target: text(action.target, 'action.target') } : {}),
      arguments: action.arguments ?? {},
    },
  }
  if (input.agent?.id) request.agent = { id: text(input.agent.id, 'agent.id') }
  if (input.agent?.name) request.agent = { ...request.agent, name: text(input.agent.name, 'agent.name') }
  if (input.session?.id) request.session = { id: text(input.session.id, 'session.id') }
  if (context.description || context.reason || risk) {
    request.context = {
      ...(context.description ? { description: text(context.description, 'context.description') } : {}),
      ...(context.reason ? { reason: text(context.reason, 'context.reason') } : {}),
      ...(risk ? { risk } : {}),
    }
  }

  let hash
  try {
    canonicalJson(request, { maxBytes: MAX_REQUEST_CANONICAL_BYTES })
    hash = computeIntentHash(request)
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      throw new IntentRequestError(`action is not representable canonically: ${error.message}`)
    }
    throw error
  }
  return { ...request, intentHash: hash }
}

/** True when the request window has elapsed. */
export function isExpired(request, now = Date.now()) {
  return new Date(request.expiresAt).getTime() <= now
}

/** Structural validation for requests that arrive from untrusted storage. */
export function validateIntentRequest(request) {
  if (!request || typeof request !== 'object') throw new IntentRequestError('request must be an object')
  if (request.version !== PROTOCOL_VERSION) {
    throw new IntentRequestError(`unsupported intent protocol version ${JSON.stringify(request.version)}`)
  }
  for (const field of ['requestId', 'nonce', 'issuedAt', 'expiresAt', 'intentHash']) {
    if (typeof request[field] !== 'string' || request[field].length === 0) {
      throw new IntentRequestError(`request.${field} must be a non-empty string`)
    }
  }
  if (!/^[0-9a-f]{64}$/.test(request.intentHash)) {
    throw new IntentRequestError('request.intentHash must be a lowercase 64-character SHA-256 hex digest')
  }
  if (!request.action || typeof request.action !== 'object' || typeof request.action.tool !== 'string') {
    throw new IntentRequestError('request.action.tool must be a string')
  }
  validateIsoTime(request.issuedAt, 'request.issuedAt')
  validateIsoTime(request.expiresAt, 'request.expiresAt')
  const created = createIntentRequest({
    action: request.action,
    agent: request.agent,
    session: request.session,
    context: request.context,
    ttlMs: new Date(request.expiresAt).getTime() - new Date(request.issuedAt).getTime(),
  }, { now: new Date(request.issuedAt).getTime(), nonce: request.nonce, requestId: request.requestId })
  if (created.intentHash !== request.intentHash) {
    throw new IntentRequestError('request fields do not hash to the stated intentHash (tampered request)')
  }
  return true
}
