/**
 * Intent hashing: the cryptographic digest that binds a human authorization
 * to one exact action.
 *
 * SECURITY: intentHash = SHA-256(canonicalJson(hashing payload)).
 * The hashing payload contains every semantic field of the request
 * (requestId, nonce, action, timing window, agent, session, context).
 * Any mutation of tool, arguments, target, nonce, requestId or expiry
 * changes the hash, and therefore invalidates every signature over it.
 */
import { createHash, randomBytes } from 'node:crypto'
import { canonicalJson, pruneUndefined } from './canonicalize.js'

export const PROTOCOL_VERSION = '0.1'
export const HASH_ALGORITHM = 'sha256'
export const HASH_CONTEXT = 'dsh-human-intent/0.1'

/**
 * Build the exact object that gets hashed for a request. `request` is an
 * IntentRequest WITHOUT its intentHash field (it is computed from this).
 * Empty optional fields are omitted so that absent and blank are the same
 * intent.
 */
export function intentHashingPayload(request) {
  const payload = {
    v: HASH_CONTEXT,
    requestId: request.requestId,
    nonce: request.nonce,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    action: {
      tool: request.action.tool,
      ...(request.action.operation ? { operation: request.action.operation } : {}),
      ...(request.action.target ? { target: request.action.target } : {}),
      arguments: request.action.arguments,
    },
  }
  const agent = pruneUndefined(request.agent ?? {})
  if (Object.keys(agent).length > 0) payload.agent = agent
  const session = pruneUndefined(request.session ?? {})
  if (Object.keys(session).length > 0) payload.session = session
  const context = pruneUndefined(request.context ?? {})
  if (Object.keys(context).length > 0) payload.context = context
  return payload
}

/** SHA-256 over the canonical JSON form, hex-encoded. */
export function hashIntentPayload(payload) {
  return createHash(HASH_ALGORITHM).update(canonicalJson(payload), 'utf8').digest('hex')
}

/** Compute the intentHash for an IntentRequest (without its intentHash). */
export function computeIntentHash(request) {
  return hashIntentPayload(intentHashingPayload(request))
}

/** Re-derive the intentHash from a full request (including its own fields). */
export function verifyIntentHash(request) {
  const { intentHash, ...rest } = request
  return computeIntentHash(rest) === intentHash
}

/** Fresh unguessable nonce (256 bits). */
export function newNonce() {
  return randomBytes(32).toString('hex')
}
