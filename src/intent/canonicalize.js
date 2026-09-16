/**
 * Deterministic intent serialization (RFC 8785 JSON Canonicalization Scheme).
 *
 * SECURITY: The intent hash is only as strong as the canonicalization.
 * We rely on the `canonicalize` reference implementation of RFC 8785 (JCS),
 * which guarantees: sorted object keys, no insignificant whitespace, and
 * ECMAScript-compatible number serialization. Never hand-roll string
 * concatenation for hashing.
 */
import canonicalize from 'canonicalize'

const DEFAULT_MAX_DEPTH = 32
const DEFAULT_MAX_BYTES = 256 * 1024

export class CanonicalizationError extends Error {
  constructor(message) {
    super(message)
    this.name = 'CanonicalizationError'
  }
}

function assertJsonSafe(value, depth, maxDepth, path = '$') {
  if (depth > maxDepth) {
    throw new CanonicalizationError(`value at ${path} exceeds maximum nesting depth ${maxDepth}`)
  }
  if (value === null) return
  const type = typeof value
  if (type === 'string' || type === 'boolean') return
  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(`non-finite number at ${path} is not representable in canonical JSON`)
    }
    return
  }
  if (type === 'bigint') {
    throw new CanonicalizationError(`bigint at ${path} is not representable in canonical JSON; convert to string first`)
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) assertJsonSafe(value[i], depth + 1, maxDepth, `${path}[${i}]`)
    return
  }
  if (type === 'object') {
    if (value instanceof Date || value instanceof RegExp || value instanceof Map || value instanceof Set) {
      throw new CanonicalizationError(`unsupported value at ${path}: plain JSON structures only`)
    }
    for (const key of Object.keys(value)) assertJsonSafe(value[key], depth + 1, maxDepth, `${path}.${key}`)
    return
  }
  throw new CanonicalizationError(`unsupported value at ${path} (${type}): undefined and functions cannot be canonicalized`)
}

/**
 * Canonicalize a JSON-safe value into its deterministic RFC 8785 representation.
 * Throws CanonicalizationError on structures that cannot be hashed reliably.
 */
export function canonicalJson(value, { maxDepth = DEFAULT_MAX_DEPTH, maxBytes = DEFAULT_MAX_BYTES } = {}) {
  assertJsonSafe(value, 0, maxDepth)
  let text
  try {
    text = canonicalize(value)
  } catch (error) {
    throw new CanonicalizationError(`canonicalization failed: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (text === undefined) {
    throw new CanonicalizationError('value is not representable in canonical JSON')
  }
  if (text.length > maxBytes) {
    throw new CanonicalizationError(`canonical form exceeds ${maxBytes} bytes (received ${text.length})`)
  }
  return text
}

/**
 * Remove undefined properties recursively so that omitted fields and
 * explicitly-undefined fields produce identical canonical forms.
 */
export function pruneUndefined(value) {
  if (Array.isArray(value)) return value.map(pruneUndefined)
  if (value && typeof value === 'object') {
    const out = {}
    for (const key of Object.keys(value)) {
      const item = value[key]
      if (item !== undefined) out[key] = pruneUndefined(item)
    }
    return out
  }
  return value
}
