/**
 * Minimal deterministic CBOR encoder (RFC 8949 subset) for building COSE
 * keys and attestation objects in tests. Only the types needed by WebAuthn
 * test vectors are supported: unsigned/negative integers, byte strings,
 * text strings, arrays and maps.
 */

function encodeHead(major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length])
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length])
  if (length <= 0xffff) {
    const out = Buffer.alloc(3)
    out[0] = (major << 5) | 25
    out.writeUInt16BE(length, 1)
    return out
  }
  const out = Buffer.alloc(5)
  out[0] = (major << 5) | 26
  out.writeUInt32BE(length, 1)
  return out
}

export function cborEncode(value) {
  if (Number.isInteger(value)) {
    if (value >= 0) return encodeHead(0, value)
    return encodeHead(1, -value - 1)
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([encodeHead(2, value.length), value])
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8')
    return Buffer.concat([encodeHead(3, bytes.length), bytes])
  }
  if (Array.isArray(value)) {
    const parts = value.map(cborEncode)
    return Buffer.concat([encodeHead(4, parts.length), ...parts])
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value)
    const parts = []
    for (const [key, item] of entries) {
      const keyNumber = /^-?\d+$/.test(key) ? Number(key) : key
      parts.push(cborEncode(keyNumber), cborEncode(item))
    }
    return Buffer.concat([encodeHead(5, entries.length), ...parts])
  }
  throw new Error(`unsupported CBOR value: ${typeof value}`)
}
