import test from 'node:test'
import assert from 'node:assert/strict'
import { createIntentRequest } from '../src/intent/request.js'
import { computeIntentHash, verifyIntentHash, newNonce } from '../src/intent/hash.js'

const base = {
  action: { tool: 'shell.exec', arguments: { command: 'rm -rf ./important-data' } },
  context: { risk: 'high' },
}

test('the same logical intent always produces the same hash', () => {
  const nonce = newNonce()
  const now = Date.parse('2026-09-17T00:00:00Z')
  const first = createIntentRequest(base, { now, nonce, requestId: 'req_fixed' })
  const second = createIntentRequest(base, { now, nonce, requestId: 'req_fixed' })
  assert.equal(first.intentHash, second.intentHash)
  assert.equal(verifyIntentHash(first), true)
})

test('argument key order does not change the hash', () => {
  const nonce = newNonce()
  const now = 1_000
  const a = createIntentRequest({ action: { tool: 't', arguments: { x: 1, y: 2 } } }, { now, nonce, requestId: 'req_order' })
  const b = createIntentRequest({ action: { tool: 't', arguments: { y: 2, x: 1 } } }, { now, nonce, requestId: 'req_order' })
  assert.equal(a.intentHash, b.intentHash)
})

test('different arguments produce a different hash', () => {
  const nonce = newNonce()
  const now = 1_000
  const a = createIntentRequest({ action: { tool: 't', arguments: { path: './test-data' } } }, { now, nonce })
  const b = createIntentRequest({ action: { tool: 't', arguments: { path: './production-data' } } }, { now, nonce })
  assert.notEqual(a.intentHash, b.intentHash)
})

test('different tool produces a different hash', () => {
  const nonce = newNonce()
  const now = 1_000
  const a = createIntentRequest({ action: { tool: 'shell.exec', arguments: {} } }, { now, nonce })
  const b = createIntentRequest({ action: { tool: 'kubectl.delete', arguments: {} } }, { now, nonce })
  assert.notEqual(a.intentHash, b.intentHash)
})

test('different target produces a different hash', () => {
  const nonce = newNonce()
  const now = 1_000
  const a = createIntentRequest({ action: { tool: 't', target: 'ns/test/pod/foo', arguments: {} } }, { now, nonce })
  const b = createIntentRequest({ action: { tool: 't', target: 'ns/prod/pod/foo', arguments: {} } }, { now, nonce })
  assert.notEqual(a.intentHash, b.intentHash)
})

test('different nonce, requestId or window produce different hashes', () => {
  const now = 1_000
  const base0 = { action: { tool: 't', arguments: { a: 1 } } }
  const n1 = createIntentRequest(base0, { now, nonce: 'n1'.padEnd(64, '0') })
  const n2 = createIntentRequest(base0, { now, nonce: 'n2'.padEnd(64, '0') })
  assert.notEqual(n1.intentHash, n2.intentHash)
  const r1 = createIntentRequest(base0, { now, nonce: 'x'.padEnd(64, '0'), requestId: 'req_1' })
  const r2 = createIntentRequest(base0, { now, nonce: 'x'.padEnd(64, '0'), requestId: 'req_2' })
  assert.notEqual(r1.intentHash, r2.intentHash)
  const w1 = createIntentRequest(base0, { now, nonce: 'y'.padEnd(64, '0'), requestId: 'req_w' })
  const w2 = createIntentRequest(base0, { now: now + 60_000, nonce: 'y'.padEnd(64, '0'), requestId: 'req_w' })
  assert.notEqual(w1.intentHash, w2.intentHash)
})

test('tampering any hashed field invalidates the recorded hash', () => {
  const request = createIntentRequest(base)
  const tampered = { ...request, action: { ...request.action, arguments: { command: 'rm -rf ./production-data' } } }
  assert.equal(verifyIntentHash(tampered), false)
  const tamperedNonce = { ...request, nonce: 'f'.repeat(64) }
  assert.equal(verifyIntentHash(tamperedNonce), false)
})

test('computeIntentHash is a 64-character lowercase hex digest', () => {
  const request = createIntentRequest(base)
  assert.match(request.intentHash, /^[0-9a-f]{64}$/)
})
