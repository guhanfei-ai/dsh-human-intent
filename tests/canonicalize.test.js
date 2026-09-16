import test from 'node:test'
import assert from 'node:assert/strict'
import { canonicalJson, pruneUndefined, CanonicalizationError } from '../src/intent/canonicalize.js'

test('canonicalization is independent of key order', () => {
  assert.equal(
    canonicalJson({ a: 1, b: 2 }),
    canonicalJson({ b: 2, a: 1 }),
  )
})

test('canonicalization is stable for nested structures and arrays', () => {
  const a = { z: { y: [3, 2, { k: 'v' }] }, a: [{ b: true }, null, 'x'] }
  const b = { a: [{ b: true }, null, 'x'], z: { y: [3, 2, { k: 'v' }] } }
  assert.equal(canonicalJson(a), canonicalJson(b))
  assert.equal(canonicalJson(a), '{"a":[{"b":true},null,"x"],"z":{"y":[3,2,{"k":"v"}]}}')
})

test('arguments with different key orders canonicalize identically', () => {
  const first = canonicalJson({ command: 'rm', flags: ['-rf', './important-data'], cwd: '/tmp' })
  const second = canonicalJson({ cwd: '/tmp', flags: ['-rf', './important-data'], command: 'rm' })
  assert.equal(first, second)
})

test('unicode escapes are deterministic (same codepoints, same bytes)', () => {
  assert.equal(canonicalJson({ '名': '值' }), canonicalJson({ '名': '值' }))
  assert.equal(canonicalJson({ s: '\u00e9' }), canonicalJson({ s: 'é' }))
})

test('pruneUndefined makes absent and explicitly-undefined equal', () => {
  assert.deepEqual(
    canonicalJson(pruneUndefined({ a: 1, b: undefined })),
    canonicalJson({ a: 1 }),
  )
})

test('non-finite numbers are rejected', () => {
  assert.throws(() => canonicalJson({ a: Number.NaN }), CanonicalizationError)
  assert.throws(() => canonicalJson({ a: Number.POSITIVE_INFINITY }), CanonicalizationError)
})

test('bigint values are rejected', () => {
  assert.throws(() => canonicalJson({ a: 10n }), CanonicalizationError)
})

test('deeply nested values are rejected beyond the depth limit', () => {
  let deep = { v: 1 }
  for (let i = 0; i < 64; i += 1) deep = { nested: deep }
  assert.throws(() => canonicalJson(deep), CanonicalizationError)
})

test('oversized canonical forms are rejected', () => {
  const large = { blob: 'x'.repeat(300 * 1024) }
  assert.throws(() => canonicalJson(large, { maxBytes: 1024 }), CanonicalizationError)
})

test('unsupported runtime values are rejected', () => {
  assert.throws(() => canonicalJson({ when: new Date() }), CanonicalizationError)
  assert.throws(() => canonicalJson({ when: undefined }), CanonicalizationError)
  assert.throws(() => canonicalJson([() => {}]), CanonicalizationError)
})
