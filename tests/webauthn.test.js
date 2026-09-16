import test from 'node:test'
import assert from 'node:assert/strict'
import { WebAuthnAuthenticator } from '../src/auth/webauthn.js'
import { createIntentRequest } from '../src/intent/request.js'
import { WebAuthnEmulator } from './helpers/webauthn-emulator.js'
import { TEST_ORIGIN, TEST_RP_ID } from './helpers/context.js'

function authenticatorWith(emulator) {
  return new WebAuthnAuthenticator({ expectedOrigins: [emulator.origin], expectedRPID: emulator.rpId })
}

async function registered(emulator) {
  const authenticator = authenticatorWith(emulator)
  const options = await authenticator.registrationOptions({})
  const attestation = await emulator.register(options)
  const record = await authenticator.verifyRegistration(attestation, options.challenge)
  return { authenticator, record, options }
}

test('a genuine registration produces a storable credential', async () => {
  const emulator = new WebAuthnEmulator()
  const { record } = await registered(emulator)
  assert.match(record.id, /^[A-Za-z0-9_-]+$/)
  assert.ok(record.publicKey.length > 40)
  assert.equal(record.counter, 0)
})

test('registration with a tampered challenge is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const authenticator = authenticatorWith(emulator)
  const options = await authenticator.registrationOptions({})
  const attestation = await emulator.register(options)
  await assert.rejects(
    () => authenticator.verifyRegistration(attestation, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    /registration rejected/,
  )
})

test('registration from a foreign origin is rejected', async () => {
  const emulator = new WebAuthnEmulator({ origin: 'https://evil.example' })
  const authenticator = new WebAuthnAuthenticator({ expectedOrigins: [TEST_ORIGIN], expectedRPID: TEST_RP_ID })
  const options = await authenticator.registrationOptions({})
  const attestation = await emulator.register(options)
  await assert.rejects(() => authenticator.verifyRegistration(attestation, options.challenge), /registration rejected/)
})

test('a genuine assertion for the intent hash verifies', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 'shell.exec', arguments: { command: 'ls' } } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const assertion = await emulator.sign(options)
  const verification = await authenticator.verifyAuthorization(request, assertion, record)
  assert.equal(verification.verified, true)
  assert.equal(verification.userVerified, true)
  assert.equal(verification.credentialId, record.id)
  assert.ok(verification.newCounter >= 1)
})

test('the WebAuthn challenge equals the intent hash bytes', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const expected = Buffer.from(request.intentHash, 'hex').toString('base64url')
  assert.equal(options.challenge, expected)
})

test('an assertion for a different intent (challenge) is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const requestA = createIntentRequest({ action: { tool: 't', arguments: { x: 1 } } })
  const requestB = createIntentRequest({ action: { tool: 't', arguments: { x: 2 } } })
  const options = await authenticator.authorizationChallenge(requestA, [record])
  const signedForA = await emulator.sign(options)
  await assert.rejects(
    () => authenticator.verifyAuthorization(requestB, signedForA, record),
    /authorization rejected/,
  )
})

test('a tampered signature is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const assertion = await emulator.sign(options, { tamperSignature: true })
  await assert.rejects(() => authenticator.verifyAuthorization(request, assertion, record), /rejected|could not be verified/)
})

test('an assertion from a foreign origin is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const assertion = await emulator.sign(options, { origin: 'https://phishing.example' })
  await assert.rejects(() => authenticator.verifyAuthorization(request, assertion, record), /authorization rejected/)
})

test('an assertion over the wrong RP ID is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const assertion = await emulator.sign(options, { rpId: 'evil.example' })
  await assert.rejects(() => authenticator.verifyAuthorization(request, assertion, record), /authorization rejected/)
})

test('an assertion without user verification (UV flag) is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const assertion = await emulator.sign(options, { flags: 0x01 })
  await assert.rejects(() => authenticator.verifyAuthorization(request, assertion, record), /authorization rejected/)
})

test('a replayed assertion after counter advancement is rejected (clone detection)', async () => {
  const emulator = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record])
  const first = await emulator.sign(options)
  await authenticator.verifyAuthorization(request, first, record)
  const advanced = { ...record, counter: 1 }
  await assert.rejects(() => authenticator.verifyAuthorization(request, first, advanced), /authorization rejected/)
})

test('an assertion signed by another credential is rejected', async () => {
  const emulator = new WebAuthnEmulator()
  const stranger = new WebAuthnEmulator()
  const { authenticator, record } = await registered(emulator)
  const { record: strangerRecord } = await (async () => {
    const strangerAuth = authenticatorWith(stranger)
    const options = await strangerAuth.registrationOptions({})
    const attestation = await stranger.register(options)
    return { record: await strangerAuth.verifyRegistration(attestation, options.challenge) }
  })()
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  const options = await authenticator.authorizationChallenge(request, [record, strangerRecord])
  const strangerAssertion = await stranger.sign(options)
  await assert.rejects(
    () => authenticator.verifyAuthorization(request, strangerAssertion, record),
    /different credential|authorization rejected/,
  )
})

test('authorization challenge fails without registered credentials', async () => {
  const emulator = new WebAuthnEmulator()
  const authenticator = authenticatorWith(emulator)
  const request = createIntentRequest({ action: { tool: 't', arguments: {} } })
  await assert.rejects(() => authenticator.authorizationChallenge(request, []), /no registered credentials/)
})

test('empty origin allowlists are rejected at construction', () => {
  assert.throws(() => new WebAuthnAuthenticator({ expectedOrigins: [] }))
  assert.throws(() => new WebAuthnAuthenticator({ expectedOrigins: ['https://ok.example'], expectedRPID: '' }))
})

test('non-loopback plain-http origins are rejected at construction', () => {
  assert.throws(() => new WebAuthnAuthenticator({ expectedOrigins: ['http://lan-host.example:8080'] }))
})
