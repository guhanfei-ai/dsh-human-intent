/**
 * WebAuthn software authenticator emulator for tests.
 *
 * Uses REAL cryptography: a genuine EC P-256 key pair held in Node, real
 * ES256 signatures over authenticatorData||clientDataHash, real SHA-256
 * rpIdHash and a real CBOR/COSE credential. Registration uses the "none"
 * attestation format (allowed and fully verified by @simplewebauthn/server).
 *
 * This is how the test suite proves that verification accepts genuine
 * assertions and rejects tampered ones — no mocking of the crypto.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto'
import { cborEncode } from './cbor.js'

export const UP_FLAG = 0x01
export const UV_FLAG = 0x04
export const AT_FLAG = 0x40
export const FLAG_NO_UV = UP_FLAG // user present but NOT verified

function sha256(data) {
  return createHash('sha256').update(data).digest()
}

function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url')
}

function authenticatorData({ rpIdHash, flags, counter, attestedCredentialData = null }) {
  const head = Buffer.alloc(37)
  Buffer.from(rpIdHash).copy(head, 0)
  head[32] = flags
  head.writeUInt32BE(counter, 33)
  if (!attestedCredentialData) return head
  return Buffer.concat([head, attestedCredentialData])
}

export class WebAuthnEmulator {
  constructor({ rpId = 'localhost', origin = 'http://localhost:8787' } = {}) {
    this.rpId = rpId
    this.origin = origin
    this.counter = 0
    this.credentialId = null
    this.keyPair = null
  }

  /** Create a credential for the given registration options. */
  async register(registrationOptions, { flags = UP_FLAG | UV_FLAG | AT_FLAG } = {}) {
    const clientData = {
      type: 'webauthn.create',
      challenge: registrationOptions.challenge,
      origin: this.origin,
      crossOrigin: false,
    }
    const clientDataJSON = Buffer.from(JSON.stringify(clientData), 'utf8')
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    this.keyPair = { privateKey, publicKey }
    this.credentialId = randomBytes(32)
    const jwk = publicKey.export({ format: 'jwk' })
    const x = Buffer.from(jwk.x, 'base64url')
    const y = Buffer.from(jwk.y, 'base64url')
    const coseKey = cborEncode({ 1: 2, 3: -7, '-1': 1, '-2': x, '-3': y })
    const aaguid = Buffer.alloc(16)
    const credIdLength = Buffer.alloc(2)
    credIdLength.writeUInt16BE(this.credentialId.length, 0)
    const attested = Buffer.concat([aaguid, credIdLength, this.credentialId, coseKey])
    const rpIdHash = sha256(this.rpId)
    const authData = authenticatorData({ rpIdHash, flags, counter: 0, attestedCredentialData: attested })
    const attestationObject = cborEncode({ fmt: 'none', attStmt: {}, authData })
    return {
      id: base64url(this.credentialId),
      rawId: base64url(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject: base64url(attestationObject),
      },
      clientExtensionResults: {},
      type: 'public-key',
    }
  }

  /**
   * Produce a genuine assertion for authentication options.
   * @param {object} authenticationOptions
   * @param {object} [overrides] - deliberate tampering for negative tests
   */
  async sign(authenticationOptions, { challenge = null, origin = null, flags = UP_FLAG | UV_FLAG, counter = null, rpId = null, tamperSignature = false } = {}) {
    const effectiveChallenge = challenge ?? authenticationOptions.challenge
    const effectiveOrigin = origin ?? this.origin
    const effectiveRpId = rpId ?? this.rpId
    this.counter = counter ?? this.counter + 1
    const clientData = {
      type: 'webauthn.get',
      challenge: effectiveChallenge,
      origin: effectiveOrigin,
      crossOrigin: false,
    }
    const clientDataJSON = Buffer.from(JSON.stringify(clientData), 'utf8')
    const authData = authenticatorData({ rpIdHash: sha256(effectiveRpId), flags, counter: this.counter })
    const signatureInput = Buffer.concat([authData, sha256(clientDataJSON)])
    let signature = cryptoSign('sha256', signatureInput, this.keyPair.privateKey)
    if (tamperSignature) {
      signature = Buffer.from(signature)
      signature[signature.length - 1] ^= 0xff
    }
    return {
      id: base64url(this.credentialId),
      rawId: base64url(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: base64url(clientDataJSON),
        authenticatorData: base64url(authData),
        signature: base64url(signature),
        userHandle: base64url(Buffer.from('dsh-human-intent-user', 'utf8')),
      },
      clientExtensionResults: {},
    }
  }
}
