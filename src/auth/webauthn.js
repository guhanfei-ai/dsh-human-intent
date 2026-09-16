/**
 * WebAuthnAuthenticator: server-side WebAuthn verification.
 *
 * SECURITY: every assertion is fully verified with @simplewebauthn/server:
 *   - challenge  (bound to the intentHash, so the signature covers the action)
 *   - origin     (explicit allowlist, never derived from the request)
 *   - RP ID      (explicit configuration)
 *   - credential public key + signature (ES256/RSA verified via COSE)
 *   - signature counter (clone detection)
 *   - user verification flag (the human actually proved presence/identity)
 *
 * We never trust a client-provided "verified: true".
 */
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { AuthenticatorError, AUTHENTICATOR_METHOD_WEBAUTHN } from './provider.js'

const SUPPORTED_ALGORITHMS = [-7, -257] // ES256, RS256

/** intentHash (hex) -> WebAuthn challenge (base64url of 32 bytes). */
export function intentChallenge(request) {
  return Buffer.from(request.intentHash, 'hex').toString('base64url')
}

export class WebAuthnAuthenticator {
  constructor({ expectedOrigins = [], expectedRPID = 'localhost', rpName = 'dsh-human-intent' } = {}) {
    if (!Array.isArray(expectedOrigins) || expectedOrigins.length === 0) {
      throw new AuthenticatorError('expectedOrigins allowlist must not be empty')
    }
    for (const origin of expectedOrigins) {
      try {
        const url = new URL(origin)
        if (url.protocol !== 'https:' && !/^(localhost|127\.0\.0\.1)$/.test(url.hostname)) {
          throw new AuthenticatorError(`origin ${origin} is not https and not loopback`)
        }
      } catch (error) {
        throw error instanceof AuthenticatorError
          ? error
          : new AuthenticatorError(`expectedOrigins contains an invalid URL: ${origin}`)
      }
    }
    if (typeof expectedRPID !== 'string' || expectedRPID.length === 0) {
      throw new AuthenticatorError('expectedRPID is required')
    }
    this.expectedOrigins = expectedOrigins.map((value) => String(value))
    this.expectedRPID = expectedRPID
    this.rpName = rpName
    this.method = AUTHENTICATOR_METHOD_WEBAUTHN
  }

  /** Registration options for creating a new passkey/platform credential. */
  async registrationOptions({ userName = 'human-operator', userID = 'dsh-human-intent-user' } = {}) {
    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.expectedRPID,
      userName,
      userID: Buffer.from(userID, 'utf8'),
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
    })
    return options
  }

  /**
   * Verify a registration response and return a storable credential record.
   * The private key never leaves the authenticator; we persist only the
   * public key and counters.
   */
  async verifyRegistration(response, expectedChallenge) {
    let result
    try {
      result = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: this.expectedOrigins,
        expectedRPID: this.expectedRPID,
        requireUserVerification: true,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
      })
    } catch (error) {
      throw new AuthenticatorError(`registration rejected: ${error.message}`, { code: 'registration_invalid' })
    }
    if (!result.verified) throw new AuthenticatorError('registration could not be verified', { code: 'registration_invalid' })
    const credential = result.registrationInfo.credential
    return {
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      ...(Array.isArray(credential.transports) ? { transports: credential.transports } : {}),
      deviceType: result.registrationInfo.credentialDeviceType,
      backedUp: result.registrationInfo.credentialBackedUp,
      createdAt: new Date().toISOString(),
      label: '',
    }
  }

  /**
   * Authorization options for one pending intent. The challenge is the
   * intentHash itself: the authenticator will sign the exact bytes that
   * represent the exact action the human sees on screen.
   */
  async authorizationChallenge(request, credentials) {
    if (!Array.isArray(credentials) || credentials.length === 0) {
      throw new AuthenticatorError('no registered credentials; register a passkey first', { code: 'no_credentials' })
    }
    const options = await generateAuthenticationOptions({
      rpID: this.expectedRPID,
      challenge: Buffer.from(request.intentHash, 'hex'),
      allowCredentials: credentials.map((record) => ({
        id: record.id,
        ...(Array.isArray(record.transports) ? { transports: record.transports } : {}),
      })),
      userVerification: 'required',
    })
    return options
  }

  /**
   * Verify the human's authorization assertion for one intent.
   * Returns the normalized verification result; the caller decides when to
   * persist the new counter (consumption time in this protocol).
   */
  async verifyAuthorization(request, assertion, credentialRecord) {
    if (!assertion || typeof assertion !== 'object') {
      throw new AuthenticatorError('assertion must be an object', { code: 'assertion_invalid' })
    }
    if (assertion.id !== credentialRecord.id) {
      throw new AuthenticatorError('assertion was produced by a different credential', { code: 'credential_mismatch' })
    }
    let result
    try {
      result = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: intentChallenge(request),
        expectedOrigin: this.expectedOrigins,
        expectedRPID: this.expectedRPID,
        credential: {
          id: credentialRecord.id,
          publicKey: Buffer.from(credentialRecord.publicKey, 'base64url'),
          counter: credentialRecord.counter,
          ...(Array.isArray(credentialRecord.transports) ? { transports: credentialRecord.transports } : {}),
        },
        requireUserVerification: true,
      })
    } catch (error) {
      throw new AuthenticatorError(`authorization rejected: ${error.message}`, { code: 'assertion_invalid' })
    }
    if (!result.verified) throw new AuthenticatorError('assertion could not be verified', { code: 'assertion_invalid' })
    const info = result.authenticationInfo
    return {
      verified: true,
      credentialId: credentialRecord.id,
      userVerified: info.userVerified === true,
      newCounter: info.newCounter,
      credentialDeviceType: info.credentialDeviceType,
      credentialBackedUp: info.credentialBackedUp,
      assertion,
    }
  }
}
